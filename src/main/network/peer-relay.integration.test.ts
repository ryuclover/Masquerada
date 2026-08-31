import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { DATABASE_FILE_NAME, listMembers, openServerDatabase } from '../servers/server-database'
import { createPeerRendezvousEndpoint, RendezvousDescriptorStore } from './peer-rendezvous'
import {
  createPeerRelayEndpoint,
  createPeerRelayService,
  decodeRelayMessage,
  encodeRelayMessage,
  RelayMessageType,
  type RelayTransportStream
} from './peer-relay'
import {
  acceptRelayServerTransport,
  ClientTcpPeerConnection,
  connectAndAdmitTcpPeer,
  establishSecureServerConnectionOverTransport,
  startTcpServer,
  tcpTransportTestOnly,
  type AuthorizedPeerChannel,
  type ServerTcpPeerConnection,
  type TcpServerHandle
} from './tcp-transport'
import { encodeSessionFrame } from './p2p-session'

interface ServerFixture {
  readonly root: string
  readonly storage: ReturnType<typeof createLocalServerStorage>
  readonly storageId: string
  readonly serverId: string
  readonly publicKey: Buffer
  readonly privateKey: KeyObject
}

const roots: string[] = []
const serverConnections: ServerTcpPeerConnection[] = []
const closeChannels: Array<() => void> = []
const tcpServers: TcpServerHandle[] = []

afterEach(async () => {
  for (const connection of serverConnections.splice(0)) connection.destroy()
  for (const close of closeChannels.splice(0)) close()
  await Promise.all(tcpServers.splice(0).map((server) => server.close()))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function deviceIdentity() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

async function serverFixture(name: string): Promise<ServerFixture> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-relay-'))
  roots.push(root)
  const plaintext = new Map<string, string>()
  let counter = 0
  let serverPrivateKey: KeyObject | undefined
  const owner = deviceIdentity()
  const storage = createLocalServerStorage(
    root,
    {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (value: string) => {
        const key = `protected:${++counter}`
        plaintext.set(key, value)
        try { serverPrivateKey = createPrivateKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'pkcs8' }) } catch { /* unrelated protected value */ }
        return Buffer.from(key)
      },
      decryptString: (value: Buffer) => {
        const result = plaintext.get(value.toString())
        if (!result) throw new Error('missing fixture value')
        return result
      }
    },
    createAuthenticatedCandidateDevice(owner.fingerprint, owner.publicKey),
    { platform: 'win32', generateStorageId: () => (++counter).toString(16).padStart(32, '0') }
  )
  const server = await storage.createLocalServer(name)
  if (!serverPrivateKey) throw new Error('missing server private key')
  return { root, storage, storageId: server.localStorageId, serverId: server.serverId, publicKey: server.identity.publicKey, privateKey: serverPrivateKey }
}

function memberCount(fixture: ServerFixture): number {
  const db = openServerDatabase(join(fixture.root, 'servers', fixture.storageId, DATABASE_FILE_NAME))
  const result = listMembers(db).length
  db.close()
  return result
}

async function invite(fixture: ServerFixture): Promise<string> {
  return (await fixture.storage.createLocalServerInvite(fixture.storageId, { expiresAt: 2_000_000_000, maxUses: 1 })).encoded
}

interface Link {
  readonly remote: AuthorizedPeerChannel
  readonly relay: AuthorizedPeerChannel
  readonly remotePlaintexts: Buffer[]
  readonly relayPlaintexts: Buffer[]
  setRemoteTransform(transform?: (bytes: Buffer) => Buffer | null): void
}

function link(binding: { readonly serverId?: string; readonly peerDeviceFingerprint?: string } = {}): Link {
  const delivery: { remote?: (bytes: Buffer) => Promise<void>; relay?: (bytes: Buffer) => Promise<void> } = {}
  let transform: ((bytes: Buffer) => Buffer | null) | undefined
  const remotePlaintexts: Buffer[] = []
  const relayPlaintexts: Buffer[] = []
  const remoteHarness = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: async (bytes) => {
    remotePlaintexts.push(Buffer.from(bytes))
    const forwarded = transform?.(Buffer.from(bytes)) ?? bytes
    if (forwarded) await delivery.relay!(forwarded)
  } })
  const relayHarness = tcpTransportTestOnly.createAuthorizedPeerChannel({
    ...binding,
    onSend: async (bytes) => {
      relayPlaintexts.push(Buffer.from(bytes))
      await delivery.remote!(bytes)
    }
  })
  delivery.remote = remoteHarness.deliver
  delivery.relay = relayHarness.deliver
  closeChannels.push(remoteHarness.close, relayHarness.close)
  return { remote: remoteHarness.channel, relay: relayHarness.channel, remotePlaintexts, relayPlaintexts, setRemoteTransform(value) { transform = value } }
}

async function relayFixture(target: ServerFixture, requesterDevice = deviceIdentity()) {
  const relayIdentity = deviceIdentity()
  const targetOuterDevice = deviceIdentity()
  const targetLink = link({ serverId: relayIdentity.fingerprint, peerDeviceFingerprint: targetOuterDevice.fingerprint })
  const requesterLink = link({ serverId: relayIdentity.fingerprint, peerDeviceFingerprint: requesterDevice.fingerprint })
  const service = createPeerRelayService({ relayServerId: relayIdentity.fingerprint })
  createPeerRelayEndpoint({ channel: targetLink.relay, service })
  createPeerRelayEndpoint({ channel: requesterLink.relay, service })
  const targetEndpoint = createPeerRelayEndpoint({ channel: targetLink.remote })
  const requesterEndpoint = createPeerRelayEndpoint({ channel: requesterLink.remote })
  const accepted: ServerTcpPeerConnection[] = []
  const registration = await targetEndpoint.registerTarget({
    targetServerId: target.serverId,
    targetServerPublicKey: target.publicKey,
    targetServerPrivateKey: target.privateKey,
    relayServerId: relayIdentity.fingerprint,
    outerDeviceFingerprint: targetOuterDevice.fingerprint,
    onIncomingCircuit: (stream) => {
      const connection = acceptRelayServerTransport({
        transport: stream,
        storage: target.storage,
        localStorageId: target.storageId,
        serverId: target.serverId,
        serverPublicKey: target.publicKey,
        serverPrivateKey: target.privateKey,
        onMemberConnected: (authorized) => accepted.push(authorized)
      })
      serverConnections.push(connection)
    }
  })
  return { relayIdentity, targetOuterDevice, requesterDevice, targetLink, requesterLink, service, targetEndpoint, requesterEndpoint, registration, accepted }
}

async function secureOverRelay(stream: RelayTransportStream, target: ServerFixture, requester: ReturnType<typeof deviceIdentity>) {
  return establishSecureServerConnectionOverTransport({
    transport: stream,
    expectedServerId: target.serverId,
    expectedServerPublicKey: target.publicKey,
    deviceFingerprint: requester.fingerprint,
    devicePublicKey: requester.publicKey,
    devicePrivateKey: requester.privateKey
  })
}

describe('peer relay inner Masquerada pipeline', () => {
  it('rejects relay pre-auth and decrypts exactly once after MEMBER_CONNECTED', async () => {
    const peerR = await serverFixture('Real outer relay R')
    const requester = deviceIdentity()
    const service = createPeerRelayService({ relayServerId: peerR.serverId })
    let relayServerConnection: ServerTcpPeerConnection | undefined
    const handle = await startTcpServer({
      host: '127.0.0.1',
      port: 0,
      storage: peerR.storage,
      localStorageId: peerR.storageId,
      serverId: peerR.serverId,
      serverPublicKey: peerR.publicKey,
      serverPrivateKey: peerR.privateKey,
      onMemberConnected: (connection) => {
        relayServerConnection = connection
        createPeerRelayEndpoint({ channel: connection.getAuthorizedChannel()!, service })
      }
    })
    tcpServers.push(handle)

    const preAuth = new ClientTcpPeerConnection({
      host: handle.host,
      port: handle.port,
      expectedServerId: peerR.serverId,
      expectedServerPublicKey: peerR.publicKey,
      deviceFingerprint: requester.fingerprint,
      devicePublicKey: requester.publicKey,
      devicePrivateKey: requester.privateKey,
      deferAuthorization: true
    })
    await preAuth.waitForSecureConnection()
    const invalidRelay = Buffer.alloc(105)
    invalidRelay[0] = 1
    invalidRelay[1] = RelayMessageType.OPEN_REQUEST
    await preAuth.writeFrame(encodeSessionFrame(preAuth.getSession()!.encrypt(invalidRelay)))
    await expect(preAuth.waitForAdmission()).rejects.toBeDefined()
    expect(preAuth.getAuthorizedChannel()).toBeNull()

    const outerInvite = await invite(peerR)
    const authorized = connectAndAdmitTcpPeer({
      host: handle.host,
      port: handle.port,
      expectedServerId: peerR.serverId,
      expectedServerPublicKey: peerR.publicKey,
      deviceFingerprint: requester.fingerprint,
      devicePublicKey: requester.publicKey,
      devicePrivateKey: requester.privateKey,
      invite: outerInvite
    })
    await authorized.waitForAdmission()
    const requesterEndpoint = createPeerRelayEndpoint({ channel: authorized.getAuthorizedChannel()! })
    const serverDecrypt = relayServerConnection!.getSession()!.decrypt.bind(relayServerConnection!.getSession()!)
    const clientDecrypt = authorized.getSession()!.decrypt.bind(authorized.getSession()!)
    let serverDecrypts = 0
    let clientDecrypts = 0
    relayServerConnection!.getSession()!.decrypt = (payload) => { serverDecrypts++; return serverDecrypt(payload) }
    authorized.getSession()!.decrypt = (payload) => { clientDecrypts++; return clientDecrypt(payload) }
    await expect(requesterEndpoint.openCircuit(deviceIdentity().fingerprint)).rejects.toMatchObject({ code: 'RELAY_TARGET_NOT_AVAILABLE' })
    expect(serverDecrypts).toBe(1)
    expect(clientDecrypts).toBe(1)
    authorized.destroy()
  })

  it('admits once, encrypts application plaintext from R, then reconnects without invite', async () => {
    const target = await serverFixture('Relay target X')
    const requester = deviceIdentity()
    const fixture = await relayFixture(target, requester)
    const initialMembers = memberCount(target)
    const targetInvite = await invite(target)

    const firstStream = await fixture.requesterEndpoint.openCircuit(target.serverId)
    const secure = await secureOverRelay(firstStream, target, requester)
    const admitted = await secure.authorizeWithInvite(targetInvite)
    expect(admitted.connection.getState()).toBe('MEMBER_CONNECTED')
    expect(memberCount(target)).toBe(initialMembers + 1)
    expect(fixture.accepted).toHaveLength(1)

    const application = Buffer.from([1, 0x70, ...Buffer.from('inner-application-plaintext')])
    const received = new Promise<Buffer>((resolve) => {
      fixture.accepted[0]!.getAuthorizedChannel()!.registerMessageHandler([0x70], resolve)
    })
    await admitted.connection.getAuthorizedChannel()!.send(application)
    expect(await received).toEqual(application)

    const allOuterPlaintexts = [...fixture.requesterLink.remotePlaintexts, ...fixture.requesterLink.relayPlaintexts, ...fixture.targetLink.remotePlaintexts, ...fixture.targetLink.relayPlaintexts]
    expect(allOuterPlaintexts.every((plaintext) => !plaintext.includes(Buffer.from(targetInvite)))).toBe(true)
    expect(allOuterPlaintexts.every((plaintext) => !plaintext.includes(Buffer.from('inner-application-plaintext')))).toBe(true)
    const dataMessages = allOuterPlaintexts.map((plaintext) => {
      try { return decodeRelayMessage(plaintext) } catch { return null }
    }).filter((message) => message?.type === RelayMessageType.DATA)
    expect(dataMessages.length).toBeGreaterThan(0)

    admitted.connection.destroy()
    const reconnectStream = await fixture.requesterEndpoint.openCircuit(target.serverId)
    const reconnectSecure = await secureOverRelay(reconnectStream, target, requester)
    const reconnected = await reconnectSecure.authorizeExistingMember()
    expect(reconnected.connection.getState()).toBe('MEMBER_CONNECTED')
    expect(memberCount(target)).toBe(initialMembers + 1)
    expect(fixture.accepted).toHaveLength(2)
    reconnected.connection.destroy()
  })

  it('outer authorization does not grant target membership to an unknown reconnecting device', async () => {
    const target = await serverFixture('Relay target membership')
    const unknown = deviceIdentity()
    const fixture = await relayFixture(target, unknown)
    const stream = await fixture.requesterEndpoint.openCircuit(target.serverId)
    const secure = await secureOverRelay(stream, target, unknown)
    await expect(secure.authorizeExistingMember()).rejects.toBeDefined()
    expect(memberCount(target)).toBe(1)
  })

  it('rejects a relay-routed wrong Server Identity in the normal inner handshake', async () => {
    const targetX = await serverFixture('Claimed X')
    const targetY = await serverFixture('Actual Y')
    const requester = deviceIdentity()
    const relayIdentity = deviceIdentity()
    const targetOuterDevice = deviceIdentity()
    const targetLink = link({ serverId: relayIdentity.fingerprint, peerDeviceFingerprint: targetOuterDevice.fingerprint })
    const requesterLink = link({ serverId: relayIdentity.fingerprint, peerDeviceFingerprint: requester.fingerprint })
    const service = createPeerRelayService({ relayServerId: relayIdentity.fingerprint })
    createPeerRelayEndpoint({ channel: targetLink.relay, service })
    createPeerRelayEndpoint({ channel: requesterLink.relay, service })
    const targetEndpoint = createPeerRelayEndpoint({ channel: targetLink.remote })
    const requesterEndpoint = createPeerRelayEndpoint({ channel: requesterLink.remote })
    await targetEndpoint.registerTarget({
      targetServerId: targetX.serverId,
      targetServerPublicKey: targetX.publicKey,
      targetServerPrivateKey: targetX.privateKey,
      relayServerId: relayIdentity.fingerprint,
      outerDeviceFingerprint: targetOuterDevice.fingerprint,
      onIncomingCircuit: (stream) => {
        serverConnections.push(acceptRelayServerTransport({ transport: stream, storage: targetY.storage, localStorageId: targetY.storageId, serverId: targetY.serverId, serverPublicKey: targetY.publicKey, serverPrivateKey: targetY.privateKey }))
      }
    })
    const stream = await requesterEndpoint.openCircuit(targetX.serverId)
    await expect(secureOverRelay(stream, targetX, requester)).rejects.toBeDefined()
    expect(memberCount(targetX)).toBe(1)
    expect(memberCount(targetY)).toBe(1)
  })

  it('relay mutation of inner ciphertext causes failure only, without authority change', async () => {
    const target = await serverFixture('Tamper target')
    const requester = deviceIdentity()
    const fixture = await relayFixture(target, requester)
    const stream = await fixture.requesterEndpoint.openCircuit(target.serverId)
    let mutated = false
    fixture.requesterLink.setRemoteTransform((bytes) => {
      const message = decodeRelayMessage(bytes)
      if (!mutated && message.type === RelayMessageType.DATA) {
        mutated = true
        const payload = Buffer.from(message.payload)
        payload[Math.floor(payload.length / 2)]! ^= 1
        return encodeRelayMessage({ ...message, payload })
      }
      return bytes
    })
    await expect(secureOverRelay(stream, target, requester)).rejects.toBeDefined()
    expect(mutated).toBe(true)
    expect(memberCount(target)).toBe(1)
  })

  it('rendezvous and relay coexist on one post-auth dispatcher', async () => {
    const relayIdentity = deviceIdentity(); const target = deviceIdentity(); const device = deviceIdentity(); const linked = link({ serverId: relayIdentity.fingerprint, peerDeviceFingerprint: device.fingerprint })
    const service = createPeerRelayService({ relayServerId: relayIdentity.fingerprint })
    createPeerRelayEndpoint({ channel: linked.relay, service })
    createPeerRendezvousEndpoint({ channel: linked.relay, store: new RendezvousDescriptorStore() })
    const relayEndpoint = createPeerRelayEndpoint({ channel: linked.remote })
    const rendezvousEndpoint = createPeerRendezvousEndpoint({ channel: linked.remote })
    await expect(rendezvousEndpoint.requestDescriptor(target.fingerprint)).rejects.toMatchObject({ code: 'RENDEZVOUS_NOT_AVAILABLE' })
    await expect(relayEndpoint.openCircuit(target.fingerprint)).rejects.toMatchObject({ code: 'RELAY_TARGET_NOT_AVAILABLE' })
    expect(linked.remotePlaintexts.some((bytes) => bytes[1] === 0x20)).toBe(true)
    expect(linked.remotePlaintexts.some((bytes) => bytes[1] === 0x35)).toBe(true)
  })
})
