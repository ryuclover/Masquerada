import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer, type Server, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import {
  DATABASE_FILE_NAME,
  listMembers,
  openServerDatabase
} from '../servers/server-database'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  type ConnectivityCandidate
} from './connectivity-descriptor'
import {
  connectToServerViaRendezvous,
  createPeerRendezvousEndpoint,
  markRendezvousShareable,
  RENDEZVOUS_REQUEST_BYTES,
  RendezvousDescriptorStore
} from './peer-rendezvous'
import type { SecureConnectionAttempt } from './candidate-racing'
import { encodeSessionFrame } from './p2p-session'
import {
  ClientTcpPeerConnection,
  connectAndAdmitTcpPeer,
  establishSecureServerConnection,
  startTcpServer,
  type ServerTcpPeerConnection,
  type TcpServerHandle
} from './tcp-transport'

interface ServerFixture {
  readonly root: string
  readonly storage: ReturnType<typeof createLocalServerStorage>
  readonly storageId: string
  readonly serverId: string
  readonly publicKey: Buffer
  readonly privateKey: KeyObject
}

const roots: string[] = []
const tcpServers: TcpServerHandle[] = []
const rawServers: Server[] = []
const rawSockets: Socket[] = []

afterEach(async () => {
  for (const socket of rawSockets.splice(0)) socket.destroy()
  await Promise.all(rawServers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
  await Promise.all(tcpServers.splice(0).map((server) => server.close()))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
  vi.restoreAllMocks()
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
  const root = await mkdtemp(join(tmpdir(), 'masquerada-rendezvous-'))
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
        try {
          serverPrivateKey = createPrivateKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'pkcs8' })
        } catch { /* not a private key */ }
        return Buffer.from(key)
      },
      decryptString: (value: Buffer) => {
        const result = plaintext.get(value.toString())
        if (!result) throw new Error('missing protected fixture value')
        return result
      }
    },
    createAuthenticatedCandidateDevice(owner.fingerprint, owner.publicKey),
    { platform: 'win32', generateStorageId: () => (++counter).toString(16).padStart(32, '0') }
  )
  const server = await storage.createLocalServer(name)
  if (!serverPrivateKey) throw new Error('missing server key')
  return {
    root,
    storage,
    storageId: server.localStorageId,
    serverId: server.serverId,
    publicKey: server.identity.publicKey,
    privateKey: serverPrivateKey
  }
}

async function startFixtureServer(
  fixture: ServerFixture,
  onMemberConnected?: (connection: ServerTcpPeerConnection) => void
): Promise<TcpServerHandle> {
  const handle = await startTcpServer({
    host: '127.0.0.1',
    port: 0,
    storage: fixture.storage,
    localStorageId: fixture.storageId,
    serverId: fixture.serverId,
    serverPublicKey: fixture.publicKey,
    serverPrivateKey: fixture.privateKey,
    onMemberConnected
  })
  tcpServers.push(handle)
  return handle
}

async function invite(fixture: ServerFixture, maxUses = 1): Promise<string> {
  return (await fixture.storage.createLocalServerInvite(fixture.storageId, {
    expiresAt: 2_000_000_000,
    maxUses
  })).encoded
}

function memberCount(fixture: ServerFixture): number {
  const db = openServerDatabase(join(fixture.root, 'servers', fixture.storageId, DATABASE_FILE_NAME))
  const count = listMembers(db).length
  db.close()
  return count
}

async function rawHttpServer(): Promise<number> {
  const server = createServer((socket) => {
    rawSockets.push(socket)
    socket.write('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
  })
  rawServers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('missing raw address')
  return address.port
}

describe('peer-provided rendezvous over real authorized channels', () => {
  it('rejects rendezvous plaintext in SECURE_UNAUTHORIZED before membership', async () => {
    const peerR = await serverFixture('Peer R pre-auth')
    const handleR = await startFixtureServer(peerR)
    const requester = deviceIdentity()
    const client = new ClientTcpPeerConnection({
      host: handleR.host,
      port: handleR.port,
      expectedServerId: peerR.serverId,
      expectedServerPublicKey: peerR.publicKey,
      deviceFingerprint: requester.fingerprint,
      devicePublicKey: requester.publicKey,
      devicePrivateKey: requester.privateKey,
      deferAuthorization: true
    })
    await client.waitForSecureConnection()
    expect(client.getState()).toBe('SECURE_UNAUTHORIZED')
    expect(client.getAuthorizedChannel()).toBeNull()
    const session = client.getSession()!
    const invalidPreAuthRequest = Buffer.alloc(105)
    invalidPreAuthRequest[0] = 1
    invalidPreAuthRequest[1] = 0x20
    await client.writeFrame(encodeSessionFrame(session.encrypt(invalidPreAuthRequest)))
    await expect(client.waitForAdmission()).rejects.toBeDefined()
    expect(client.getAuthorizedChannel()).toBeNull()
  })

  it('forwards raw metadata over R, decrypts once, races direct, admits once, then reconnects', async () => {
    const peerR = await serverFixture('Peer R')
    const targetX = await serverFixture('Target X')
    const requester = deviceIdentity()
    const rawPort = await rawHttpServer()
    const handleX = await startFixtureServer(targetX)

    const candidates: ConnectivityCandidate[] = [
      { candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP, family: 4, address: '1.1.1.1', port: rawPort },
      { candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP, family: 4, address: '8.8.8.8', port: handleX.port }
    ]
    const rawDescriptor = createSignedConnectivityDescriptor({
      serverId: targetX.serverId,
      serverPublicKey: targetX.publicKey,
      serverPrivateKey: targetX.privateKey,
      candidates,
      allowRawCandidatesForTesting: true
    })
    const verified = verifySignedConnectivityDescriptor({
      encodedDescriptor: rawDescriptor,
      expectedServerId: targetX.serverId
    })
    const storeR = new RendezvousDescriptorStore()
    storeR.put(markRendezvousShareable(verified))

    let serverRConnection: ServerTcpPeerConnection | undefined
    let serverREndpointCreated = false
    const handleR = await startFixtureServer(peerR, (connection) => {
      serverRConnection = connection
      createPeerRendezvousEndpoint({ channel: connection.getAuthorizedChannel()!, store: storeR })
      serverREndpointCreated = true
    })
    const inviteR = await invite(peerR)
    const channelToR = connectAndAdmitTcpPeer({
      host: handleR.host,
      port: handleR.port,
      expectedServerId: peerR.serverId,
      expectedServerPublicKey: peerR.publicKey,
      deviceFingerprint: requester.fingerprint,
      devicePublicKey: requester.publicKey,
      devicePrivateKey: requester.privateKey,
      invite: inviteR
    })
    expect(channelToR.getAuthorizedChannel()).toBeNull()
    await channelToR.waitForAdmission()
    expect(serverREndpointCreated).toBe(true)
    const requesterEndpoint = createPeerRendezvousEndpoint({ channel: channelToR.getAuthorizedChannel()! })

    const serverSession = serverRConnection!.getSession()!
    const clientSession = channelToR.getSession()!
    const originalServerDecrypt = serverSession.decrypt.bind(serverSession)
    const originalClientDecrypt = clientSession.decrypt.bind(clientSession)
    const rendezvousPlaintexts: Buffer[] = []
    const serverDecrypt = vi.spyOn(serverSession, 'decrypt').mockImplementation((payload) => {
      const plaintext = originalServerDecrypt(payload)
      rendezvousPlaintexts.push(Buffer.from(plaintext))
      return plaintext
    })
    const clientDecrypt = vi.spyOn(clientSession, 'decrypt').mockImplementation(originalClientDecrypt)
    const lowLevel = await requesterEndpoint.requestDescriptor(targetX.serverId)
    expect(lowLevel.getRawEncoded()).toEqual(rawDescriptor)
    expect(serverDecrypt).toHaveBeenCalledTimes(1)
    expect(clientDecrypt).toHaveBeenCalledTimes(1)
    expect(rendezvousPlaintexts[0]).toHaveLength(RENDEZVOUS_REQUEST_BYTES)

    const membersBeforeRendezvous = memberCount(peerR)
    const targetInvite = await invite(targetX)
    let decoyAttempts = 0
    let correctAttempts = 0
    const establish: SecureConnectionAttempt = async (target, options) => {
      const decoy = target.address === '1.1.1.1'
      if (decoy) decoyAttempts += 1
      else correctAttempts += 1
      return establishSecureServerConnection({
        endpoint: { family: 4, address: '127.0.0.1', port: decoy ? rawPort : handleX.port },
        expectedServerId: options.expectedServerId,
        expectedServerPublicKey: options.expectedServerPublicKey,
        deviceFingerprint: options.device.fingerprint,
        devicePublicKey: options.device.publicKey,
        devicePrivateKey: options.device.privateKey,
        signal: options.signal
      })
    }

    const admitted = await connectToServerViaRendezvous({
      rendezvous: requesterEndpoint,
      targetServerId: targetX.serverId,
      device: requester,
      authorization: { mode: 'admission', invite: targetInvite },
      establishConnection: establish
    })
    expect(admitted.getState()).toBe('MEMBER_CONNECTED')
    admitted.destroy()
    expect(decoyAttempts).toBeGreaterThanOrEqual(1)
    expect(correctAttempts).toBeGreaterThanOrEqual(1)
    expect(rendezvousPlaintexts.every((plaintext) => !plaintext.includes(Buffer.from(targetInvite)))).toBe(true)
    expect(memberCount(peerR)).toBe(membersBeforeRendezvous)

    const reconnected = await connectToServerViaRendezvous({
      rendezvous: requesterEndpoint,
      targetServerId: targetX.serverId,
      device: requester,
      authorization: { mode: 'reconnect' },
      establishConnection: establish
    })
    expect(reconnected.getState()).toBe('MEMBER_CONNECTED')
    reconnected.destroy()
    expect(memberCount(peerR)).toBe(membersBeforeRendezvous)
    expect(rendezvousPlaintexts.every((plaintext) => plaintext.length === RENDEZVOUS_REQUEST_BYTES)).toBe(true)

    channelToR.destroy()
  })
})
