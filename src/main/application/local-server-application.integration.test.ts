import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { DATABASE_FILE_NAME, openServerDatabase } from '../servers/server-database'
import {
  ClientTcpPeerConnection,
  startTcpServer,
  tcpTransportTestOnly,
  type ServerTcpPeerConnection,
  type TcpServerHandle
} from '../network/tcp-transport'
import { createPeerRendezvousEndpoint, RendezvousDescriptorStore } from '../network/peer-rendezvous'
import { createPeerRelayEndpoint, createPeerRelayService } from '../network/peer-relay'
import { createApplicationClient } from './application-endpoint'
import { attachLocalServerApplication } from './local-server-application'

const roots: string[] = []
const listeners: TcpServerHandle[] = []
const clients: ClientTcpPeerConnection[] = []

afterEach(async () => {
  clients.splice(0).forEach((client) => client.destroy())
  await Promise.all(listeners.splice(0).map((listener) => listener.close()))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
  vi.restoreAllMocks()
})

function device() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-application-'))
  roots.push(root)
  const owner = device()
  let privateKey: KeyObject | undefined
  const secrets = new Map<string, string>()
  const storage = createLocalServerStorage(root, {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptString: (plaintext) => {
      const key = `fixture:${secrets.size}`
      secrets.set(key, plaintext)
      privateKey = createPrivateKey({ key: Buffer.from(plaintext, 'base64'), format: 'der', type: 'pkcs8' })
      return Buffer.from(key)
    },
    decryptString: (encrypted) => {
      const plaintext = secrets.get(encrypted.toString())
      if (!plaintext) throw new Error('fixture secret missing')
      return plaintext
    }
  }, createAuthenticatedCandidateDevice(owner.fingerprint, owner.publicKey), { platform: 'win32' })
  const server = await storage.createLocalServer('Masquerada local')
  if (!privateKey) throw new Error('fixture private key missing')
  return { root, storage, server, privateKey }
}

async function connectFixture() {
  const host = await fixture()
  const member = device()
  let hostConnection: ServerTcpPeerConnection | undefined
  let resolveApplication!: () => void
  let rejectApplication!: (error: unknown) => void
  const applicationReady = new Promise<void>((resolve, reject) => {
    resolveApplication = resolve
    rejectApplication = reject
  })
  const relayService = createPeerRelayService({ relayServerId: host.server.serverId })
  const listener = await startTcpServer({
    host: '127.0.0.1', port: 0,
    storage: host.storage,
    localStorageId: host.server.localStorageId,
    serverId: host.server.serverId,
    serverPublicKey: host.server.identity.publicKey,
    serverPrivateKey: host.privateKey,
    onMemberConnected: (connection) => {
      hostConnection = connection
      const channel = connection.getAuthorizedChannel()!
      createPeerRendezvousEndpoint({ channel, store: new RendezvousDescriptorStore() })
      createPeerRelayEndpoint({ channel, service: relayService })
      void attachLocalServerApplication({ storage: host.storage, localStorageId: host.server.localStorageId, channel })
        .then(resolveApplication, rejectApplication)
    }
  })
  listeners.push(listener)
  const invite = await host.storage.createLocalServerInvite(host.server.localStorageId, {
    expiresAt: Math.floor(Date.now() / 1000) + 3600, maxUses: 1
  })
  const connection = new ClientTcpPeerConnection({
    host: listener.host, port: listener.port,
    expectedServerId: host.server.serverId,
    expectedServerPublicKey: host.server.identity.publicKey,
    deviceFingerprint: member.fingerprint,
    devicePublicKey: member.publicKey,
    devicePrivateKey: member.privateKey,
    invite: invite.encoded
  })
  clients.push(connection)
  await connection.waitForAdmission()
  await applicationReady
  const channel = connection.getAuthorizedChannel()!
  const application = createApplicationClient({ channel, expectedServerId: host.server.serverId })
  return { ...host, member, connection, hostConnection: hostConnection!, application, channel }
}

describe('local application over an authorized secure connection', () => {
  it('returns only public state and coexists with rendezvous and relay with one decrypt per frame', async () => {
    const host = await connectFixture()
    const serverDecrypt = vi.spyOn(host.hostConnection.getSession()!, 'decrypt')
    const clientDecrypt = vi.spyOn(host.connection.getSession()!, 'decrypt')
    const state = await host.application.requestServerState()
    expect(state).toEqual({ displayName: 'Masquerada local', channels: [] })
    expect(serverDecrypt).toHaveBeenCalledTimes(1)
    expect(clientDecrypt).toHaveBeenCalledTimes(1)
    const rendezvous = createPeerRendezvousEndpoint({ channel: host.channel })
    const relay = createPeerRelayEndpoint({ channel: host.channel })
    const missingServer = device().fingerprint
    await expect(rendezvous.requestDescriptor(missingServer)).rejects.toBeDefined()
    await expect(relay.openCircuit(missingServer)).rejects.toBeDefined()
    expect(await host.application.requestServerState()).toEqual(state)
    expect(serverDecrypt).toHaveBeenCalledTimes(4)
    expect(clientDecrypt).toHaveBeenCalledTimes(4)
  })

  it('revalidates persisted membership rather than trusting a still-open authorized channel', async () => {
    const host = await connectFixture()
    expect((await host.application.requestServerState()).displayName).toBe('Masquerada local')
    const db = openServerDatabase(join(host.root, 'servers', host.server.localStorageId, DATABASE_FILE_NAME))
    try {
      db.exec('BEGIN IMMEDIATE;')
      db.prepare('DELETE FROM member_certificates WHERE device_fingerprint = ?').run(host.member.fingerprint)
      db.prepare('DELETE FROM members WHERE device_fingerprint = ?').run(host.member.fingerprint)
      db.exec('COMMIT;')
    } finally {
      db.close()
    }
    await expect(host.application.requestServerState()).rejects.toBeDefined()
  })

  it('does not disclose state when membership is removed while loading the snapshot', async () => {
    const host = await connectFixture()
    const verify = host.storage.verifyLocalServerMemberAuthorization.bind(host.storage)
    let checks = 0
    const guardedStorage = {
      ...host.storage,
      verifyLocalServerMemberAuthorization: async (...args: Parameters<typeof verify>) => {
        checks++
        return checks === 1 ? verify(...args) : { isAuthorized: false, isOwner: false }
      }
    }
    const harness = tcpTransportTestOnly.createAuthorizedPeerChannel({
      serverId: host.server.serverId,
      peerDeviceFingerprint: host.member.fingerprint,
      onSend: async (bytes) => {
        expect(bytes.includes(Buffer.from('Masquerada local'))).toBe(false)
      }
    })
    const endpoint = await attachLocalServerApplication({
      storage: guardedStorage, localStorageId: host.server.localStorageId, channel: harness.channel
    })
    const { encodeApplicationEnvelope } = await import('./application-protocol')
    try {
      await harness.deliver(encodeApplicationEnvelope({
        kind: 'request', messageType: 'server-state.request', messageId: 'a'.repeat(32),
        correlationId: null, serverId: host.server.serverId, channelId: null, sequence: null, payload: {}
      }))
      // The host handler returns before its async authorize/read chain completes.
      await vi.waitFor(() => expect(checks).toBe(2))
    } finally {
      endpoint.close()
      harness.close()
    }
  })

  it('rejects host binding mismatch before installing an application handler', async () => {
    const host = await fixture()
    const harness = tcpTransportTestOnly.createAuthorizedPeerChannel({
      serverId: device().fingerprint, peerDeviceFingerprint: device().fingerprint,
      onSend: async () => { throw new Error('must not send') }
    })
    try {
      await expect(attachLocalServerApplication({
        storage: host.storage, localStorageId: host.server.localStorageId, channel: harness.channel
      })).rejects.toBeDefined()
    } finally {
      harness.close()
    }
  })

  it('paginates history by cursor with host-assigned sequences and revalidates membership per request', async () => {
    const host = await connectFixture()
    const channelIds = await host.storage.listLocalServerChannels(host.server.localStorageId)
    expect(channelIds).toEqual([])

    // Seed a channel with several messages as the owner.
    const ownerFingerprint = host.server.initialOwner.deviceFingerprint
    const created = await host.storage.createLocalServerChannel(host.server.localStorageId, {
      name: 'Geral', actorFingerprint: ownerFingerprint
    })
    const createdIds: string[] = []
    for (let index = 1; index <= 5; index++) {
      const message = await host.storage.createLocalServerMessage(host.server.localStorageId, {
        channelId: created.channelId,
        content: `Mensagem ${index}`,
        clientMessageId: index.toString(16).padStart(32, '0'),
        actorFingerprint: ownerFingerprint
      })
      createdIds.push(message.messageId)
    }

    const firstPage = await host.application.requestHistory({
      channelId: created.channelId, afterSequence: 0, limit: 2
    })
    expect(firstPage.messages.map((message) => message.sequence)).toEqual([1, 2])
    expect(firstPage.messages[0]!.content).toBe('Mensagem 1')
    expect(firstPage.hasMore).toBe(true)

    const secondPage = await host.application.requestHistory({
      channelId: created.channelId, afterSequence: 2, limit: 2
    })
    expect(secondPage.messages.map((message) => message.sequence)).toEqual([3, 4])
    expect(secondPage.hasMore).toBe(true)

    const thirdPage = await host.application.requestHistory({
      channelId: created.channelId, afterSequence: 4, limit: 2
    })
    expect(thirdPage.messages.map((message) => message.sequence)).toEqual([5])
    expect(thirdPage.hasMore).toBe(false)

    // Deleted messages surface as tombstones with empty content.
    await host.storage.deleteLocalServerMessage(host.server.localStorageId, {
      messageId: createdIds[2]!, actorFingerprint: ownerFingerprint
    })
    const afterDelete = await host.application.requestHistory({
      channelId: created.channelId, afterSequence: 2, limit: 1
    })
    expect(afterDelete.messages[0]!.content).toBe('')
    expect(afterDelete.messages[0]!.deletedAt).not.toBeNull()

    // Non-members cannot read history even with a still-authorized channel.
    const db = openServerDatabase(join(host.root, 'servers', host.server.localStorageId, DATABASE_FILE_NAME))
    try {
      db.exec('BEGIN IMMEDIATE;')
      db.prepare('DELETE FROM member_certificates WHERE device_fingerprint = ?').run(host.member.fingerprint)
      db.prepare('DELETE FROM members WHERE device_fingerprint = ?').run(host.member.fingerprint)
      db.exec('COMMIT;')
    } finally {
      db.close()
    }
    await expect(host.application.requestHistory({
      channelId: created.channelId, afterSequence: 0, limit: 10
    })).rejects.toBeDefined()

    // Channel ids from a peer never select a storage path: unknown channel is a safe miss.
    await expect(host.application.requestHistory({
      channelId: 'f'.repeat(32), afterSequence: 0, limit: 10
    })).rejects.toBeDefined()
  })

  it('rejects history requests above the wire batch limit and unknown message types', async () => {
    const host = await connectFixture()
    await expect(host.application.requestHistory({
      channelId: 'a'.repeat(32), afterSequence: 0, limit: 101
    })).rejects.toBeDefined()
  })

  it('delivers member messages with dedup and refuses non-members with an explicit wire error', async () => {
    const host = await connectFixture()
    const ownerFingerprint = host.server.initialOwner.deviceFingerprint
    const created = await host.storage.createLocalServerChannel(host.server.localStorageId, {
      name: 'Geral', actorFingerprint: ownerFingerprint
    })

    const accepted = await host.application.sendMessage({
      channelId: created.channelId, clientMessageId: 'd'.repeat(32), content: 'Primeira do membro'
    })
    expect(accepted.sequence).toBe(1)
    expect(accepted.dedup).toBe(false)

    const replay = await host.application.sendMessage({
      channelId: created.channelId, clientMessageId: 'd'.repeat(32), content: 'Primeira do membro'
    })
    expect(replay.dedup).toBe(true)
    expect(replay.messageId).toBe(accepted.messageId)
    expect(replay.sequence).toBe(accepted.sequence)

    const second = await host.application.sendMessage({
      channelId: created.channelId, clientMessageId: 'e'.repeat(32), content: 'Segunda do membro'
    })
    expect(second.sequence).toBe(2)
    expect(second.dedup).toBe(false)

    const page = await host.application.requestHistory({
      channelId: created.channelId, afterSequence: 0, limit: 10
    })
    expect(page.messages).toHaveLength(2)
    expect(page.messages[0]!.content).toBe('Primeira do membro')
  })
})
