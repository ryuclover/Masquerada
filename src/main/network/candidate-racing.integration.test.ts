import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { createSocket, type Socket as DgramSocket } from 'node:dgram'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer, isIP, type Server, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { aggregateServerCandidates, type ServerDialPlan } from './candidate-aggregation'
import { connectToServerUsingCandidates, raceSecureServerConnections } from './candidate-racing'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  type ConnectivityCandidate
} from './connectivity-descriptor'
import {
  discoverLanServer,
  encodeDiscoveryResponse,
  parseDiscoveryQuery
} from './lan-discovery'
import { startTcpServer, type TcpServerHandle } from './tcp-transport'

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
const udpSockets: DgramSocket[] = []
const rawServers: Server[] = []
const rawSockets: Socket[] = []

afterEach(async () => {
  for (const socket of rawSockets.splice(0)) socket.destroy()
  await Promise.all(rawServers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
  for (const socket of udpSockets.splice(0)) socket.close()
  await Promise.all(tcpServers.splice(0).map((server) => server.close()))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
  vi.restoreAllMocks()
})

function clientIdentity() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

async function serverFixture(): Promise<ServerFixture> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-racing-'))
  roots.push(root)
  const plaintext = new Map<string, string>()
  let counter = 0
  let serverPrivateKey: KeyObject | undefined
  const owner = clientIdentity()
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
        } catch { /* non-key protected value */ }
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
  const server = await storage.createLocalServer('Racing integration')
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

function lanCandidate(port: number): ConnectivityCandidate {
  return {
    candidateType: ConnectivityCandidateType.LAN_TCP,
    family: 4,
    address: '127.0.0.1',
    port,
    scope: 'LOOPBACK'
  }
}

async function discoveredPlan(fixture: ServerFixture, ports: readonly number[]): Promise<ServerDialPlan> {
  const encoded = createSignedConnectivityDescriptor({
    serverId: fixture.serverId,
    serverPublicKey: fixture.publicKey,
    serverPrivateKey: fixture.privateKey,
    candidates: ports.map(lanCandidate),
    allowRawCandidatesForTesting: true,
    allowLoopbackForTesting: true
  })
  const udp = createSocket('udp4')
  udpSockets.push(udp)
  await new Promise<void>((resolve) => udp.bind(0, '127.0.0.1', resolve))
  udp.on('message', (message, source) => {
    const query = parseDiscoveryQuery(message)
    if (query) udp.send(encodeDiscoveryResponse(query.queryNonce, fixture.serverId, fixture.privateKey, encoded), source.port, source.address)
  })
  const discovery = await discoverLanServer({
    expectedServerId: fixture.serverId,
    localInterfaceAddress: '127.0.0.1',
    targetUnicastAddress: '127.0.0.1',
    port: udp.address().port,
    timeoutMs: 1000,
    allowLoopbackForTesting: true
  })
  return aggregateServerCandidates({
    expectedServerId: fixture.serverId,
    expectedServerPublicKey: fixture.publicKey,
    lanDiscoveries: [discovery]
  })
}

async function listeningRawServer(): Promise<{ server: Server; port: number }> {
  const server = createServer((socket) => {
    rawSockets.push(socket)
    socket.write('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
  })
  rawServers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('raw server address unavailable')
  return { server, port: address.port }
}

describe('real cryptographic racing and two-phase authorization', () => {
  it('does not treat raw TCP/HTTP acceptance as candidate success and performs no DNS', async () => {
    const fixture = await serverFixture()
    const raw = await listeningRawServer()
    const plan = await discoveredPlan(fixture, [raw.port])
    expect(plan.orderedDialTargets.every((target) => isIP(target.address) !== 0)).toBe(true)
    await expect(raceSecureServerConnections({
      plan,
      device: clientIdentity(),
      overallTimeoutMs: 250
    })).rejects.toMatchObject({ code: 'NO_REACHABLE_SERVER_CANDIDATE' })
  })

  it('authenticates SecureSession first, then performs one admission and preserves ALREADY_MEMBER', async () => {
    const fixture = await serverFixture()
    const handle = await startTcpServer({
      host: '127.0.0.1', port: 0,
      storage: fixture.storage, localStorageId: fixture.storageId,
      serverId: fixture.serverId, serverPublicKey: fixture.publicKey, serverPrivateKey: fixture.privateKey
    })
    tcpServers.push(handle)
    const plan = await discoveredPlan(fixture, [handle.port])
    const invite = await fixture.storage.createLocalServerInvite(fixture.storageId, {
      expiresAt: 2_000_000_000,
      maxUses: 2
    })
    const client = clientIdentity()
    const first = await connectToServerUsingCandidates({
      plan, device: client,
      authorization: { mode: 'admission', invite: invite.encoded }
    })
    expect(first.getState()).toBe('MEMBER_CONNECTED')
    first.destroy()
    const second = await connectToServerUsingCandidates({
      plan, device: client,
      authorization: { mode: 'admission', invite: invite.encoded }
    })
    expect(second.getState()).toBe('MEMBER_CONNECTED')
    second.destroy()
  })

  it('reconnects an existing member through a newly raced secure winner without an invite', async () => {
    const fixture = await serverFixture()
    const handle = await startTcpServer({
      host: '127.0.0.1', port: 0,
      storage: fixture.storage, localStorageId: fixture.storageId,
      serverId: fixture.serverId, serverPublicKey: fixture.publicKey, serverPrivateKey: fixture.privateKey
    })
    tcpServers.push(handle)
    const plan = await discoveredPlan(fixture, [handle.port])
    const invite = await fixture.storage.createLocalServerInvite(fixture.storageId, {
      expiresAt: 2_000_000_000,
      maxUses: 1
    })
    const client = clientIdentity()
    const admitted = await connectToServerUsingCandidates({
      plan, device: client, authorization: { mode: 'admission', invite: invite.encoded }
    })
    admitted.destroy()
    const reconnected = await connectToServerUsingCandidates({
      plan, device: client, authorization: { mode: 'reconnect' }
    })
    expect(reconnected.getState()).toBe('MEMBER_CONNECTED')
    reconnected.destroy()
  })
})
