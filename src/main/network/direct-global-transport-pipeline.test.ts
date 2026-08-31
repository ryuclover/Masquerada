import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { createConnection, createServer, type ListenOptions, type Server } from 'node:net'
import { type NetworkInterfaceInfo } from 'node:os'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { DATABASE_FILE_NAME, listMembers, openServerDatabase } from '../servers/server-database'
import {
  type ActiveDirectGlobalListener,
  directGlobalTransportTestOnly,
  type StartDirectGlobalTcpServerOptions
} from './direct-global-transport'
import { connectAndAdmitTcpPeer, type ClientTcpPeerConnection } from './tcp-transport'

const GLOBAL = '2600::1234'
const roots: string[] = []
const listeners: ActiveDirectGlobalListener[] = []
const clients: ClientTcpPeerConnection[] = []

afterEach(async () => {
  for (const client of clients.splice(0)) client.destroy()
  await Promise.all(listeners.splice(0).map((listener) => listener.close()))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

class LoopbackIpv6MasqueradeServer extends EventEmitter {
  private readonly actual = createServer({ allowHalfOpen: false })
  listenOptions: ListenOptions | null = null

  constructor() {
    super()
    this.actual.on('connection', (socket) => this.emit('connection', socket))
    this.actual.on('error', (error) => this.emit('error', error))
  }

  get listening(): boolean {
    return this.actual.listening
  }

  get actualPort(): number {
    const address = this.actual.address()
    return typeof address === 'object' && address ? address.port : 0
  }

  listen(options: ListenOptions, callback?: () => void): this {
    this.listenOptions = options
    this.actual.listen({ host: '::1', port: 0, ipv6Only: true }, callback)
    return this
  }

  address() {
    if (!this.actual.listening) return null
    return { address: GLOBAL, family: 'IPv6', port: this.actualPort }
  }

  close(callback?: (error?: Error) => void): this {
    if (!this.actual.listening) {
      queueMicrotask(() => callback?.())
      return this
    }
    this.actual.close(callback)
    return this
  }

  asServer(): Server {
    return this as unknown as Server
  }
}

function globalProvider() {
  return {
    wan0: [{
      address: GLOBAL,
      family: 'IPv6',
      internal: false,
      cidr: `${GLOBAL}/64`,
      netmask: 'ffff:ffff:ffff:ffff::',
      mac: '00:00:00:00:00:01',
      scopeid: 0
    } as NetworkInterfaceInfo]
  }
}

async function startControlledGlobal(
  fixture: Awaited<ReturnType<typeof createServerFixture>>,
  overrides: Partial<StartDirectGlobalTcpServerOptions> = {}
) {
  const transport = new LoopbackIpv6MasqueradeServer()
  const listener = await directGlobalTransportTestOnly.start({
    localAddress: GLOBAL,
    port: 0,
    storage: fixture.storage,
    localStorageId: fixture.storageId,
    serverId: fixture.serverId,
    serverPublicKey: fixture.publicKey,
    serverPrivateKey: fixture.privateKey,
    ...overrides
  }, {
    interfaceProvider: globalProvider,
    serverFactory: () => transport.asServer()
  })
  listeners.push(listener)
  return { listener, transport }
}

describe('Direct Global IPv6 preserva a pipeline TCP segura existente', () => {
  it('executa handshake, SecureSession e admission MQR1 sem trust por endereço', async () => {
    const serverFixture = await createServerFixture()
    const device = createClientFixture()
    const { encoded: invite } = await serverFixture.storage.createLocalServerInvite(
      serverFixture.storageId,
      { expiresAt: 2_000_000_000, maxUses: 1 }
    )
    const { transport } = await startControlledGlobal(serverFixture)

    const client = connectAndAdmitTcpPeer({
      host: '::1',
      port: transport.actualPort,
      expectedServerId: serverFixture.serverId,
      deviceFingerprint: device.fingerprint,
      devicePublicKey: device.publicKey,
      devicePrivateKey: device.privateKey,
      invite,
      authorizationMode: 'admission'
    })
    clients.push(client)

    await expect(client.waitForAdmission()).resolves.toEqual({ status: 'admitted' })
    expect(client.getState()).toBe('MEMBER_CONNECTED')
    expect(getMembers(serverFixture).some((member) => member.deviceFingerprint === device.fingerprint)).toBe(true)
  })

  it('reconnect legítimo continua exigindo identidade já admitida', async () => {
    const serverFixture = await createServerFixture()
    const device = createClientFixture()
    const { encoded: invite } = await serverFixture.storage.createLocalServerInvite(
      serverFixture.storageId,
      { expiresAt: 2_000_000_000, maxUses: 1 }
    )
    const { transport } = await startControlledGlobal(serverFixture)

    const admission = connectAndAdmitTcpPeer({
      host: '::1', port: transport.actualPort,
      expectedServerId: serverFixture.serverId,
      deviceFingerprint: device.fingerprint,
      devicePublicKey: device.publicKey,
      devicePrivateKey: device.privateKey,
      invite,
      authorizationMode: 'admission'
    })
    clients.push(admission)
    await admission.waitForAdmission()
    admission.destroy()

    const reconnect = connectAndAdmitTcpPeer({
      host: '::1', port: transport.actualPort,
      expectedServerId: serverFixture.serverId,
      deviceFingerprint: device.fingerprint,
      devicePublicKey: device.publicKey,
      devicePrivateKey: device.privateKey,
      authorizationMode: 'reconnect'
    })
    clients.push(reconnect)
    await expect(reconnect.waitForAuthorization()).resolves.toEqual({ status: 'authorized' })
    expect(reconnect.getState()).toBe('MEMBER_CONNECTED')
  })

  it('dispositivo desconhecido chegando pelo listener global é rejeitado', async () => {
    const serverFixture = await createServerFixture()
    const unknown = createClientFixture()
    const { transport } = await startControlledGlobal(serverFixture)
    const client = connectAndAdmitTcpPeer({
      host: '::1', port: transport.actualPort,
      expectedServerId: serverFixture.serverId,
      deviceFingerprint: unknown.fingerprint,
      devicePublicKey: unknown.publicKey,
      devicePrivateKey: unknown.privateKey,
      authorizationMode: 'reconnect'
    })
    clients.push(client)
    await expect(client.waitForAuthorization()).rejects.toBeDefined()
    expect(client.getState()).toBe('FAILED')
  })

  it('peer silencioso e frame malformado são encerrados dentro dos limites existentes', async () => {
    const serverFixture = await createServerFixture()
    const { transport } = await startControlledGlobal(serverFixture, { handshakeTimeoutMs: 30 })

    const silent = createConnection({ host: '::1', port: transport.actualPort })
    await new Promise<void>((resolve, reject) => {
      silent.once('connect', resolve)
      silent.once('error', reject)
    })
    await new Promise<void>((resolve) => silent.once('close', resolve))

    const malformed = createConnection({ host: '::1', port: transport.actualPort })
    await new Promise<void>((resolve, reject) => {
      malformed.once('connect', () => {
        malformed.write(Buffer.from([0x00, 0xff, 0xff, 0xff, 0xff]))
      })
      malformed.once('close', resolve)
      malformed.once('error', reject)
    })
  })

  it('preserva limites globais e por source no listener público', async () => {
    const serverFixture = await createServerFixture()
    const { listener, transport } = await startControlledGlobal(serverFixture, {
      maxConnections: 1,
      maxConnectionsPerIp: 1,
      handshakeTimeoutMs: 500
    })
    const first = createConnection({ host: '::1', port: transport.actualPort })
    await new Promise<void>((resolve, reject) => {
      first.once('connect', resolve)
      first.once('error', reject)
    })
    await waitUntil(() => listener.getActiveConnectionCount() === 1)

    const second = createConnection({ host: '::1', port: transport.actualPort })
    await new Promise<void>((resolve, reject) => {
      second.once('connect', resolve)
      second.once('error', reject)
    })
    await new Promise<void>((resolve) => second.once('close', resolve))
    expect(listener.getActiveConnectionCount()).toBe(1)
    expect(listener.getIpConnectionCount('0:0:0:0:0:0:0:1')).toBe(1)
    first.destroy()
  })
})

async function waitUntil(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('timeout')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

function getMembers(fixture: { root: string; storageId: string }) {
  const db = openServerDatabase(join(fixture.root, 'servers', fixture.storageId, DATABASE_FILE_NAME))
  const members = listMembers(db)
  db.close()
  return members
}

async function createServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-direct-global-'))
  roots.push(root)
  const secureStorage = createFakeSecureStorage()
  const ownerPair = generateKeyPairSync('ed25519')
  const ownerPublicKey = Buffer.from(ownerPair.publicKey.export({ format: 'der', type: 'spki' }))
  const ownerFingerprint = `sha256:${createHash('sha256').update(ownerPublicKey).digest('hex')}`
  const owner = createAuthenticatedCandidateDevice(ownerFingerprint, ownerPublicKey)
  let id = 1
  const storage = createLocalServerStorage(root, secureStorage.storage, owner, {
    platform: 'win32', generateStorageId: () => (id++).toString(16).padStart(32, '0')
  })
  const server = await storage.createLocalServer('Direct Global Test')
  if (!secureStorage.lastGeneratedServerKey) throw new Error('missing key')
  return {
    root,
    storage,
    storageId: server.localStorageId,
    serverId: server.serverId,
    publicKey: server.identity.publicKey,
    privateKey: secureStorage.lastGeneratedServerKey
  }
}

function createClientFixture() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    publicKey,
    privateKey: pair.privateKey,
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
  }
}

function createFakeSecureStorage() {
  const plaintext = new Map<string, string>()
  let counter = 0
  let lastKey: KeyObject | undefined
  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (value: string) => {
        const cipher = `direct-global:${++counter}`
        plaintext.set(cipher, value)
        try {
          lastKey = createPrivateKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'pkcs8' })
        } catch {
          lastKey = undefined
        }
        return Buffer.from(cipher)
      },
      decryptString: (cipher: Buffer) => {
        const value = plaintext.get(cipher.toString())
        if (!value) throw new Error('invalid ciphertext')
        return value
      }
    },
    get lastGeneratedServerKey() { return lastKey }
  }
}
