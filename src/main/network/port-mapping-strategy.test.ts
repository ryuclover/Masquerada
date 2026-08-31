import { afterEach, describe, expect, it, vi } from 'vitest'
import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { createSocket, type Socket as DgramSocket } from 'node:dgram'
import { mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { ActivePortMappingSource, isLegitimateActivePortMapping } from './active-port-mapping'
import {
  createSignedConnectivityDescriptor,
  ConnectivityCandidateType,
  verifySignedConnectivityDescriptor
} from './connectivity-descriptor'
import { startLanTcpServer, type BoundTcpEndpoint, type DirectTcpEndpoint, type LanTcpServerHandle } from './lan-transport'
import { NatPmpError } from './nat-pmp-client'
import { PcpError, PcpResultCode } from './pcp-client'
import {
  classifyPortMappingFailure,
  createPreferredPortMapping,
  decideNextPortMappingBackend,
  ManagedPortMapping,
  PortMappingStrategyError,
  type PortMappingBackend,
  type PortMappingBackendAdapter,
  type PortMappingStrategyTestHooks
} from './port-mapping-strategy'
import { UpnpError } from './upnp-protocol'
import { ConnectivitySubsystem } from './connectivity-subsystem'

const roots: string[] = []
const listeners: LanTcpServerHandle[] = []
const udpSockets: DgramSocket[] = []

afterEach(async () => {
  vi.useRealTimers()
  await Promise.all(listeners.splice(0).map((listener) => listener.close()))
  await Promise.all(udpSockets.splice(0).map((socket) => new Promise<void>((resolve) => socket.close(() => resolve()))))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function fakeSecureStorage() {
  const values = new Map<string, string>()
  let counter = 0
  let lastKey: KeyObject | undefined
  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (plaintext: string) => {
        const token = `strategy:${++counter}`
        values.set(token, plaintext)
        try { lastKey = createPrivateKey({ key: Buffer.from(plaintext, 'base64'), format: 'der', type: 'pkcs8' }) } catch { lastKey = undefined }
        return Buffer.from(token)
      },
      decryptString: (encrypted: Buffer) => {
        const value = values.get(encrypted.toString())
        if (!value) throw new Error('ciphertext invalid')
        return value
      }
    },
    get key(): KeyObject | undefined { return lastKey }
  }
}

async function createFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masq-strategy-'))
  roots.push(root)
  const secure = fakeSecureStorage()
  const ownerPair = generateKeyPairSync('ed25519')
  const ownerKey = Buffer.from(ownerPair.publicKey.export({ format: 'der', type: 'spki' }))
  const owner = createAuthenticatedCandidateDevice(`sha256:${createHash('sha256').update(ownerKey).digest('hex')}`, ownerKey)
  let id = 1
  const storage = createLocalServerStorage(root, secure.storage, owner, {
    platform: 'win32',
    generateStorageId: () => (id++).toString(16).padStart(32, '0')
  })
  const server = await storage.createLocalServer('Strategy Test')
  if (!secure.key) throw new Error('missing server key')
  const listener = await startLanTcpServer({
    bindAddress: '127.0.0.1',
    port: 0,
    storage,
    localStorageId: server.localStorageId,
    serverId: server.serverId,
    serverPublicKey: server.identity.publicKey,
    serverPrivateKey: secure.key
  })
  listeners.push(listener)
  return { root, storage, server, listener, privateKey: secure.key }
}

class FakeBackendMapping extends ActivePortMappingSource {
  active = true
  closeCalls = 0
  renewCalls = 0
  closeFailure = false
  closeGate?: Promise<void>
  private endpoint: DirectTcpEndpoint
  private expiresAt: number

  constructor(
    private readonly listener: LanTcpServerHandle,
    endpoint: DirectTcpEndpoint,
    private lifetimeSeconds = 300
  ) {
    super()
    this.endpoint = endpoint
    this.expiresAt = Math.floor(Date.now() / 1000) + lifetimeSeconds
  }

  isActive(): boolean { return this.active && !this.listener.isClosed() && Date.now() / 1000 < this.expiresAt }
  getExternalEndpoint(): DirectTcpEndpoint { return { ...this.endpoint } }
  getExpiresAt(): number { return this.expiresAt }
  getGrantedLifetime(): number { return this.lifetimeSeconds }
  getInternalEndpoint(): BoundTcpEndpoint { return this.listener.endpoint }
  setEndpoint(endpoint: DirectTcpEndpoint): void { this.endpoint = endpoint }
  invalidate(): void { this.active = false }
  renew(): void {
    this.renewCalls += 1
    this.expiresAt = Math.floor(Date.now() / 1000) + this.lifetimeSeconds
  }
  async close(): Promise<void> {
    this.closeCalls += 1
    this.active = false
    if (this.closeGate) await this.closeGate
    if (this.closeFailure) throw new Error('advisory close failure')
  }
}

interface Deferred<T> {
  readonly promise: Promise<T>
  resolve(value: T): void
  reject(error: unknown): void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((accept, decline) => { resolve = accept; reject = decline })
  return { promise, resolve, reject }
}

type CreateOutcome = ActivePortMappingSource | Error | Promise<ActivePortMappingSource>
type RenewOutcome = Error | Promise<void> | (() => void | Promise<void>) | undefined

class AdapterHarness {
  readonly createCalls: Record<PortMappingBackend, number> = { PCP: 0, NAT_PMP: 0, UPNP: 0 }
  readonly renewCalls: Record<PortMappingBackend, number> = { PCP: 0, NAT_PMP: 0, UPNP: 0 }
  readonly createOutcomes: Record<PortMappingBackend, CreateOutcome[]> = { PCP: [], NAT_PMP: [], UPNP: [] }
  readonly renewOutcomes: Record<PortMappingBackend, RenewOutcome[]> = { PCP: [], NAT_PMP: [], UPNP: [] }
  readonly adapters: Readonly<Record<PortMappingBackend, PortMappingBackendAdapter>>

  constructor() {
    this.adapters = Object.freeze({
      PCP: this.adapter('PCP'),
      NAT_PMP: this.adapter('NAT_PMP'),
      UPNP: this.adapter('UPNP')
    })
  }

  private adapter(backend: PortMappingBackend): PortMappingBackendAdapter {
    return {
      create: async () => {
        this.createCalls[backend] += 1
        const outcome = this.createOutcomes[backend].shift()
        if (outcome instanceof Error) throw outcome
        if (!outcome) throw new Error(`missing ${backend} outcome`)
        return outcome
      },
      renew: async (mapping) => {
        this.renewCalls[backend] += 1
        const outcome = this.renewOutcomes[backend].shift()
        if (outcome instanceof Error) throw outcome
        if (outcome instanceof Promise) await outcome
        else if (outcome) await outcome()
        else if (mapping instanceof FakeBackendMapping) mapping.renew()
      }
    }
  }
}

class FakeScheduler {
  private nextId = 1
  readonly tasks = new Map<number, () => void>()
  readonly scheduler: NonNullable<PortMappingStrategyTestHooks['scheduler']> = {
    set: (callback) => {
      const id = this.nextId++
      this.tasks.set(id, callback)
      return id
    },
    clear: (handle) => { this.tasks.delete(handle as number) }
  }

  runNext(): void {
    const entry = this.tasks.entries().next().value as [number, () => void] | undefined
    if (!entry) throw new Error('no scheduled task')
    this.tasks.delete(entry[0])
    entry[1]()
  }
}

function mapping(
  listener: LanTcpServerHandle,
  address = '8.8.4.4',
  port = 55000,
  lifetime = 300
): FakeBackendMapping {
  return new FakeBackendMapping(listener, { family: 4, address, port }, lifetime)
}

function options(
  listener: LanTcpServerHandle,
  harness: AdapterHarness,
  scheduler = new FakeScheduler(),
  signal?: AbortSignal
) {
  return {
    listener,
    requestedLifetimeSeconds: 300,
    signal,
    testOnly: {
      gatewayProvider: { resolveGatewayForLocalAddress: async () => '127.0.0.1' },
      adapters: harness.adapters,
      scheduler: scheduler.scheduler,
      allowLoopback: true
    }
  }
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
}

async function startFakePcpGateway() {
  const socket = createSocket('udp4')
  let requests = 0
  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, '127.0.0.1', () => { socket.off('error', reject); resolve() })
  })
  udpSockets.push(socket)
  socket.on('message', (request, remote) => {
    requests += 1
    const response = Buffer.alloc(60)
    response[0] = 2
    response[1] = 0x81
    response.writeUInt32BE(request.readUInt32BE(4) === 0 ? 0 : 300, 4)
    response.writeUInt32BE(1000, 8)
    request.subarray(24, 36).copy(response, 24)
    response[36] = 6
    response.writeUInt16BE(request.readUInt16BE(40), 40)
    response.writeUInt16BE(55000, 42)
    response.writeUInt16BE(0xffff, 54)
    response.set([8, 8, 4, 4], 56)
    socket.send(response, remote.port, remote.address)
  })
  return { port: socket.address().port, requestCount: () => requests }
}

describe('PortMappingStrategy fallback matrix e classificação', () => {
  it.each([
    ['PCP', 'PROTOCOL_UNSUPPORTED', 'NAT_PMP'],
    ['PCP', 'NO_RESPONSE', 'UPNP'],
    ['PCP', 'EXPLICIT_DENIAL', null],
    ['PCP', 'RESOURCE_FAILURE', null],
    ['PCP', 'TOPOLOGY_INVALID', null],
    ['PCP', 'LOCAL_CONFIGURATION_FAILURE', null],
    ['PCP', 'ABORTED', null],
    ['PCP', 'INTERNAL_FAILURE', null],
    ['NAT_PMP', 'NO_RESPONSE', 'UPNP'],
    ['NAT_PMP', 'EXPLICIT_DENIAL', null],
    ['NAT_PMP', 'TOPOLOGY_INVALID', null],
    ['UPNP', 'NO_RESPONSE', null],
    ['UPNP', 'PROTOCOL_UNSUPPORTED', null]
  ] as const)('%s + %s -> %s', (backend, disposition, expected) => {
    expect(decideNextPortMappingBackend(backend, disposition)).toBe(expected)
  })

  it.each([
    ['PCP', new PcpError('PCP_UNSUPPORTED_VERSION'), 'PROTOCOL_UNSUPPORTED'],
    ['PCP', new PcpError('PCP_TIMEOUT'), 'NO_RESPONSE'],
    ['PCP', new PcpError('PCP_SERVER_ERROR', PcpResultCode.NOT_AUTHORIZED), 'EXPLICIT_DENIAL'],
    ['PCP', new PcpError('PCP_SERVER_ERROR', PcpResultCode.NO_RESOURCES), 'RESOURCE_FAILURE'],
    ['PCP', new PcpError('PCP_EXTERNAL_ADDRESS_NOT_GLOBAL'), 'TOPOLOGY_INVALID'],
    ['NAT_PMP', new NatPmpError('NAT_PMP_NOT_AUTHORIZED'), 'EXPLICIT_DENIAL'],
    ['NAT_PMP', new NatPmpError('NAT_PMP_TIMEOUT'), 'NO_RESPONSE'],
    ['NAT_PMP', new NatPmpError('NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL'), 'TOPOLOGY_INVALID'],
    ['UPNP', new UpnpError('UPNP_SSDP_TIMEOUT'), 'NO_RESPONSE'],
    ['UPNP', new UpnpError('UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'), 'TOPOLOGY_INVALID'],
    ['PCP', { code: 'PCP_TIMEOUT' }, 'INTERNAL_FAILURE'],
    ['UPNP', new Error('UPNP_SSDP_TIMEOUT'), 'INTERNAL_FAILURE']
  ] as const)('classifica %s sem string matching permissivo', (backend, error, expected) => {
    expect(classifyPortMappingFailure(backend, error)).toBe(expected)
  })
})

describe('PortMappingStrategy creation sequencial', () => {
  it('PCP success seleciona PCP sem NAT-PMP ou UPnP', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    expect(managed.getBackendForTesting()).toBe('PCP')
    expect(harness.createCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 0 })
    await managed.close()
  })

  it('PCP Unsupported seleciona NAT-PMP e não toca UPnP', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'))
    harness.createOutcomes.NAT_PMP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    expect(managed.getBackendForTesting()).toBe('NAT_PMP')
    expect(harness.createCalls).toEqual({ PCP: 1, NAT_PMP: 1, UPNP: 0 })
    await managed.close()
  })

  it('PCP Unsupported + NAT-PMP timeout seleciona UPnP', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'))
    harness.createOutcomes.NAT_PMP.push(new NatPmpError('NAT_PMP_TIMEOUT'))
    harness.createOutcomes.UPNP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    expect(managed.getBackendForTesting()).toBe('UPNP')
    expect(harness.createCalls).toEqual({ PCP: 1, NAT_PMP: 1, UPNP: 1 })
    await managed.close()
  })

  it('PCP timeout pula NAT-PMP e seleciona UPnP', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'))
    harness.createOutcomes.UPNP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    expect(managed.getBackendForTesting()).toBe('UPNP')
    expect(harness.createCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 1 })
    await managed.close()
  })

  it.each([
    [new PcpError('PCP_SERVER_ERROR', PcpResultCode.NOT_AUTHORIZED), 'PORT_MAPPING_DENIED'],
    [new PcpError('PCP_SERVER_ERROR', PcpResultCode.NO_RESOURCES), 'PORT_MAPPING_DENIED'],
    [new PcpError('PCP_EXTERNAL_ADDRESS_NOT_GLOBAL'), 'PORT_MAPPING_TOPOLOGY_INVALID']
  ] as const)('PCP denial/topology para sem fallback', async (failure, code) => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(failure)
    await expect(createPreferredPortMapping(options(fixture.listener, harness))).rejects.toThrow(
      expect.objectContaining({ code })
    )
    expect(harness.createCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 0 })
  })

  it.each([
    [new NatPmpError('NAT_PMP_NOT_AUTHORIZED'), 'PORT_MAPPING_DENIED'],
    [new NatPmpError('NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL'), 'PORT_MAPPING_TOPOLOGY_INVALID']
  ] as const)('NAT-PMP denial/topology para antes de UPnP', async (failure, code) => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'))
    harness.createOutcomes.NAT_PMP.push(failure)
    await expect(createPreferredPortMapping(options(fixture.listener, harness))).rejects.toThrow(
      expect.objectContaining({ code })
    )
    expect(harness.createCalls.UPNP).toBe(0)
  })

  it('UPnP failure é terminal e agrega apenas backends seguros', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'))
    harness.createOutcomes.UPNP.push(new UpnpError('UPNP_SSDP_TIMEOUT'))
    await expect(createPreferredPortMapping(options(fixture.listener, harness))).rejects.toThrow(
      expect.objectContaining({
        code: 'NO_PORT_MAPPING_AVAILABLE',
        attemptedBackends: ['PCP', 'UPNP']
      })
    )
  })

  it('listener forjado falha antes de adapters e Managed constructor sem token falha', async () => {
    const harness = new AdapterHarness()
    await expect(createPreferredPortMapping(options({} as LanTcpServerHandle, harness))).rejects.toThrow(
      expect.objectContaining({ code: 'PORT_MAPPING_LISTENER_INVALID' })
    )
    expect(harness.createCalls).toEqual({ PCP: 0, NAT_PMP: 0, UPNP: 0 })
    expect(() => new ManagedPortMapping({} as never)).toThrow(PortMappingStrategyError)
    expect(isLegitimateActivePortMapping({ isActive: () => true })).toBe(false)
  })
})

describe('PortMappingStrategy abort, registry e listeners', () => {
  it.each(['PCP', 'NAT_PMP', 'UPNP'] as const)('abort durante %s impede qualquer fallback posterior e limpa mapping tardia', async (backend) => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const pending = deferred<ActivePortMappingSource>()
    if (backend === 'PCP') harness.createOutcomes.PCP.push(pending.promise)
    if (backend === 'NAT_PMP') {
      harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'))
      harness.createOutcomes.NAT_PMP.push(pending.promise)
    }
    if (backend === 'UPNP') {
      harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'))
      harness.createOutcomes.UPNP.push(pending.promise)
    }
    const abort = new AbortController()
    const creation = createPreferredPortMapping(options(fixture.listener, harness, new FakeScheduler(), abort.signal))
    await flush()
    abort.abort()
    const late = mapping(fixture.listener)
    pending.resolve(late)
    await expect(creation).rejects.toThrow(expect.objectContaining({ code: 'PORT_MAPPING_ABORTED' }))
    expect(late.closeCalls).toBe(1)
    if (backend !== 'UPNP') expect(harness.createCalls.UPNP).toBe(0)
  })

  it('listener close durante tentativa cancela flow', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const pending = deferred<ActivePortMappingSource>()
    harness.createOutcomes.PCP.push(pending.promise)
    const creation = createPreferredPortMapping(options(fixture.listener, harness))
    await flush()
    await fixture.listener.close()
    const late = mapping(fixture.listener)
    pending.resolve(late)
    await expect(creation).rejects.toThrow(expect.objectContaining({ code: 'PORT_MAPPING_ABORTED' }))
    expect(harness.createCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 0 })
  })

  it('duas creations concorrentes no mesmo listener não criam duas mappings', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const pending = deferred<ActivePortMappingSource>()
    harness.createOutcomes.PCP.push(pending.promise)
    const first = createPreferredPortMapping(options(fixture.listener, harness))
    await expect(createPreferredPortMapping(options(fixture.listener, harness))).rejects.toThrow(
      expect.objectContaining({ code: 'PORT_MAPPING_OPERATION_IN_PROGRESS' })
    )
    pending.resolve(mapping(fixture.listener))
    const managed = await first
    await expect(createPreferredPortMapping(options(fixture.listener, harness))).rejects.toThrow(
      expect.objectContaining({ code: 'PORT_MAPPING_ALREADY_ACTIVE' })
    )
    expect(harness.createCalls.PCP).toBe(1)
    await managed.close()
  })

  it('listeners diferentes possuem registries independentes', async () => {
    const firstFixture = await createFixture()
    const secondFixture = await createFixture()
    const firstHarness = new AdapterHarness()
    const secondHarness = new AdapterHarness()
    firstHarness.createOutcomes.PCP.push(mapping(firstFixture.listener))
    secondHarness.createOutcomes.PCP.push(mapping(secondFixture.listener, '9.9.9.9', 56000))
    const [first, second] = await Promise.all([
      createPreferredPortMapping(options(firstFixture.listener, firstHarness)),
      createPreferredPortMapping(options(secondFixture.listener, secondHarness))
    ])
    expect(first.isActive()).toBe(true)
    expect(second.isActive()).toBe(true)
    await Promise.all([first.close(), second.close()])
  })
})

describe('ManagedPortMapping descriptor, renewal e migration', () => {
  it('mapping managed legítima assina PORT_MAPPED_TCP e fake wrapper não assina', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const descriptor = verifySignedConnectivityDescriptor({
      encodedDescriptor: createSignedConnectivityDescriptor({
        serverId: fixture.server.serverId,
        serverPublicKey: fixture.server.identity.publicKey,
        serverPrivateKey: fixture.privateKey,
        candidates: [managed]
      })
    })
    expect(descriptor.candidates).toEqual([{ candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP, family: 4, address: '8.8.4.4', port: 55000 }])
    expect(() => createSignedConnectivityDescriptor({
      serverId: fixture.server.serverId,
      serverPublicKey: fixture.server.identity.publicKey,
      serverPrivateKey: fixture.privateKey,
      candidates: [{ isActive: () => true } as never]
    })).toThrow()
    await managed.close()
  })

  it('backend raw e Managed wrapper com mesmo endpoint produzem wire idêntico', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const issuedAt = Math.floor(Date.now() / 1000)
    const descriptorId = Buffer.alloc(32, 0x75)
    const wire = (candidate: ActivePortMappingSource): Buffer => createSignedConnectivityDescriptor({
      serverId: fixture.server.serverId,
      serverPublicKey: fixture.server.identity.publicKey,
      serverPrivateKey: fixture.privateKey,
      candidates: [candidate],
      lifetimeSeconds: 60,
      customIssuedAt: issuedAt,
      customDescriptorId: descriptorId
    })
    expect(wire(managed).equals(wire(backend))).toBe(true)
    for (const forbidden of ['PCP', 'NAT_PMP', 'UPNP']) expect(wire(managed).includes(Buffer.from(forbidden))).toBe(false)
    await managed.close()
  })

  it.each(['PCP', 'NAT_PMP', 'UPNP'] as const)('%s backend invalidada torna manager inativa e signer rejeita', async (selected) => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    if (selected === 'PCP') harness.createOutcomes.PCP.push(backend)
    if (selected === 'NAT_PMP') {
      harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'))
      harness.createOutcomes.NAT_PMP.push(backend)
    }
    if (selected === 'UPNP') {
      harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'))
      harness.createOutcomes.UPNP.push(backend)
    }
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    backend.invalidate()
    expect(managed.isActive()).toBe(false)
    expect(() => createSignedConnectivityDescriptor({
      serverId: fixture.server.serverId,
      serverPublicKey: fixture.server.identity.publicKey,
      serverPrivateKey: fixture.privateKey,
      candidates: [managed]
    })).toThrow()
    await managed.close()
  })

  it('NAT-PMP renewal reproba PCP e migra atomicamente para PCP', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener, '8.8.4.4', 55000)
    const upgraded = mapping(fixture.listener, '9.9.9.9', 56000)
    harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'), upgraded)
    harness.createOutcomes.NAT_PMP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    expect(managed.getBackendForTesting()).toBe('PCP')
    expect(managed.getExternalEndpoint()).toEqual({ family: 4, address: '9.9.9.9', port: 56000 })
    expect(old.closeCalls).toBe(1)
    await managed.close()
  })

  it.each([
    { label: 'unsupported', probeFailure: new PcpError('PCP_UNSUPPORTED_VERSION') },
    { label: 'timeout', probeFailure: new PcpError('PCP_TIMEOUT') }
  ] as const)('NAT-PMP renewal com PCP $label renova NAT-PMP atual', async ({ probeFailure }) => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(new PcpError('PCP_UNSUPPORTED_VERSION'), probeFailure)
    harness.createOutcomes.NAT_PMP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    expect(managed.getBackendForTesting()).toBe('NAT_PMP')
    expect(harness.renewCalls.NAT_PMP).toBe(1)
    expect(managed.isActive()).toBe(true)
    await managed.close()
  })

  it('UPnP renewal migra diretamente para PCP quando disponível', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    const upgraded = mapping(fixture.listener, '9.9.9.9', 56000)
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'), upgraded)
    harness.createOutcomes.UPNP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    expect(managed.getBackendForTesting()).toBe('PCP')
    expect(old.closeCalls).toBe(1)
    await managed.close()
  })

  it('UPnP renewal tenta NAT-PMP após PCP Unsupported e migra', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    const nat = mapping(fixture.listener, '9.9.9.9', 56000)
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'), new PcpError('PCP_UNSUPPORTED_VERSION'))
    harness.createOutcomes.UPNP.push(old)
    harness.createOutcomes.NAT_PMP.push(nat)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    expect(managed.getBackendForTesting()).toBe('NAT_PMP')
    expect(old.closeCalls).toBe(1)
    await managed.close()
  })

  it('UPnP renewal mantém/renova UPnP em PCP timeout ou NAT-PMP timeout', async () => {
    for (const mode of ['pcp-timeout', 'nat-timeout'] as const) {
      const fixture = await createFixture()
      const harness = new AdapterHarness()
      const old = mapping(fixture.listener)
      harness.createOutcomes.PCP.push(
        new PcpError('PCP_TIMEOUT'),
        mode === 'pcp-timeout' ? new PcpError('PCP_TIMEOUT') : new PcpError('PCP_UNSUPPORTED_VERSION')
      )
      harness.createOutcomes.UPNP.push(old)
      if (mode === 'nat-timeout') harness.createOutcomes.NAT_PMP.push(new NatPmpError('NAT_PMP_TIMEOUT'))
      const managed = await createPreferredPortMapping(options(fixture.listener, harness))
      await managed.executeRenewalForTesting()
      expect(managed.getBackendForTesting()).toBe('UPNP')
      expect(harness.renewCalls.UPNP).toBe(1)
      await managed.close()
    }
  })

  it.each([
    PcpResultCode.NOT_AUTHORIZED,
    PcpResultCode.NO_RESOURCES
  ])('denial PCP %s durante upgrade invalida e fecha fallback atual', async (resultCode) => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(
      new PcpError('PCP_TIMEOUT'),
      new PcpError('PCP_SERVER_ERROR', resultCode)
    )
    harness.createOutcomes.UPNP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    expect(managed.isActive()).toBe(false)
    expect(managed.getStateForTesting()).toBe('FAILED')
    expect(old.closeCalls).toBe(1)
  })

  it('migration mantém old current até new valid, depois switcha e descriptors são snapshots', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener, '8.8.4.4', 55000)
    const pending = deferred<ActivePortMappingSource>()
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'), pending.promise)
    harness.createOutcomes.UPNP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const before = verifySignedConnectivityDescriptor({
      encodedDescriptor: createSignedConnectivityDescriptor({
        serverId: fixture.server.serverId,
        serverPublicKey: fixture.server.identity.publicKey,
        serverPrivateKey: fixture.privateKey,
        candidates: [managed]
      })
    })
    const renewal = managed.executeRenewalForTesting()
    await flush()
    expect(managed.getStateForTesting()).toBe('MIGRATING')
    expect(managed.getExternalEndpoint().address).toBe('8.8.4.4')
    const upgraded = mapping(fixture.listener, '9.9.9.9', 56000)
    pending.resolve(upgraded)
    await renewal
    const after = verifySignedConnectivityDescriptor({
      encodedDescriptor: createSignedConnectivityDescriptor({
        serverId: fixture.server.serverId,
        serverPublicKey: fixture.server.identity.publicKey,
        serverPrivateKey: fixture.privateKey,
        candidates: [managed]
      })
    })
    expect(before.candidates[0]!.address).toBe('8.8.4.4')
    expect(after.candidates[0]!.address).toBe('9.9.9.9')
    expect(old.closeCalls).toBe(1)
    await managed.close()
  })

  it('falha de cleanup old não invalida nova mapping', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    old.closeFailure = true
    const upgraded = mapping(fixture.listener, '9.9.9.9', 56000)
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'), upgraded)
    harness.createOutcomes.UPNP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    expect(managed.isActive()).toBe(true)
    expect(managed.getBackendForTesting()).toBe('PCP')
    await managed.close()
  })

  it('endpoint current mutável é refletido sem expor dois candidates', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    backend.setEndpoint({ family: 4, address: '9.9.9.9', port: 56000 })
    expect(managed.getExternalEndpoint()).toEqual({ family: 4, address: '9.9.9.9', port: 56000 })
    const descriptor = verifySignedConnectivityDescriptor({
      encodedDescriptor: createSignedConnectivityDescriptor({
        serverId: fixture.server.serverId,
        serverPublicKey: fixture.server.identity.publicKey,
        serverPrivateKey: fixture.privateKey,
        candidates: [managed]
      })
    })
    expect(descriptor.candidates).toHaveLength(1)
    expect(descriptor.candidates[0]!.address).toBe('9.9.9.9')
    await managed.close()
  })
})

describe('ManagedPortMapping scheduler, close e persistence', () => {
  it('production adapter PCP desabilita auto-renew do backend no modo managed', async () => {
    const fixture = await createFixture()
    const gateway = await startFakePcpGateway()
    const scheduler = new FakeScheduler()
    const managed = await createPreferredPortMapping({
      listener: fixture.listener,
      requestedLifetimeSeconds: 300,
      timeoutMs: 50,
      maxRetransmissions: 1,
      testOnly: {
        gatewayProvider: { resolveGatewayForLocalAddress: async () => '127.0.0.1' },
        pcpNatPmpGatewayPort: gateway.port,
        scheduler: scheduler.scheduler,
        allowLoopback: true
      }
    })
    expect(managed.getBackendForTesting()).toBe('PCP')
    expect(gateway.requestCount()).toBe(1)
    expect(scheduler.tasks.size).toBe(1)
    vi.useFakeTimers()
    await vi.advanceTimersByTimeAsync(151_000)
    expect(gateway.requestCount()).toBe(1)
    vi.useRealTimers()
    await managed.close()
    expect(gateway.requestCount()).toBe(2)
  })

  it('manager possui exatamente um timer e close antes do renew cancela tudo', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const scheduler = new FakeScheduler()
    harness.createOutcomes.PCP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness, scheduler))
    expect(scheduler.tasks.size).toBe(1)
    await managed.close()
    expect(scheduler.tasks.size).toBe(0)
    expect(harness.renewCalls).toEqual({ PCP: 0, NAT_PMP: 0, UPNP: 0 })
    expect(managed.getStateForTesting()).toBe('CLOSED')
  })

  it('timer do manager é a única authority e reagenda exatamente uma vez', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const scheduler = new FakeScheduler()
    harness.createOutcomes.PCP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness, scheduler))
    expect(scheduler.tasks.size).toBe(1)
    scheduler.runNext()
    await flush()
    expect(harness.renewCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 0 })
    expect(scheduler.tasks.size).toBe(1)
    await managed.close()
  })

  it('close durante renewal atual aguarda operação e fecha backend uma vez', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    const pendingRenewal = deferred<void>()
    harness.createOutcomes.PCP.push(backend)
    harness.renewOutcomes.PCP.push(pendingRenewal.promise)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const renewal = managed.executeRenewalForTesting()
    await flush()
    const closing = managed.close()
    expect(managed.isActive()).toBe(false)
    pendingRenewal.resolve()
    await Promise.all([renewal, closing])
    expect(backend.closeCalls).toBe(1)
    expect(managed.getStateForTesting()).toBe('CLOSED')
  })

  it('descriptor expiry é clampado pela lease curta do backend managed', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener, '8.8.4.4', 55000, 30)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const issuedAt = Math.floor(Date.now() / 1000)
    const descriptor = verifySignedConnectivityDescriptor({
      encodedDescriptor: createSignedConnectivityDescriptor({
        serverId: fixture.server.serverId,
        serverPublicKey: fixture.server.identity.publicKey,
        serverPrivateKey: fixture.privateKey,
        candidates: [managed],
        customIssuedAt: issuedAt,
        lifetimeSeconds: 300
      })
    })
    expect(descriptor.expiresAt).toBeLessThanOrEqual(backend.getExpiresAt())
    expect(descriptor.expiresAt - descriptor.issuedAt).toBeLessThanOrEqual(30)
    await managed.close()
  })

  it('deadline monotônica do manager invalida mesmo se backend ainda se declarar ativo', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    let monotonic = 1000
    harness.createOutcomes.PCP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping({
      ...options(fixture.listener, harness),
      monotonicClock: () => monotonic
    })
    monotonic += 301
    expect(managed.isActive()).toBe(false)
    expect(managed.getStateForTesting()).toBe('FAILED')
    await managed.close()
  })

  it('close durante migration limpa old e mapping nova tardia', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    const pending = deferred<ActivePortMappingSource>()
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'), pending.promise)
    harness.createOutcomes.UPNP.push(old)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const renewal = managed.executeRenewalForTesting()
    await flush()
    const closing = managed.close()
    const late = mapping(fixture.listener, '9.9.9.9', 56000)
    pending.resolve(late)
    await Promise.all([renewal, closing])
    expect(old.closeCalls).toBeGreaterThanOrEqual(1)
    expect(late.closeCalls).toBe(1)
    expect(managed.getStateForTesting()).toBe('CLOSED')
  })

  it('listener close cascade invalida manager e backend', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await fixture.listener.close()
    await flush()
    expect(managed.isActive()).toBe(false)
    expect(backend.closeCalls).toBe(1)
  })

  it('connectivity shutdown cancela renewal e fecha mapping gerenciada', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const scheduler = new FakeScheduler()
    const subsystem = new ConnectivitySubsystem()
    const backend = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping({
      ...options(fixture.listener, harness, scheduler),
      subsystem
    })
    expect(scheduler.tasks.size).toBe(1)
    await subsystem.shutdown()
    expect(managed.getStateForTesting()).toBe('CLOSED')
    expect(backend.closeCalls).toBe(1)
    expect(scheduler.tasks.size).toBe(0)
  })

  it('close é idempotente e registry só libera depois do cleanup', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await Promise.all([managed.close(), managed.close(), managed.close()])
    expect(backend.closeCalls).toBe(1)

    const restartedHarness = new AdapterHarness()
    restartedHarness.createOutcomes.PCP.push(mapping(fixture.listener, '9.9.9.9', 56000))
    const restarted = await createPreferredPortMapping(options(fixture.listener, restartedHarness))
    expect(restartedHarness.createCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 0 })
    await restarted.close()
  })

  it('registry rejeita nova creation enquanto close cleanup ainda está em voo', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const backend = mapping(fixture.listener)
    const closeGate = deferred<void>()
    backend.closeGate = closeGate.promise
    harness.createOutcomes.PCP.push(backend)
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    const closing = managed.close()
    await flush()
    const concurrent = new AdapterHarness()
    await expect(createPreferredPortMapping(options(fixture.listener, concurrent))).rejects.toThrow(
      expect.objectContaining({ code: 'PORT_MAPPING_OPERATION_IN_PROGRESS' })
    )
    closeGate.resolve()
    await closing
  })

  it('create/renew/migrate/close não persiste strategy state nem altera arquivos', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    const old = mapping(fixture.listener)
    const upgraded = mapping(fixture.listener, '9.9.9.9', 56000)
    harness.createOutcomes.PCP.push(new PcpError('PCP_TIMEOUT'), upgraded)
    harness.createOutcomes.UPNP.push(old)
    const before = (await readdir(fixture.root, { recursive: true })).sort()
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.executeRenewalForTesting()
    await managed.close()
    const after = (await readdir(fixture.root, { recursive: true })).sort()
    expect(after).toEqual(before)
  })

  it('sequências após CLOSED e erros forjados nunca reativam ou fazem fallback', async () => {
    const fixture = await createFixture()
    const harness = new AdapterHarness()
    harness.createOutcomes.PCP.push(mapping(fixture.listener))
    const managed = await createPreferredPortMapping(options(fixture.listener, harness))
    await managed.close()
    await managed.executeRenewalForTesting()
    expect(managed.getStateForTesting()).toBe('CLOSED')
    expect(managed.isActive()).toBe(false)

    const unknownHarness = new AdapterHarness()
    unknownHarness.createOutcomes.PCP.push(Object.assign(new Error('PCP_TIMEOUT'), { code: 'PCP_TIMEOUT' }))
    await expect(createPreferredPortMapping(options(fixture.listener, unknownHarness))).rejects.toThrow(
      expect.objectContaining({ code: 'PORT_MAPPING_INTERNAL_FAILURE' })
    )
    expect(unknownHarness.createCalls).toEqual({ PCP: 1, NAT_PMP: 0, UPNP: 0 })
  })
})
