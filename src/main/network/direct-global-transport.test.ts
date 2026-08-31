import { createHash, generateKeyPairSync } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { type ListenOptions, type Server } from 'node:net'
import { type NetworkInterfaceInfo } from 'node:os'

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor
} from './connectivity-descriptor'
import {
  ActiveDirectGlobalListener,
  directGlobalTransportTestOnly,
  isLegitimateActiveDirectGlobalListener,
  type StartDirectGlobalTcpServerOptions
} from './direct-global-transport'
import {
  classifyNetworkAddress,
  listEligibleDirectGlobalIpv6Addresses,
  type NetworkInterfaceProvider
} from './network-interfaces'
import { type ServerTcpPeerConnection } from './tcp-transport'

const GLOBAL_A = '2600::1'
const GLOBAL_A_EXPANDED = '2600:0000:0000:0000:0000:0000:0000:0001'
const GLOBAL_B = '2600::2'
const activeListeners: ActiveDirectGlobalListener[] = []

afterEach(async () => {
  vi.useRealTimers()
  await Promise.all(activeListeners.splice(0).map((listener) => listener.close()))
})

class FakeDirectGlobalServer extends EventEmitter {
  listening = false
  closeCalls = 0
  readonly port: number
  listenOptions: ListenOptions | null = null
  completeListen = true
  reportedAddressOverride: string | null = null

  constructor(port = 43210) {
    super()
    this.port = port
  }

  listen(options: ListenOptions, callback?: () => void): this {
    this.listenOptions = options
    this.listening = true
    if (this.completeListen) queueMicrotask(() => callback?.())
    return this
  }

  address() {
    if (!this.listening || !this.listenOptions) return null
    return {
      address: this.reportedAddressOverride ?? String(this.listenOptions.host),
      family: 'IPv6',
      port: this.port
    }
  }

  close(callback?: (error?: Error) => void): this {
    this.closeCalls += 1
    this.listening = false
    queueMicrotask(() => callback?.())
    return this
  }

  asServer(): Server {
    return this as unknown as Server
  }
}

function interfaceEntry(
  address: string,
  options: { internal?: boolean; name?: string } = {}
): ReturnType<NetworkInterfaceProvider> {
  return {
    [options.name ?? 'wan0']: [
      {
        address,
        family: 'IPv6',
        internal: options.internal ?? false,
        cidr: `${address}/64`,
        netmask: 'ffff:ffff:ffff:ffff::',
        mac: '00:00:00:00:00:01',
        scopeid: 0
      } as NetworkInterfaceInfo
    ]
  }
}

function providerFor(address = GLOBAL_A): NetworkInterfaceProvider {
  return () => interfaceEntry(address)
}

function identityFixture() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    serverId: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

function baseOptions(overrides: Partial<StartDirectGlobalTcpServerOptions> = {}): StartDirectGlobalTcpServerOptions {
  const identity = identityFixture()
  return {
    localAddress: GLOBAL_A,
    port: 0,
    storage: {} as StartDirectGlobalTcpServerOptions['storage'],
    localStorageId: '0'.repeat(32),
    serverId: identity.serverId,
    serverPublicKey: identity.publicKey,
    serverPrivateKey: identity.privateKey,
    ...overrides
  }
}

async function startFake(
  options: Partial<StartDirectGlobalTcpServerOptions> = {},
  provider: NetworkInterfaceProvider = providerFor(),
  server = new FakeDirectGlobalServer()
) {
  const listener = await directGlobalTransportTestOnly.start(baseOptions(options), {
    interfaceProvider: provider,
    serverFactory: () => server.asServer()
  })
  activeListeners.push(listener)
  return { listener, server }
}

describe('Direct Global IPv6: classificação, seleção e bind exato', () => {
  it('aceita fixture IPv6 global sem executar I/O externo', () => {
    expect(classifyNetworkAddress(GLOBAL_A)).toMatchObject({
      family: 'IPv6', scope: 'GLOBAL', isGloballyRoutableWan: true, normalizedAddress: GLOBAL_A
    })
  })

  it.each([
    '::', '::1', 'fc00::1', 'fd00::1', 'fe80::1', 'fec0::1', 'ff02::1',
    '2001:db8::1', '2001:2::1', '2001:10::1', '2001:20::1', '2002::1'
  ])('rejeita scope IPv6 não global antes de criar server: %s', async (address) => {
    const factory = vi.fn(() => new FakeDirectGlobalServer().asServer())
    await expect(directGlobalTransportTestOnly.start(baseOptions({ localAddress: address }), {
      interfaceProvider: providerFor(address), serverFactory: factory
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_ADDRESS_NOT_GLOBAL' })
    expect(factory).not.toHaveBeenCalled()
  })

  it.each(['8.8.8.8', '::ffff:8.8.8.8', 'fe80::1%12', '2600::1%eth0', 'host.example', ' 2600::1', '2600::1\n'])(
    'rejeita IPv4, mapped, zone, hostname e whitespace: %s', async (address) => {
    await expect(directGlobalTransportTestOnly.start(baseOptions({ localAddress: address }), {
      interfaceProvider: providerFor()
    })).rejects.toBeInstanceOf(Error)
    }
  )

  it('rejeita entrada enorme/Unicode/control chars de forma bounded', async () => {
    for (const address of ['a'.repeat(10_000), '2600::💥', '2600::1\u0000']) {
      await expect(directGlobalTransportTestOnly.start(baseOptions({ localAddress: address }), {
        interfaceProvider: providerFor()
      })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_ADDRESS_INVALID' })
    }
  })

  it('exige atribuição local atual e rejeita interface internal', async () => {
    await expect(directGlobalTransportTestOnly.start(baseOptions(), {
      interfaceProvider: () => ({}), serverFactory: () => new FakeDirectGlobalServer().asServer()
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_ADDRESS_NOT_LOCAL' })

    await expect(directGlobalTransportTestOnly.start(baseOptions(), {
      interfaceProvider: () => interfaceEntry(GLOBAL_A, { internal: true }),
      serverFactory: () => new FakeDirectGlobalServer().asServer()
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_ADDRESS_NOT_LOCAL' })
  })

  it('canonicaliza formas equivalentes e faz bind exato com ipv6Only true e sem reusePort', async () => {
    const { listener, server } = await startFake({ localAddress: GLOBAL_A_EXPANDED })
    expect(server.listenOptions).toEqual({ host: GLOBAL_A, port: 0, ipv6Only: true })
    expect(server.listenOptions).not.toHaveProperty('reusePort')
    expect(listener.getBoundEndpoint()).toEqual({ family: 6, address: GLOBAL_A, port: 43210 })
  })

  it.each([-1, 65536, 1.5, Number.NaN])('rejeita porta inválida: %s', async (port) => {
    await expect(directGlobalTransportTestOnly.start(baseOptions({ port }), {
      interfaceProvider: providerFor(), serverFactory: () => new FakeDirectGlobalServer().asServer()
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_PORT_INVALID' })
  })

  it('port 0 anuncia somente a porta real retornada pelo server', async () => {
    const { listener } = await startFake({ port: 0 }, providerFor(), new FakeDirectGlobalServer(49152))
    expect(listener.getBoundEndpoint().port).toBe(49152)
  })

  it('não seleciona automaticamente entre vários IPv6 globais', async () => {
    const provider = () => ({ ...interfaceEntry(GLOBAL_A, { name: 'wanA' }), ...interfaceEntry(GLOBAL_B, { name: 'wanB' }) })
    const { listener, server } = await startFake({ localAddress: GLOBAL_B }, provider)
    expect(server.listenOptions?.host).toBe(GLOBAL_B)
    expect(listener.getBoundEndpoint().address).toBe(GLOBAL_B)
  })

  it('enumeração é snapshot sem side effects, deduplica e omite ambiguidade cross-interface', () => {
    const sameInterfaceDuplicate = () => ({
      wan0: [...(interfaceEntry(GLOBAL_A).wan0 ?? []), ...(interfaceEntry(GLOBAL_A).wan0 ?? [])]
    })
    expect(listEligibleDirectGlobalIpv6Addresses(sameInterfaceDuplicate)).toEqual([
      { address: GLOBAL_A, interfaceName: 'wan0' }
    ])

    const ambiguous = () => ({ ...interfaceEntry(GLOBAL_A, { name: 'wan0' }), ...interfaceEntry(GLOBAL_A, { name: 'wan1' }) })
    expect(listEligibleDirectGlobalIpv6Addresses(ambiguous)).toEqual([])

    const contradictory = () => ({
      wan0: [
        ...(interfaceEntry(GLOBAL_A).wan0 ?? []),
        ...(interfaceEntry(GLOBAL_A, { internal: true }).wan0 ?? [])
      ]
    })
    expect(listEligibleDirectGlobalIpv6Addresses(contradictory)).toEqual([])
  })

  it('bind failure é controlada e nunca tenta outro endereço/porta', async () => {
    const server = new FakeDirectGlobalServer()
    server.listen = function (options: ListenOptions): FakeDirectGlobalServer {
      this.listenOptions = options
      queueMicrotask(() => this.emit('error', Object.assign(new Error('unavailable'), { code: 'EADDRNOTAVAIL' })))
      return this
    }
    await expect(directGlobalTransportTestOnly.start(baseOptions({ port: 45678 }), {
      interfaceProvider: providerFor(), serverFactory: () => server.asServer()
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_BIND_FAILED' })
    expect(server.listenOptions).toEqual({ host: GLOBAL_A, port: 45678, ipv6Only: true })
  })

  it('rejeita fallback/wildcard reportado pelo server após bind', async () => {
    const server = new FakeDirectGlobalServer()
    server.reportedAddressOverride = '::'
    await expect(directGlobalTransportTestOnly.start(baseOptions(), {
      interfaceProvider: providerFor(), serverFactory: () => server.asServer()
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_BIND_FAILED' })
    expect(server.closeCalls).toBe(1)
  })
})

describe('Direct Global IPv6: capability e lifecycle', () => {
  it('revalida depois do listen e fecha se o endereço desaparecer', async () => {
    let calls = 0
    const provider = () => (++calls === 1 ? interfaceEntry(GLOBAL_A) : {})
    const server = new FakeDirectGlobalServer()
    await expect(directGlobalTransportTestOnly.start(baseOptions(), {
      interfaceProvider: provider, serverFactory: () => server.asServer()
    })).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_ADDRESS_LOST' })
    expect(server.closeCalls).toBe(1)
  })

  it('produz capability legítima e rejeita constructor sem token', async () => {
    const { listener, server } = await startFake()
    expect(isLegitimateActiveDirectGlobalListener(listener)).toBe(true)
    expect(listener.isActive()).toBe(true)
    expect(() => new ActiveDirectGlobalListener(
      Symbol('fake'), server.asServer(), GLOBAL_A, providerFor(),
      new Set<ServerTcpPeerConnection>(), new Map<string, number>()
    )).toThrowError(expect.objectContaining({ code: 'DIRECT_GLOBAL_CAPABILITY_INVALID' }))
  })

  it('address removal invalida terminalmente e não reativa quando retorna', async () => {
    let assigned = true
    const provider = () => assigned ? interfaceEntry(GLOBAL_A) : {}
    const { listener, server } = await startFake({}, provider)
    assigned = false
    expect(listener.isActive()).toBe(false)
    expect(listener.getState()).toBe('INVALIDATED')
    assigned = true
    expect(listener.isActive()).toBe(false)
    await vi.waitFor(() => expect(server.closeCalls).toBe(1))
  })

  it('mudança A para B invalida A sem migrar ou executar novo bind', async () => {
    let snapshot = interfaceEntry(GLOBAL_A)
    const provider = () => snapshot
    const { listener, server } = await startFake({}, provider)
    snapshot = interfaceEntry(GLOBAL_B)
    expect(listener.isActive()).toBe(false)
    expect(server.listenOptions?.host).toBe(GLOBAL_A)
  })

  it('close é imediatamente inativo e idempotente', async () => {
    const { listener, server } = await startFake()
    const first = listener.close()
    expect(listener.isActive()).toBe(false)
    await first
    await listener.close()
    expect(listener.getState()).toBe('CLOSED')
    expect(server.closeCalls).toBe(1)
  })

  it('abort durante opening fecha o server e não entrega capability', async () => {
    const controller = new AbortController()
    const server = new FakeDirectGlobalServer()
    server.completeListen = false
    const pending = directGlobalTransportTestOnly.start(baseOptions({ signal: controller.signal }), {
      interfaceProvider: providerFor(), serverFactory: () => server.asServer()
    })
    controller.abort()
    await expect(pending).rejects.toMatchObject({ code: 'DIRECT_GLOBAL_ABORTED' })
    expect(server.closeCalls).toBeGreaterThanOrEqual(1)
  })

  it('abort depois da capability entregue não fecha o listener', async () => {
    const controller = new AbortController()
    const { listener } = await startFake({ signal: controller.signal })
    controller.abort()
    expect(listener.isActive()).toBe(true)
  })
})

describe('Direct Global IPv6: Connectivity Descriptor production', () => {
  it('rejeita object literal/cast e raw DIRECT_GLOBAL no signer production', async () => {
    const identity = identityFixture()
    const fake = {
      isActive: () => true,
      getBoundEndpoint: () => ({ family: 6, address: GLOBAL_A, port: 43210 })
    } as unknown as ActiveDirectGlobalListener

    for (const candidate of [fake, {
      candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
      family: 6 as const,
      address: GLOBAL_A,
      port: 43210
    }]) {
      expect(() => createSignedConnectivityDescriptor({
        serverId: identity.serverId,
        serverPublicKey: identity.publicKey,
        serverPrivateKey: identity.privateKey,
        candidates: [candidate]
      })).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    }
  })

  it('capability legítima produz DIRECT_GLOBAL_TCP v1 byte-exact e sem metadata de interface', async () => {
    const identity = identityFixture()
    const { listener } = await startFake({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey
    })
    const encoded = createSignedConnectivityDescriptor({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey,
      candidates: [listener]
    })
    const verified = verifySignedConnectivityDescriptor({ encodedDescriptor: encoded })
    expect(verified.version).toBe(1)
    expect(verified.candidates).toEqual([{
      candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
      family: 6,
      address: GLOBAL_A,
      port: 43210
    }])
    const addressBytes = Buffer.from(GLOBAL_A)
    const offset = encoded.indexOf(addressBytes)
    expect([...encoded.subarray(offset - 3, offset)]).toEqual([0x03, 0x06, addressBytes.length])
    expect(encoded.readUInt8(offset + addressBytes.length + 2)).toBe(0)
    expect(encoded.includes(Buffer.from('wan0'))).toBe(false)
  })

  it('tampering de IPv6, porta ou candidateType invalida descriptor', async () => {
    const identity = identityFixture()
    const { listener } = await startFake({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey
    })
    const encoded = createSignedConnectivityDescriptor({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey,
      candidates: [listener]
    })
    const addrOffset = encoded.indexOf(Buffer.from(GLOBAL_A))
    const mutations = [addrOffset, addrOffset + GLOBAL_A.length, addrOffset - 3]
    for (const index of mutations) {
      const tampered = Buffer.from(encoded)
      tampered[index] = (tampered[index] ?? 0) ^ 1
      expect(() => verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })).toThrow()
    }
  })

  it('address removal ou listener close impedem novo descriptor; snapshot anterior permanece verificável', async () => {
    const identity = identityFixture()
    let assigned = true
    const provider = () => assigned ? interfaceEntry(GLOBAL_A) : {}
    const { listener } = await startFake({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey
    }, provider)
    const sign = () => createSignedConnectivityDescriptor({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey,
      candidates: [listener]
    })
    const snapshot = sign()
    assigned = false
    expect(() => sign()).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_HANDLE_CLOSED' }))
    expect(verifySignedConnectivityDescriptor({ encodedDescriptor: snapshot }).candidates).toHaveLength(1)
    await listener.close()
    expect(() => sign()).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
  })
})
