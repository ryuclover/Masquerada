import { createHash, generateKeyPairSync } from 'node:crypto'
import { createSocket as createDgramSocket, type RemoteInfo, type Socket as DgramSocket, type SocketType } from 'node:dgram'
import { EventEmitter } from 'node:events'
import { type ListenOptions, type Server } from 'node:net'
import { type NetworkInterfaceInfo } from 'node:os'

import { afterEach, describe, expect, it, vi } from 'vitest'

import { ActivePortMappingSource } from './active-port-mapping'
import {
  createSignedConnectivityDescriptor,
  type ConnectivityCandidate
} from './connectivity-descriptor'
import {
  type ActiveDirectGlobalListener,
  directGlobalTransportTestOnly
} from './direct-global-transport'
import { type DirectTcpEndpoint } from './lan-transport'
import {
  compareStunObservationToDirectGlobalListener,
  compareStunObservationToPortMapping,
  isLegitimateValidatedStunObservation,
  observeStunBinding,
  STUN_OBSERVATION_MAX_AGE_SECONDS,
  stunObservationTestOnly,
  ValidatedStunObservation,
  type ObserveStunBindingOptions
} from './stun-observation'
import {
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
  STUN_BINDING_ERROR_RESPONSE,
  STUN_BINDING_SUCCESS_RESPONSE,
  STUN_HEADER_BYTES,
  STUN_MAGIC_COOKIE
} from './stun-protocol'
import { ConnectivitySubsystem } from './connectivity-subsystem'
import { ConnectivityResourceGovernor, MAX_PENDING_UDP_OPERATIONS } from './connectivity-resource-governor'

const LOCAL_V4 = '192.168.1.20'
const LOCAL_V6 = '2600::20'
const TARGET_V4 = '203.0.114.50'
const TARGET_V6 = '2600::50'
const activeDirect: ActiveDirectGlobalListener[] = []
const realSockets: DgramSocket[] = []

afterEach(async () => {
  vi.useRealTimers()
  await Promise.all(activeDirect.splice(0).map((listener) => listener.close()))
  for (const socket of realSockets.splice(0)) {
    try { socket.close() } catch { /* already closed */ }
  }
})

function interfaceProvider(address: string, internal = false) {
  const family = address.includes(':') ? 'IPv6' : 'IPv4'
  return () => ({
    net0: [{
      address,
      family,
      internal,
      cidr: `${address}/${family === 'IPv6' ? 64 : 24}`,
      netmask: family === 'IPv6' ? 'ffff:ffff:ffff:ffff::' : '255.255.255.0',
      mac: '00:00:00:00:00:01',
      scopeid: 0
    } as NetworkInterfaceInfo]
  })
}

class FakeDgramSocket extends EventEmitter {
  bindOptions: { address?: string; port?: number; exclusive?: boolean } | null = null
  readonly sends: Array<{ message: Buffer; port: number; address: string }> = []
  closed = false
  boundPort = 40001

  bind(options: { address?: string; port?: number; exclusive?: boolean }): this {
    this.bindOptions = options
    queueMicrotask(() => this.emit('listening'))
    return this
  }

  address() {
    return {
      address: this.bindOptions?.address ?? '0.0.0.0',
      family: (this.bindOptions?.address ?? '').includes(':') ? 'IPv6' : 'IPv4',
      port: this.boundPort
    }
  }

  send(message: Buffer, port: number, address: string, callback?: (error: Error | null, bytes: number) => void): void {
    this.sends.push({ message: Buffer.from(message), port, address })
    queueMicrotask(() => callback?.(null, message.length))
  }

  close(): this {
    if (!this.closed) {
      this.closed = true
      queueMicrotask(() => this.emit('close'))
    }
    return this
  }

  asSocket(): DgramSocket {
    return this as unknown as DgramSocket
  }
}

function encodedAttribute(type: number, value: Buffer): Buffer {
  const padded = (value.length + 3) & ~3
  const result = Buffer.alloc(4 + padded)
  result.writeUInt16BE(type, 0)
  result.writeUInt16BE(value.length, 2)
  value.copy(result, 4)
  return result
}

function successIpv4(transactionId: Buffer, address = '203.0.114.9', port = 55000): Buffer {
  const value = Buffer.alloc(8)
  value[1] = 1
  value.writeUInt16BE(port ^ (STUN_MAGIC_COOKIE >>> 16), 2)
  const cookie = Buffer.alloc(4)
  cookie.writeUInt32BE(STUN_MAGIC_COOKIE)
  address.split('.').map(Number).forEach((octet, index) => { value[index + 4] = octet ^ cookie[index]! })
  return stunResponse(transactionId, STUN_BINDING_SUCCESS_RESPONSE, [
    encodedAttribute(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, value)
  ])
}

function successIpv6(transactionId: Buffer, words: readonly number[], port = 55000): Buffer {
  const address = Buffer.alloc(16)
  words.forEach((word, index) => address.writeUInt16BE(word, index * 2))
  const mask = Buffer.alloc(16)
  mask.writeUInt32BE(STUN_MAGIC_COOKIE)
  transactionId.copy(mask, 4)
  const value = Buffer.alloc(20)
  value[1] = 2
  value.writeUInt16BE(port ^ (STUN_MAGIC_COOKIE >>> 16), 2)
  for (let index = 0; index < 16; index += 1) value[index + 4] = address[index]! ^ mask[index]!
  return stunResponse(transactionId, STUN_BINDING_SUCCESS_RESPONSE, [
    encodedAttribute(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, value)
  ])
}

function stunResponse(transactionId: Buffer, type: number, attributes: readonly Buffer[]): Buffer {
  const body = Buffer.concat(attributes)
  const result = Buffer.alloc(STUN_HEADER_BYTES + body.length)
  result.writeUInt16BE(type, 0)
  result.writeUInt16BE(body.length, 2)
  result.writeUInt32BE(STUN_MAGIC_COOKIE, 4)
  transactionId.copy(result, 8)
  body.copy(result, STUN_HEADER_BYTES)
  return result
}

function rinfo(address: string, port: number): RemoteInfo {
  return { address, port, family: address.includes(':') ? 'IPv6' : 'IPv4', size: 0 }
}

function testOptions(overrides: Partial<ObserveStunBindingOptions> = {}): ObserveStunBindingOptions {
  return {
    localAddress: LOCAL_V4,
    server: { address: TARGET_V4, port: 3478 },
    timeoutMs: 1000,
    ...overrides
  }
}

async function waitForSend(socket: FakeDgramSocket): Promise<Buffer> {
  await vi.waitFor(() => expect(socket.sends).toHaveLength(1))
  return socket.sends[0]!.message
}

describe('STUN observation: target, bind, source e transaction', () => {
  it('rejeita hostname/whitespace/zone target antes de socket ou DNS', async () => {
    const factory = vi.fn(() => new FakeDgramSocket().asSocket())
    for (const address of ['stun.example.com', ' 203.0.114.50', '2600::50%1', 'x'.repeat(1000)]) {
      await expect(stunObservationTestOnly.observe(testOptions({ server: { address } }), {
        interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: factory
      })).rejects.toMatchObject({ code: 'STUN_TARGET_INVALID' })
    }
    expect(factory).not.toHaveBeenCalled()
  })

  it.each([0, -1, 65536, 1.5, Number.NaN])('rejeita target port inválida: %s', async (port) => {
    await expect(stunObservationTestOnly.observe(testOptions({ server: { address: TARGET_V4, port } }), {
      interfaceProvider: interfaceProvider(LOCAL_V4)
    })).rejects.toMatchObject({ code: 'STUN_TARGET_INVALID' })
  })

  it('usa somente o default explícito 3478 quando port é omitida', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions({ server: { address: TARGET_V4 } }), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 0x33)
    })
    const request = await waitForSend(socket)
    expect(socket.sends[0]).toMatchObject({ address: TARGET_V4, port: 3478 })
    socket.emit('message', successIpv4(request.subarray(8, 20)), rinfo(TARGET_V4, 3478))
    await pending
  })

  it('rejeita local wildcard, loopback production, família diferente e address não atribuído', async () => {
    for (const localAddress of ['0.0.0.0', '127.0.0.1', '::', LOCAL_V6]) {
      await expect(stunObservationTestOnly.observe(testOptions({ localAddress }), {
        interfaceProvider: interfaceProvider(localAddress)
      })).rejects.toMatchObject({ code: 'STUN_LOCAL_ADDRESS_INVALID' })
    }
    await expect(stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: () => ({})
    })).rejects.toMatchObject({ code: 'STUN_LOCAL_ADDRESS_NOT_ASSIGNED' })
  })

  it('faz bind exact no localAddress com porta efêmera e nunca wildcard', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: interfaceProvider(LOCAL_V4),
      socketFactory: (type: SocketType) => {
        expect(type).toBe('udp4')
        return socket.asSocket()
      },
      randomProvider: () => Buffer.alloc(12, 1)
    })
    const request = await waitForSend(socket)
    expect(socket.bindOptions).toEqual({ address: LOCAL_V4, port: 0, exclusive: true })
    socket.emit('message', successIpv4(request.subarray(8, 20)), rinfo(TARGET_V4, 3478))
    const observation = await pending
    expect(observation.localPort).toBe(40001)
  })

  it('revalida atribuição depois do bind e fecha se endereço desapareceu', async () => {
    let calls = 0
    const socket = new FakeDgramSocket()
    await expect(stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: () => (++calls === 1 ? interfaceProvider(LOCAL_V4)() : {}),
      socketFactory: () => socket.asSocket()
    })).rejects.toMatchObject({ code: 'STUN_LOCAL_ADDRESS_NOT_ASSIGNED' })
    expect(socket.closed).toBe(true)
    expect(socket.sends).toHaveLength(0)
  })

  it('aceita endpoints IPv4 e IPv6 literais canônicos', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions({
      localAddress: '2600:0:0:0:0:0:0:20',
      server: { address: '2600:0:0:0:0:0:0:50', port: 3478 }
    }), {
      interfaceProvider: interfaceProvider(LOCAL_V6),
      socketFactory: (type) => { expect(type).toBe('udp6'); return socket.asSocket() },
      randomProvider: () => Buffer.alloc(12, 2)
    })
    const request = await waitForSend(socket)
    expect(socket.bindOptions?.address).toBe(LOCAL_V6)
    expect(socket.sends[0]).toMatchObject({ address: TARGET_V6, port: 3478 })
    socket.emit('message', successIpv6(
      request.subarray(8, 20), [0x2600, 0, 0, 0, 0, 0, 0, 0x20]
    ), rinfo(TARGET_V6, 3478))
    await expect(pending).resolves.toMatchObject({ observedAddress: LOCAL_V6, family: 6 })
  })

  it('ignora source IP/port diferentes antes de aceitar response correlacionada', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 3)
    })
    const request = await waitForSend(socket)
    const valid = successIpv4(request.subarray(8, 20))
    socket.emit('message', valid, rinfo('203.0.114.51', 3478))
    socket.emit('message', valid, rinfo(TARGET_V4, 3479))
    expect(socket.closed).toBe(false)
    socket.emit('message', valid, rinfo(TARGET_V4, 3478))
    await expect(pending).resolves.toMatchObject({ observedAddress: '203.0.114.9' })
  })

  it('ignora transaction ID incorreta e aceita somente a current transaction', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 4)
    })
    const request = await waitForSend(socket)
    socket.emit('message', successIpv4(Buffer.alloc(12, 9)), rinfo(TARGET_V4, 3478))
    expect(socket.closed).toBe(false)
    socket.emit('message', successIpv4(request.subarray(8, 20)), rinfo(TARGET_V4, 3478))
    await expect(pending).resolves.toBeInstanceOf(Object)
  })
})

describe('STUN observation: retransmission, timeout e cleanup', () => {
  it('cada call usa novo ID do provider; retransmissions reutilizam bytes exatos', async () => {
    vi.useFakeTimers()
    let id = 0
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions({ timeoutMs: 40 }), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, ++id), initialRtoMs: 5, attempts: 4
    })
    const timedOut = expect(pending).rejects.toMatchObject({ code: 'STUN_TIMEOUT' })
    await vi.advanceTimersByTimeAsync(40)
    await timedOut
    expect(socket.sends).toHaveLength(4)
    for (const sent of socket.sends) expect(sent.message).toEqual(socket.sends[0]!.message)
    expect(socket.closed).toBe(true)

    const secondSocket = new FakeDgramSocket()
    const second = stunObservationTestOnly.observe(testOptions({ timeoutMs: 1 }), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => secondSocket.asSocket(),
      randomProvider: () => Buffer.alloc(12, ++id)
    })
    const secondTimedOut = expect(second).rejects.toMatchObject({ code: 'STUN_TIMEOUT' })
    await vi.advanceTimersByTimeAsync(1)
    await secondTimedOut
    expect(secondSocket.sends[0]!.message.subarray(8, 20)).not.toEqual(socket.sends[0]!.message.subarray(8, 20))
  })

  it('abort interrompe retransmission, fecha socket e não produz observation', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 5), initialRtoMs: 5
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(socket.sends).toHaveLength(1)
    controller.abort()
    // The signal must belong to the call; this first controller intentionally proves unrelated abort is inert.
    expect(socket.closed).toBe(false)
    const actualController = new AbortController()
    const actualSocket = new FakeDgramSocket()
    const actual = stunObservationTestOnly.observe(testOptions({ signal: actualController.signal }), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => actualSocket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 6), initialRtoMs: 5
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(actualSocket.sends).toHaveLength(1)
    const aborted = expect(actual).rejects.toMatchObject({ code: 'STUN_ABORTED' })
    actualController.abort()
    await aborted
    expect(actualSocket.closed).toBe(true)
    expect(actualSocket.sends).toHaveLength(1)
    socket.emit('message', successIpv4(socket.sends[0]!.message.subarray(8, 20)), rinfo(TARGET_V4, 3478))
    await pending
  })

  it('socket error é controlado sem unhandled EventEmitter error', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket()
    })
    await waitForSend(socket)
    socket.emit('error', new Error('synthetic'))
    await expect(pending).rejects.toMatchObject({ code: 'STUN_SOCKET_ERROR' })
    expect(socket.closed).toBe(true)
  })

  it('connectivity shutdown aborta STUN e impede retransmissions posteriores', async () => {
    vi.useFakeTimers()
    const subsystem = new ConnectivitySubsystem()
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions({ subsystem }), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 9), initialRtoMs: 5
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(socket.sends).toHaveLength(1)
    const aborted = expect(pending).rejects.toMatchObject({ code: 'STUN_ABORTED' })
    await subsystem.shutdown()
    await aborted
    await vi.advanceTimersByTimeAsync(100)
    expect(socket.sends).toHaveLength(1)
    expect(socket.closed).toBe(true)
  })

  it('global UDP cap rejeita antes de criar socket e libera capacidade', async () => {
    const governor = new ConnectivityResourceGovernor()
    const held = Array.from({ length: MAX_PENDING_UDP_OPERATIONS }, () => governor.reserve('UDP_OPERATION'))
    let sockets = 0
    await expect(stunObservationTestOnly.observe(testOptions({ resourceGovernor: governor }), {
      interfaceProvider: interfaceProvider(LOCAL_V4),
      socketFactory: () => { sockets += 1; return new FakeDgramSocket().asSocket() }
    })).rejects.toMatchObject({ code: 'CONNECTIVITY_RESOURCE_LIMIT' })
    expect(sockets).toBe(0)
    held[0]!.release()
    const pending = stunObservationTestOnly.observe(testOptions({ timeoutMs: 1, resourceGovernor: governor }), {
      interfaceProvider: interfaceProvider(LOCAL_V4),
      socketFactory: () => { sockets += 1; return new FakeDgramSocket().asSocket() }
    })
    await expect(pending).rejects.toMatchObject({ code: 'STUN_TIMEOUT' })
    expect(sockets).toBe(1)
    for (const reservation of held) reservation.release()
  })

  it('error response/auth não causa credential retry nem ALTERNATE-SERVER follow', async () => {
    const socket = new FakeDgramSocket()
    const pending = stunObservationTestOnly.observe(testOptions(), {
      interfaceProvider: interfaceProvider(LOCAL_V4), socketFactory: () => socket.asSocket(),
      randomProvider: () => Buffer.alloc(12, 7)
    })
    const request = await waitForSend(socket)
    const errorCode = Buffer.from([0, 0, 4, 1])
    socket.emit('message', stunResponse(request.subarray(8, 20), STUN_BINDING_ERROR_RESPONSE, [
      encodedAttribute(0x0009, errorCode),
      encodedAttribute(0x8023, Buffer.alloc(8))
    ]), rinfo(TARGET_V4, 3478))
    await expect(pending).rejects.toMatchObject({ code: 'STUN_AUTH_REQUIRED', responseCode: 401 })
    expect(socket.sends).toHaveLength(1)
    expect(new Set(socket.sends.map((sent) => `${sent.address}:${sent.port}`))).toEqual(new Set([`${TARGET_V4}:3478`]))
  })
})

describe('ValidatedStunObservation: brand, freshness e topology signal', () => {
  function observation(address = '203.0.114.9', observedPort = 55000, clock = { value: 0 }): ValidatedStunObservation {
    return stunObservationTestOnly.createObservation({
      localAddress: LOCAL_V4,
      localPort: 40001,
      observedAddress: address,
      observedPort,
      family: address.includes(':') ? 6 : 4,
      observedScope: 'GLOBAL',
      serverAddress: TARGET_V4,
      serverPort: 3478
    }, () => clock.value, () => 1_700_000_000)
  }

  it('possui runtime brand; object literal/cast e constructor token falso não passam', () => {
    const real = observation()
    expect(isLegitimateValidatedStunObservation(real)).toBe(true)
    expect(isLegitimateValidatedStunObservation({ ...real })).toBe(false)
    expect(Object.isFrozen(real)).toBe(true)
    expect(() => new ValidatedStunObservation(
      Symbol('fake'),
      {
        localAddress: LOCAL_V4, localPort: 40001,
        observedAddress: '203.0.114.9', observedPort: 55000,
        family: 4, observedScope: 'GLOBAL', serverAddress: TARGET_V4, serverPort: 3478
      },
      () => 0,
      () => 1_700_000_000
    )).toThrowError(expect.objectContaining({ code: 'STUN_RESPONSE_INVALID' }))
  })

  it('freshness usa monotonic clock e expira em 30 segundos', () => {
    const clock = { value: 1000 }
    const value = observation('203.0.114.9', 55000, clock)
    expect(value.observedAt).toBe(1_700_000_000)
    expect(value.expiresAt).toBe(1_700_000_000 + STUN_OBSERVATION_MAX_AGE_SECONDS)
    expect(value.isFresh()).toBe(true)
    clock.value += STUN_OBSERVATION_MAX_AGE_SECONDS * 1000
    expect(value.isFresh()).toBe(false)
  })

  it('compara somente ADDRESS com port mapping; UDP/TCP ports diferentes continuam match', () => {
    const value = observation('203.0.114.9', 55000)
    const mapping = new FakeMapping({ family: 4, address: '203.0.114.9', port: 40000 })
    expect(compareStunObservationToPortMapping(value, mapping)).toBe('ADDRESS_MATCH')
    expect(mapping.getExternalEndpoint().port).not.toBe(value.observedPort)
    const mismatch = new FakeMapping({ family: 4, address: '203.0.114.10', port: 55000 })
    expect(compareStunObservationToPortMapping(value, mismatch)).toBe('ADDRESS_MISMATCH')
    expect(mapping.isActive()).toBe(true)
  })

  it('stale/fake/inactive são STALE ou INCOMPARABLE', () => {
    const clock = { value: 0 }
    const value = observation('203.0.114.9', 55000, clock)
    const mapping = new FakeMapping({ family: 4, address: '203.0.114.9', port: 40000 })
    clock.value = 31_000
    expect(compareStunObservationToPortMapping(value, mapping)).toBe('STALE')
    expect(compareStunObservationToPortMapping({ ...value }, mapping)).toBe('INCOMPARABLE')
    mapping.active = false
    expect(compareStunObservationToPortMapping(observation(), mapping)).toBe('INCOMPARABLE')
  })

  it('compara Direct Global por endereço sem auto-migration', async () => {
    const listener = await startFakeDirect(LOCAL_V6)
    expect(compareStunObservationToDirectGlobalListener(
      observation(LOCAL_V6), listener
    )).toBe('ADDRESS_MATCH')
    expect(compareStunObservationToDirectGlobalListener(
      observation('2600::21'), listener
    )).toBe('ADDRESS_MISMATCH')
    expect(listener.getBoundEndpoint().address).toBe(LOCAL_V6)
  })

  it('observation não é candidate e signer production a rejeita', () => {
    const identity = identityFixture()
    const value = observation()
    expect(() => createSignedConnectivityDescriptor({
      serverId: identity.serverId,
      serverPublicKey: identity.publicKey,
      serverPrivateKey: identity.privateKey,
      candidates: [value as unknown as ConnectivityCandidate]
    })).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    expect((value as unknown as { candidateType?: unknown }).candidateType).toBeUndefined()
  })
})

describe('STUN observation real local UDP, sem Internet', () => {
  it('executa Binding Request → Success → branded observation em node:dgram', async () => {
    const server = createDgramSocket('udp4')
    realSockets.push(server)
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.bind(0, '127.0.0.1', resolve)
    })
    const serverAddress = server.address()
    server.on('message', (request, source) => {
      const transactionId = request.subarray(8, 20)
      server.send(successIpv4(transactionId, '203.0.114.9', 55000), source.port, source.address)
    })

    const value = await stunObservationTestOnly.observe({
      localAddress: '127.0.0.1',
      server: { address: '127.0.0.1', port: serverAddress.port },
      timeoutMs: 1000
    }, {
      interfaceProvider: interfaceProvider('127.0.0.1', true),
      allowLoopbackLocalAddress: true,
      randomProvider: () => Buffer.alloc(12, 0xab)
    })
    expect(value).toMatchObject({
      localAddress: '127.0.0.1', observedAddress: '203.0.114.9', observedPort: 55000,
      serverAddress: '127.0.0.1', serverPort: serverAddress.port
    })
    expect(isLegitimateValidatedStunObservation(value)).toBe(true)
  })

  it('API production não possui target default e não inicia sem chamada explícita', async () => {
    await expect(observeStunBinding({
      localAddress: LOCAL_V4,
      server: { address: 'hostname.invalid' }
    })).rejects.toMatchObject({ code: 'STUN_TARGET_INVALID' })
  })
})

class FakeMapping extends ActivePortMappingSource {
  active = true
  constructor(private readonly endpoint: DirectTcpEndpoint) { super() }
  isActive(): boolean { return this.active }
  getExternalEndpoint(): DirectTcpEndpoint { return this.endpoint }
  getExpiresAt(): number { return Math.floor(Date.now() / 1000) + 60 }
  getGrantedLifetime(): number { return 60 }
  getInternalEndpoint() { return { family: 4 as const, address: LOCAL_V4, port: 1234 } }
  async close(): Promise<void> { this.active = false }
}

class FakeDirectServer extends EventEmitter {
  listening = false
  private options: ListenOptions | null = null
  listen(options: ListenOptions, callback?: () => void): this {
    this.options = options
    this.listening = true
    queueMicrotask(() => callback?.())
    return this
  }
  address() { return this.listening ? { address: this.options?.host, family: 'IPv6', port: 43210 } : null }
  close(callback?: () => void): this { this.listening = false; queueMicrotask(() => callback?.()); return this }
  asServer(): Server { return this as unknown as Server }
}

async function startFakeDirect(address: string): Promise<ActiveDirectGlobalListener> {
  const identity = identityFixture()
  const listener = await directGlobalTransportTestOnly.start({
    localAddress: address,
    port: 0,
    storage: {} as Parameters<typeof directGlobalTransportTestOnly.start>[0]['storage'],
    localStorageId: '0'.repeat(32),
    serverId: identity.serverId,
    serverPublicKey: identity.publicKey,
    serverPrivateKey: identity.privateKey
  }, {
    interfaceProvider: interfaceProvider(address),
    serverFactory: () => new FakeDirectServer().asServer()
  })
  activeDirect.push(listener)
  return listener
}

function identityFixture() {
  const keys = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keys.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    publicKey,
    privateKey: keys.privateKey,
    serverId: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
  }
}
