import { createHash, generateKeyPairSync } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { DeviceAuthError } from '../security/device-auth'
import { aggregateServerCandidates } from './candidate-aggregation'
import {
  CANDIDATE_ATTEMPT_DELAY_MS,
  MIN_CANDIDATE_ATTEMPT_GAP_MS,
  raceSecureServerConnections
} from './candidate-racing'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor
} from './connectivity-descriptor'
import { ConnectivityResourceError, ConnectivityResourceGovernor } from './connectivity-resource-governor'
import { HandshakeError } from './p2p-handshake'
import { SessionError } from './p2p-session'
import { ProtocolError } from './protocol-frame'
import {
  establishSecureServerConnection,
  TcpTransportError,
  tcpTransportTestOnly,
  type ClientSecurePreAuthorizationConnection
} from './tcp-transport'

vi.mock('./tcp-transport', async (importOriginal) => ({
  ...await importOriginal<typeof import('./tcp-transport')>(),
  establishSecureServerConnection: vi.fn()
}))

const NOW = 2_000_000_000
function identity() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}
const server = identity()
const device = identity()
const encodedDescriptor = createSignedConnectivityDescriptor({
  serverId: server.fingerprint,
  serverPublicKey: server.publicKey,
  serverPrivateKey: server.privateKey,
  candidates: ['1.1.1.1', '8.8.8.8', '9.9.9.9'].map((address) => ({
    candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
    family: 4 as const,
    address,
    port: 45000
  })),
  customIssuedAt: NOW,
  lifetimeSeconds: 300,
  allowRawCandidatesForTesting: true
})
const plan = aggregateServerCandidates({
  expectedServerId: server.fingerprint,
  expectedServerPublicKey: server.publicKey,
  descriptors: [verifySignedConnectivityDescriptor({
    encodedDescriptor,
    expectedServerId: server.fingerprint,
    nowSeconds: NOW
  })],
  nowSeconds: NOW
})
const establish = vi.mocked(establishSecureServerConnection)

describe('default candidate establishment fail-closed classification', () => {
  let governor: ConnectivityResourceGovernor

  beforeEach(() => {
    vi.useFakeTimers()
    establish.mockReset()
    governor = new ConnectivityResourceGovernor()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function race(localDevice = device) {
    return raceSecureServerConnections({
      plan,
      device: localDevice,
      nowSeconds: () => NOW,
      resourceGovernor: governor
    })
  }

  function expectReleased() {
    expect(governor.snapshot()).toEqual(new ConnectivityResourceGovernor().snapshot())
    expect(vi.getTimerCount()).toBe(0)
  }

  it.each([
    new Error('ECONNREFUSED TCP_TIMEOUT HANDSHAKE_MESSAGE_INVALID'),
    new TypeError('unexpected local bug'),
    { code: 'ECONNREFUSED', syscall: 'connect' },
    { code: 'HANDSHAKE_MESSAGE_INVALID' },
    Object.assign(new Error('untyped failure'), { code: 'ECONNREFUSED' }),
    Object.assign(new Error('local operation'), { code: 'ETIMEDOUT', syscall: 'open' }),
    new DeviceAuthError('DEVICE_AUTH_INVALID_PUBLIC_KEY'),
    new DeviceAuthError('DEVICE_AUTH_INVALID_PRIVATE_KEY'),
    new DeviceAuthError('DEVICE_AUTH_SIGNING_FAILED'),
    new HandshakeError('HANDSHAKE_FAILED'),
    new HandshakeError('HANDSHAKE_STATE_INVALID'),
    new HandshakeError('HANDSHAKE_CLIENT_PROOF_INVALID'),
    new SessionError('SESSION_FAILED'),
    new SessionError('SESSION_STATE_INVALID'),
    new SessionError('SESSION_CONTEXT_INVALID'),
    new SessionError('SESSION_DIFFIE_HELLMAN_FAILED'),
    new ProtocolError('PROTOCOL_DECODER_FAILED'),
    new TcpTransportError('TCP_ENDPOINT_INVALID'),
    new TcpTransportError('TCP_INVALID_PORT'),
    new TcpTransportError('TCP_PROTOCOL_VIOLATION'),
    new TcpTransportError('TCP_CONNECTION_FAILED'),
    new TcpTransportError('TCP_BACKPRESSURE_OVERFLOW'),
    new TcpTransportError('TCP_READ_QUEUE_OVERFLOW'),
    new TcpTransportError('TCP_CONNECTION_LIMIT_EXCEEDED'),
    new TcpTransportError('TCP_ADMISSION_REJECTED'),
    ...['EMFILE', 'ENFILE', 'ENOMEM', 'ENOBUFS', 'EACCES'].map((code) =>
      Object.assign(new Error('local resource failure'), { code, syscall: 'connect' }))
  ])('stops after one attempt on terminal lower-layer error %s', async (error) => {
    establish.mockRejectedValue(error)
    const expectation = expect(race()).rejects.toMatchObject({ code: 'CANDIDATE_PLAN_INVALID' })
    await vi.runAllTimersAsync()
    await expectation
    expect(establish).toHaveBeenCalledTimes(1)
    expect(establish.mock.calls[0]![0].signal!.aborted).toBe(true)
    expectReleased()
  })

  it.each([
    'CONNECTIVITY_RESOURCE_LIMIT',
    'CONNECT_OPERATION_IN_PROGRESS',
    'CONNECTIVITY_RESOURCE_INVALID'
  ] as const)('preserves lower-layer resource error %s without fallback', async (code) => {
    const error = new ConnectivityResourceError(code)
    establish.mockRejectedValue(error)
    const expectation = expect(race()).rejects.toBe(error)
    await vi.runAllTimersAsync()
    await expectation
    expect(establish).toHaveBeenCalledTimes(1)
    expectReleased()
  })

  it.each([
    { ...device, publicKey: Buffer.from('invalid DER') },
    { ...device, fingerprint: server.fingerprint },
    { ...device, publicKey: Buffer.concat([device.publicKey, Buffer.from([0])]) },
    { ...device, privateKey: generateKeyPairSync('ed25519').publicKey },
    { ...device, privateKey: generateKeyPairSync('x25519').privateKey },
    { ...device, privateKey: server.privateKey }
  ])('rejects invalid local identity before opening any transport %#', async (localDevice) => {
    establish.mockRejectedValue(new HandshakeError('HANDSHAKE_KEY_INVALID'))
    const expectation = expect(race(localDevice)).rejects.toMatchObject({ code: 'CANDIDATE_PLAN_INVALID' })
    await vi.runAllTimersAsync()
    await expectation
    expect(establish).not.toHaveBeenCalled()
    expectReleased()
  })

  it.each([
    new HandshakeError('HANDSHAKE_VERSION_UNSUPPORTED'),
    new HandshakeError('HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED'),
    new HandshakeError('HANDSHAKE_MESSAGE_INVALID'),
    new HandshakeError('HANDSHAKE_KEY_INVALID'),
    new HandshakeError('HANDSHAKE_SERVER_ID_MISMATCH'),
    new HandshakeError('HANDSHAKE_SERVER_PROOF_INVALID'),
    new HandshakeError('HANDSHAKE_SERVER_FINISH_INVALID'),
    new ProtocolError('PROTOCOL_INVALID_MAGIC'),
    new ProtocolError('PROTOCOL_VERSION_UNSUPPORTED'),
    new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED'),
    new ProtocolError('PROTOCOL_FLAGS_UNSUPPORTED'),
    new ProtocolError('PROTOCOL_FRAME_TOO_LARGE'),
    new ProtocolError('PROTOCOL_FRAME_TRUNCATED'),
    new ProtocolError('PROTOCOL_FRAME_INVALID'),
    new SessionError('SESSION_KEY_SHARE_INVALID'),
    new SessionError('SESSION_SIGNATURE_INVALID'),
    new SessionError('SESSION_MESSAGE_INVALID'),
    new SessionError('SESSION_MESSAGE_TYPE_UNSUPPORTED'),
    new SessionError('SESSION_VERSION_UNSUPPORTED'),
    new SessionError('SESSION_CONFIRMATION_INVALID'),
    new TcpTransportError('TCP_TIMEOUT'),
    new TcpTransportError('TCP_CONNECT_TIMEOUT'),
    new TcpTransportError('TCP_WRONG_FRAME_TYPE'),
    new TcpTransportError('TCP_CONNECTION_CLOSED'),
    ...['ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE']
      .map((code) => Object.assign(new Error('opaque message'), { code, syscall: 'connect' }))
  ])('allows bounded fallback on known remote failure %s', async (error) => {
    const connection = tcpTransportTestOnly.createSecurePreAuthorizationConnection({
      expectedServerId: server.fingerprint
    })
    establish.mockRejectedValueOnce(error).mockResolvedValueOnce(connection)
    const operation = race()
    await vi.advanceTimersByTimeAsync(MIN_CANDIDATE_ATTEMPT_GAP_MS - 1)
    expect(establish).toHaveBeenCalledTimes(1)
    expect(establish.mock.calls[0]![0].signal!.aborted).toBe(true)
    expect(governor.snapshot().counts.SECURE_CONNECTION_ATTEMPT).toBe(0)
    await vi.advanceTimersByTimeAsync(1)
    await expect(operation).resolves.toMatchObject({ connection })
    expect(establish).toHaveBeenCalledTimes(2)
    expect(connection.isDestroyed()).toBe(false)
    expectReleased()
    connection.destroy()
  })

  it('exhausts only known failures and releases each attempt', async () => {
    establish.mockRejectedValue(new HandshakeError('HANDSHAKE_MESSAGE_INVALID'))
    const expectation = expect(race()).rejects.toMatchObject({ code: 'NO_REACHABLE_SERVER_CANDIDATE' })
    await vi.runAllTimersAsync()
    await expectation
    expect(establish).toHaveBeenCalledTimes(plan.orderedDialTargets.length)
    expect(establish.mock.calls.every(([options]) => options.signal!.aborted)).toBe(true)
    expectReleased()
  })

  it('aborts an in-flight sibling on terminal failure without starting the next candidate', async () => {
    let rejectFirst!: (error: unknown) => void
    establish.mockImplementationOnce(() => new Promise<ClientSecurePreAuthorizationConnection>((_resolve, reject) => {
      rejectFirst = reject
    })).mockImplementationOnce((options) => new Promise<ClientSecurePreAuthorizationConnection>((_resolve, reject) => {
      options.signal!.addEventListener('abort', () => reject(new TcpTransportError('TCP_CONNECTION_CLOSED')), { once: true })
    }))
    const expectation = expect(race()).rejects.toMatchObject({ code: 'CANDIDATE_PLAN_INVALID' })
    await vi.advanceTimersByTimeAsync(CANDIDATE_ATTEMPT_DELAY_MS)
    expect(establish).toHaveBeenCalledTimes(2)
    expect(governor.snapshot().counts.SECURE_CONNECTION_ATTEMPT).toBe(2)
    rejectFirst(new Error('unexpected failure'))
    await vi.runAllTimersAsync()
    await expectation
    expect(establish).toHaveBeenCalledTimes(2)
    expect(establish.mock.calls.every(([options]) => options.signal!.aborted)).toBe(true)
    expectReleased()
  })
})
