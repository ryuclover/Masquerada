import { randomBytes } from 'node:crypto'
import {
  createSocket,
  type RemoteInfo,
  type Socket as DgramSocket,
  type SocketType
} from 'node:dgram'
import { isIP } from 'node:net'
import { performance } from 'node:perf_hooks'

import { isLegitimateActivePortMapping } from './active-port-mapping'
import {
  isLegitimateActiveDirectGlobalListener
} from './direct-global-transport'
import {
  classifyNetworkAddress,
  enumerateNetworkAddresses,
  type AddressScope,
  type NetworkInterfaceProvider
} from './network-interfaces'
import {
  createStunBindingRequest,
  MAX_STUN_DATAGRAM_BYTES,
  parseStunBindingResponse,
  StunProtocolError,
  STUN_TRANSACTION_ID_BYTES
} from './stun-protocol'
import {
  isNetworkEnvironmentGeneration,
  type NetworkEnvironmentGeneration
} from './network-environment'
import {
  defaultConnectivityResourceGovernor,
  type ConnectivityResourceGovernor
} from './connectivity-resource-governor'
import type { ConnectivitySubsystem } from './connectivity-subsystem'

export const DEFAULT_STUN_PORT = 3478
export const STUN_INITIAL_RTO_MS = 500
export const STUN_MAX_ATTEMPTS = 4
export const STUN_DEFAULT_TIMEOUT_MS = 7500
export const STUN_MAX_TIMEOUT_MS = 15_000
export const STUN_OBSERVATION_MAX_AGE_SECONDS = 30

const MAX_STUN_ADDRESS_LENGTH = 128
const OBSERVATION_TOKEN = Symbol('ValidatedStunObservation')
const legitimateObservations = new WeakSet<object>()

export type StunObservationErrorCode =
  | 'STUN_TARGET_INVALID'
  | 'STUN_LOCAL_ADDRESS_INVALID'
  | 'STUN_LOCAL_ADDRESS_NOT_ASSIGNED'
  | 'STUN_TIMEOUT'
  | 'STUN_ABORTED'
  | 'STUN_SOCKET_ERROR'
  | 'STUN_RESPONSE_INVALID'
  | 'STUN_TRANSACTION_MISMATCH'
  | 'STUN_XOR_MAPPED_ADDRESS_INVALID'
  | 'STUN_FINGERPRINT_INVALID'
  | 'STUN_UNSUPPORTED_ATTRIBUTE'
  | 'STUN_AUTH_REQUIRED'
  | 'STUN_SERVER_ERROR'

export class StunObservationError extends Error {
  readonly code: StunObservationErrorCode
  readonly responseCode?: number

  constructor(code: StunObservationErrorCode, options?: ErrorOptions & { responseCode?: number }) {
    super(code, options)
    this.name = 'StunObservationError'
    this.code = code
    this.responseCode = options?.responseCode
  }
}

export interface StunServerEndpoint {
  readonly address: string
  readonly port?: number
}

export interface ObserveStunBindingOptions {
  readonly localAddress: string
  readonly server: StunServerEndpoint
  readonly timeoutMs?: number
  readonly signal?: AbortSignal
  readonly networkGeneration?: NetworkEnvironmentGeneration
  readonly resourceGovernor?: ConnectivityResourceGovernor
  readonly subsystem?: ConnectivitySubsystem
}

interface StunObservationTestSeams {
  readonly interfaceProvider?: NetworkInterfaceProvider
  readonly socketFactory?: (type: SocketType) => DgramSocket
  readonly randomProvider?: (size: number) => Buffer
  readonly monotonicNowMs?: () => number
  readonly wallNowSeconds?: () => number
  readonly initialRtoMs?: number
  readonly attempts?: number
  readonly allowLoopbackLocalAddress?: boolean
}

interface ObservationFields {
  readonly localAddress: string
  readonly localPort: number
  readonly observedAddress: string
  readonly observedPort: number
  readonly family: 4 | 6
  readonly observedScope: AddressScope
  readonly serverAddress: string
  readonly serverPort: number
}

export class ValidatedStunObservation {
  readonly localAddress: string
  readonly localPort: number
  readonly observedAddress: string
  readonly observedPort: number
  readonly family: 4 | 6
  readonly observedScope: AddressScope
  readonly serverAddress: string
  readonly serverPort: number
  readonly observedAt: number
  readonly expiresAt: number
  readonly networkGeneration?: NetworkEnvironmentGeneration

  private readonly createdMonotonicMs: number
  private readonly monotonicNowMs: () => number

  constructor(
    token: symbol,
    fields: ObservationFields,
    monotonicNowMs: () => number,
    wallNowSeconds: () => number,
    networkGeneration?: NetworkEnvironmentGeneration
  ) {
    if (token !== OBSERVATION_TOKEN) {
      throw new StunObservationError('STUN_RESPONSE_INVALID')
    }
    this.localAddress = fields.localAddress
    this.localPort = fields.localPort
    this.observedAddress = fields.observedAddress
    this.observedPort = fields.observedPort
    this.family = fields.family
    this.observedScope = fields.observedScope
    this.serverAddress = fields.serverAddress
    this.serverPort = fields.serverPort
    this.createdMonotonicMs = monotonicNowMs()
    this.monotonicNowMs = monotonicNowMs
    this.observedAt = wallNowSeconds()
    this.expiresAt = this.observedAt + STUN_OBSERVATION_MAX_AGE_SECONDS
    if (networkGeneration !== undefined && !isNetworkEnvironmentGeneration(networkGeneration)) {
      throw new StunObservationError('STUN_RESPONSE_INVALID')
    }
    this.networkGeneration = networkGeneration
    legitimateObservations.add(this)
    Object.freeze(this)
  }

  /** Freshness is monotonic; wall-clock fields are diagnostic snapshots only. */
  isFresh(): boolean {
    const elapsed = this.monotonicNowMs() - this.createdMonotonicMs
    return legitimateObservations.has(this) &&
      elapsed >= 0 &&
      elapsed < STUN_OBSERVATION_MAX_AGE_SECONDS * 1000
  }
}

export function isLegitimateValidatedStunObservation(
  value: unknown
): value is ValidatedStunObservation {
  return typeof value === 'object' && value !== null && legitimateObservations.has(value)
}

function validateIpLiteral(rawAddress: unknown): { address: string; family: 4 | 6 } {
  if (
    typeof rawAddress !== 'string' ||
    rawAddress.length === 0 ||
    rawAddress.length > MAX_STUN_ADDRESS_LENGTH ||
    rawAddress !== rawAddress.trim() ||
    rawAddress.includes('%')
  ) {
    throw new StunObservationError('STUN_TARGET_INVALID')
  }
  const family = isIP(rawAddress)
  if (family !== 4 && family !== 6) throw new StunObservationError('STUN_TARGET_INVALID')
  return {
    address: classifyNetworkAddress(rawAddress).normalizedAddress,
    family
  }
}

function validateTarget(server: StunServerEndpoint): { address: string; family: 4 | 6; port: number } {
  if (!server || typeof server !== 'object') throw new StunObservationError('STUN_TARGET_INVALID')
  const target = validateIpLiteral(server.address)
  const port = server.port ?? DEFAULT_STUN_PORT
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new StunObservationError('STUN_TARGET_INVALID')
  }
  return { ...target, port }
}

function validateLocalAddress(
  rawAddress: unknown,
  family: 4 | 6,
  provider: NetworkInterfaceProvider | undefined,
  allowLoopback: boolean
): string {
  let selected: { address: string; family: 4 | 6 }
  try {
    selected = validateIpLiteral(rawAddress)
  } catch (cause) {
    throw new StunObservationError('STUN_LOCAL_ADDRESS_INVALID', { cause })
  }
  if (selected.family !== family) {
    throw new StunObservationError('STUN_LOCAL_ADDRESS_INVALID')
  }
  const classification = classifyNetworkAddress(selected.address)
  const scopeAllowed = selected.family === 4
    ? ['LAN_PRIVATE', 'CGNAT', 'GLOBAL'].includes(classification.scope)
    : classification.scope === 'GLOBAL'
  if (!scopeAllowed && !(allowLoopback && classification.scope === 'LOOPBACK')) {
    throw new StunObservationError('STUN_LOCAL_ADDRESS_INVALID')
  }

  const matches = enumerateNetworkAddresses(provider).filter((entry) =>
    entry.family === (selected.family === 4 ? 'IPv4' : 'IPv6') &&
    entry.address === selected.address
  )
  const uniqueInterfaces = new Set(matches.map((entry) => entry.interfaceName))
  if (
    matches.length === 0 ||
    uniqueInterfaces.size !== 1 ||
    (!allowLoopback && matches.some((entry) => entry.internal))
  ) {
    throw new StunObservationError('STUN_LOCAL_ADDRESS_NOT_ASSIGNED')
  }
  return selected.address
}

function mapProtocolError(error: StunProtocolError): StunObservationError {
  const supportedCodes = new Set<StunObservationErrorCode>([
    'STUN_RESPONSE_INVALID',
    'STUN_TRANSACTION_MISMATCH',
    'STUN_XOR_MAPPED_ADDRESS_INVALID',
    'STUN_FINGERPRINT_INVALID',
    'STUN_UNSUPPORTED_ATTRIBUTE',
    'STUN_AUTH_REQUIRED',
    'STUN_SERVER_ERROR'
  ])
  const code = supportedCodes.has(error.code as StunObservationErrorCode)
    ? error.code as StunObservationErrorCode
    : 'STUN_RESPONSE_INVALID'
  return new StunObservationError(code, { cause: error, responseCode: error.responseCode })
}

function closeSocket(socket: DgramSocket): void {
  try {
    socket.close()
  } catch {
    // Closing an already-closed or never-bound socket is harmless cleanup.
  }
}

async function observeStunBindingInternal(
  options: ObserveStunBindingOptions,
  seams: StunObservationTestSeams = {}
): Promise<ValidatedStunObservation> {
  const work = options.subsystem?.beginWork(options.signal)
  const signal = work?.signal ?? options.signal
  let udpReservation
  try {
  udpReservation = (options.resourceGovernor ?? options.subsystem?.governor ?? defaultConnectivityResourceGovernor).reserve('UDP_OPERATION')
  if (signal?.aborted) throw new StunObservationError('STUN_ABORTED')
  const target = validateTarget(options.server)
  const localAddress = validateLocalAddress(
    options.localAddress,
    target.family,
    seams.interfaceProvider,
    seams.allowLoopbackLocalAddress === true
  )
  const timeoutMs = options.timeoutMs ?? STUN_DEFAULT_TIMEOUT_MS
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > STUN_MAX_TIMEOUT_MS) {
    throw new StunObservationError('STUN_TARGET_INVALID')
  }

  const randomProvider = seams.randomProvider ?? randomBytes
  const transactionId = Buffer.from(randomProvider(STUN_TRANSACTION_ID_BYTES))
  if (transactionId.length !== STUN_TRANSACTION_ID_BYTES) {
    throw new StunObservationError('STUN_RESPONSE_INVALID')
  }
  const request = createStunBindingRequest(transactionId)
  const socketType: SocketType = target.family === 4 ? 'udp4' : 'udp6'
  const socket = seams.socketFactory?.(socketType) ?? createSocket({ type: socketType, reuseAddr: false })
  const preventUnhandledSocketError = (): void => undefined
  socket.on('error', preventUnhandledSocketError)

  const localPort = await new Promise<number>((resolve, reject) => {
    let settled = false
    const cleanup = (): void => {
      socket.off('listening', onListening)
      socket.off('error', onError)
      signal?.removeEventListener('abort', onAbort)
    }
    const fail = (error: StunObservationError): void => {
      if (settled) return
      settled = true
      cleanup()
      closeSocket(socket)
      reject(error)
    }
    const onError = (cause: Error): void => fail(new StunObservationError('STUN_SOCKET_ERROR', { cause }))
    const onAbort = (): void => fail(new StunObservationError('STUN_ABORTED'))
    const onListening = (): void => {
      if (settled) return
      let bound
      try {
        bound = socket.address()
      } catch (cause) {
        fail(new StunObservationError('STUN_SOCKET_ERROR', { cause }))
        return
      }
      const boundClass = classifyNetworkAddress(bound.address)
      if (
        boundClass.normalizedAddress !== localAddress ||
        !Number.isInteger(bound.port) ||
        bound.port < 1 ||
        bound.port > 65535
      ) {
        fail(new StunObservationError('STUN_LOCAL_ADDRESS_INVALID'))
        return
      }
      try {
        validateLocalAddress(
          localAddress,
          target.family,
          seams.interfaceProvider,
          seams.allowLoopbackLocalAddress === true
        )
      } catch (cause) {
        fail(new StunObservationError('STUN_LOCAL_ADDRESS_NOT_ASSIGNED', { cause }))
        return
      }
      settled = true
      cleanup()
      resolve(bound.port)
    }

    socket.once('listening', onListening)
    socket.once('error', onError)
    signal?.addEventListener('abort', onAbort, { once: true })
    try {
      socket.bind({ address: localAddress, port: 0, exclusive: true })
    } catch (cause) {
      fail(new StunObservationError('STUN_SOCKET_ERROR', { cause }))
    }
  })

  if (signal?.aborted) {
    closeSocket(socket)
    throw new StunObservationError('STUN_ABORTED')
  }

  return await new Promise<ValidatedStunObservation>((resolve, reject) => {
    let settled = false
    let attemptsSent = 0
    const timers = new Set<ReturnType<typeof setTimeout>>()
    const initialRto = seams.initialRtoMs ?? STUN_INITIAL_RTO_MS
    const maxAttempts = seams.attempts ?? STUN_MAX_ATTEMPTS
    const monotonicNowMs = seams.monotonicNowMs ?? (() => performance.now())
    const wallNowSeconds = seams.wallNowSeconds ?? (() => Math.floor(Date.now() / 1000))

    const cleanup = (): void => {
      for (const timer of timers) clearTimeout(timer)
      timers.clear()
      socket.off('message', onMessage)
      socket.off('error', onError)
      socket.off('error', preventUnhandledSocketError)
      signal?.removeEventListener('abort', onAbort)
      closeSocket(socket)
    }
    const fail = (error: StunObservationError): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(error)
    }
    const succeed = (observation: ValidatedStunObservation): void => {
      if (settled) return
      settled = true
      cleanup()
      resolve(observation)
    }
    const onError = (cause: Error): void => fail(new StunObservationError('STUN_SOCKET_ERROR', { cause }))
    const onAbort = (): void => fail(new StunObservationError('STUN_ABORTED'))
    const onMessage = (datagram: Buffer, rinfo: RemoteInfo): void => {
      if (settled || datagram.length > MAX_STUN_DATAGRAM_BYTES) return
      if (rinfo.address.includes('%') || (isIP(rinfo.address) !== 4 && isIP(rinfo.address) !== 6)) return
      const sourceClass = classifyNetworkAddress(rinfo.address)
      if (sourceClass.normalizedAddress !== target.address || rinfo.port !== target.port) return

      try {
        const decoded = parseStunBindingResponse(datagram, transactionId)
        succeed(new ValidatedStunObservation(
          OBSERVATION_TOKEN,
          {
            localAddress,
            localPort,
            observedAddress: decoded.observedAddress,
            observedPort: decoded.observedPort,
            family: decoded.family,
            observedScope: decoded.observedScope,
            serverAddress: target.address,
            serverPort: target.port
          },
          monotonicNowMs,
          wallNowSeconds,
          options.networkGeneration
        ))
      } catch (error) {
        if (error instanceof StunProtocolError && error.code === 'STUN_TRANSACTION_MISMATCH') return
        if (error instanceof StunProtocolError) fail(mapProtocolError(error))
        else fail(new StunObservationError('STUN_RESPONSE_INVALID', { cause: error }))
      }
    }
    const sendAttempt = (): void => {
      if (settled || attemptsSent >= maxAttempts) return
      socket.send(request, target.port, target.address, (error) => {
        if (error) fail(new StunObservationError('STUN_SOCKET_ERROR', { cause: error }))
      })
      attemptsSent += 1
      if (attemptsSent < maxAttempts) {
        const delay = initialRto * (2 ** (attemptsSent - 1))
        const timer = setTimeout(() => {
          timers.delete(timer)
          sendAttempt()
        }, delay)
        timers.add(timer)
      }
    }

    socket.on('message', onMessage)
    socket.once('error', onError)
    signal?.addEventListener('abort', onAbort, { once: true })
    const timeout = setTimeout(() => {
      timers.delete(timeout)
      fail(new StunObservationError('STUN_TIMEOUT'))
    }, timeoutMs)
    timers.add(timeout)
    sendAttempt()
  })
  } finally {
    udpReservation?.release()
    work?.finish()
  }
}

/** Explicit, optional RFC 8489 Binding observation over UDP. */
export function observeStunBinding(
  options: ObserveStunBindingOptions
): Promise<ValidatedStunObservation> {
  return observeStunBindingInternal(options)
}

export type StunTopologyComparison = 'ADDRESS_MATCH' | 'ADDRESS_MISMATCH' | 'INCOMPARABLE' | 'STALE'

export function compareStunObservationToPortMapping(
  observation: unknown,
  mapping: unknown
): StunTopologyComparison {
  if (!isLegitimateValidatedStunObservation(observation) || !isLegitimateActivePortMapping(mapping)) {
    return 'INCOMPARABLE'
  }
  if (!observation.isFresh()) return 'STALE'
  try {
    if (!mapping.isActive()) return 'INCOMPARABLE'
    const endpoint = mapping.getExternalEndpoint()
    const mapped = classifyNetworkAddress(endpoint.address)
    return mapped.normalizedAddress === observation.observedAddress
      ? 'ADDRESS_MATCH'
      : 'ADDRESS_MISMATCH'
  } catch {
    return 'INCOMPARABLE'
  }
}

export function compareStunObservationToDirectGlobalListener(
  observation: unknown,
  listener: unknown
): StunTopologyComparison {
  if (
    !isLegitimateValidatedStunObservation(observation) ||
    !isLegitimateActiveDirectGlobalListener(listener)
  ) {
    return 'INCOMPARABLE'
  }
  if (!observation.isFresh()) return 'STALE'
  if (!listener.isActive()) return 'INCOMPARABLE'
  try {
    const endpoint = listener.getBoundEndpoint()
    return endpoint.address === observation.observedAddress
      ? 'ADDRESS_MATCH'
      : 'ADDRESS_MISMATCH'
  } catch {
    return 'INCOMPARABLE'
  }
}

/** @internal Deterministic seams; never wired to renderer, IPC, startup or remote input. */
export const stunObservationTestOnly = Object.freeze({
  observe: observeStunBindingInternal,
  createObservation: (
    fields: ObservationFields,
    monotonicNowMs: () => number = () => performance.now(),
    wallNowSeconds: () => number = () => Math.floor(Date.now() / 1000),
    networkGeneration?: NetworkEnvironmentGeneration
  ) => new ValidatedStunObservation(OBSERVATION_TOKEN, fields, monotonicNowMs, wallNowSeconds, networkGeneration)
})
