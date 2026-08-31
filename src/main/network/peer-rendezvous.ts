import { randomBytes } from 'node:crypto'

import {
  ConnectivityCandidateType,
  MAX_CONNECTIVITY_DESCRIPTOR_BYTES,
  verifySignedConnectivityDescriptor,
  type VerifiedConnectivityDescriptor
} from './connectivity-descriptor'
import {
  aggregateServerCandidates,
  type EphemeralCandidateSuccessCache
} from './candidate-aggregation'
import {
  connectToServerUsingCandidates,
  type CandidateAuthorization,
  type CandidateRaceDeviceIdentity,
  type SecureConnectionAttempt
} from './candidate-racing'
import {
  isAuthorizedPeerChannel,
  type AuthorizedPeerChannel,
  type ClientTcpPeerConnection
} from './tcp-transport'
import {
  defaultConnectivityResourceGovernor,
  type ConnectivityResourceGovernor,
  type ConnectivityResourceReservation
} from './connectivity-resource-governor'
import type { ConnectivitySubsystem } from './connectivity-subsystem'

export const RENDEZVOUS_PROTOCOL_VERSION = 1
export const RENDEZVOUS_REQUEST_NONCE_BYTES = 32
export const RENDEZVOUS_SERVER_ID_BYTES = 71
export const RENDEZVOUS_REQUEST_BYTES = 2 + RENDEZVOUS_REQUEST_NONCE_BYTES + RENDEZVOUS_SERVER_ID_BYTES
export const RENDEZVOUS_RESPONSE_HEADER_BYTES = 3 + RENDEZVOUS_REQUEST_NONCE_BYTES + RENDEZVOUS_SERVER_ID_BYTES + 2
export const MAX_RENDEZVOUS_RESPONSE_BYTES = RENDEZVOUS_RESPONSE_HEADER_BYTES + MAX_CONNECTIVITY_DESCRIPTOR_BYTES
export const MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES = 64
export const MAX_RENDEZVOUS_DESCRIPTOR_BYTES = 512 * 1024
export const RENDEZVOUS_RATE_WINDOW_MS = 10_000
export const MAX_RENDEZVOUS_REQUESTS_PER_CONNECTION = 10
export const MAX_RENDEZVOUS_REQUESTS_GLOBAL = 100
export const MAX_RENDEZVOUS_OUTSTANDING_REQUESTS = 2
export const RENDEZVOUS_REQUEST_TIMEOUT_MS = 3000
export const MAX_RENDEZVOUS_REQUEST_TIMEOUT_MS = 10_000

export enum RendezvousMessageType {
  RENDEZVOUS_REQUEST = 0x20,
  RENDEZVOUS_RESPONSE = 0x21
}

export enum RendezvousResponseStatus {
  FOUND = 0x01,
  NOT_AVAILABLE = 0x02
}

export type PeerRendezvousErrorCode =
  | 'RENDEZVOUS_PROTOCOL_INVALID'
  | 'RENDEZVOUS_NOT_AUTHORIZED'
  | 'RENDEZVOUS_NONCE_MISMATCH'
  | 'RENDEZVOUS_SERVER_MISMATCH'
  | 'RENDEZVOUS_DESCRIPTOR_INVALID'
  | 'RENDEZVOUS_DESCRIPTOR_NOT_SHAREABLE'
  | 'RENDEZVOUS_STORE_FULL'
  | 'RENDEZVOUS_NOT_AVAILABLE'
  | 'RENDEZVOUS_RATE_LIMITED'
  | 'RENDEZVOUS_OUTSTANDING_LIMIT'
  | 'RENDEZVOUS_TIMEOUT'
  | 'RENDEZVOUS_ABORTED'
  | 'RENDEZVOUS_CHANNEL_CLOSED'

export class PeerRendezvousError extends Error {
  constructor(readonly code: PeerRendezvousErrorCode, options?: ErrorOptions) {
    super(code, options)
    this.name = 'PeerRendezvousError'
  }
}

export interface RendezvousRequest {
  readonly requestNonce: Buffer
  readonly serverId: string
}

export interface RendezvousResponse {
  readonly status: RendezvousResponseStatus
  readonly requestNonce: Buffer
  readonly serverId: string
  readonly descriptorBytes: Buffer
}

export function isCanonicalServerId(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value)
}

function assertNonce(nonce: Buffer): void {
  if (!Buffer.isBuffer(nonce) || nonce.length !== RENDEZVOUS_REQUEST_NONCE_BYTES) {
    throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  }
}

export function encodeRendezvousRequest(request: RendezvousRequest): Buffer {
  assertNonce(request.requestNonce)
  if (!isCanonicalServerId(request.serverId)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  const result = Buffer.alloc(RENDEZVOUS_REQUEST_BYTES)
  result.writeUInt8(RENDEZVOUS_PROTOCOL_VERSION, 0)
  result.writeUInt8(RendezvousMessageType.RENDEZVOUS_REQUEST, 1)
  request.requestNonce.copy(result, 2)
  result.write(request.serverId, 2 + RENDEZVOUS_REQUEST_NONCE_BYTES, RENDEZVOUS_SERVER_ID_BYTES, 'ascii')
  return result
}

export function decodeRendezvousRequest(buffer: Buffer): RendezvousRequest {
  if (!Buffer.isBuffer(buffer) || buffer.length !== RENDEZVOUS_REQUEST_BYTES) {
    throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  }
  if (
    buffer.readUInt8(0) !== RENDEZVOUS_PROTOCOL_VERSION ||
    buffer.readUInt8(1) !== RendezvousMessageType.RENDEZVOUS_REQUEST
  ) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  const requestNonce = Buffer.from(buffer.subarray(2, 2 + RENDEZVOUS_REQUEST_NONCE_BYTES))
  const serverId = buffer.subarray(2 + RENDEZVOUS_REQUEST_NONCE_BYTES).toString('ascii')
  if (!isCanonicalServerId(serverId)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  return Object.freeze({ requestNonce, serverId })
}

export function encodeRendezvousResponse(response: RendezvousResponse): Buffer {
  assertNonce(response.requestNonce)
  if (!isCanonicalServerId(response.serverId)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  if (!Buffer.isBuffer(response.descriptorBytes)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  const found = response.status === RendezvousResponseStatus.FOUND
  if (
    (!found && response.status !== RendezvousResponseStatus.NOT_AVAILABLE) ||
    (found && (response.descriptorBytes.length < 1 || response.descriptorBytes.length > MAX_CONNECTIVITY_DESCRIPTOR_BYTES)) ||
    (!found && response.descriptorBytes.length !== 0)
  ) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  const result = Buffer.alloc(RENDEZVOUS_RESPONSE_HEADER_BYTES + response.descriptorBytes.length)
  result.writeUInt8(RENDEZVOUS_PROTOCOL_VERSION, 0)
  result.writeUInt8(RendezvousMessageType.RENDEZVOUS_RESPONSE, 1)
  result.writeUInt8(response.status, 2)
  response.requestNonce.copy(result, 3)
  const serverOffset = 3 + RENDEZVOUS_REQUEST_NONCE_BYTES
  result.write(response.serverId, serverOffset, RENDEZVOUS_SERVER_ID_BYTES, 'ascii')
  const lengthOffset = serverOffset + RENDEZVOUS_SERVER_ID_BYTES
  result.writeUInt16BE(response.descriptorBytes.length, lengthOffset)
  response.descriptorBytes.copy(result, lengthOffset + 2)
  return result
}

export function decodeRendezvousResponse(buffer: Buffer): RendezvousResponse {
  if (
    !Buffer.isBuffer(buffer) ||
    buffer.length < RENDEZVOUS_RESPONSE_HEADER_BYTES ||
    buffer.length > MAX_RENDEZVOUS_RESPONSE_BYTES ||
    buffer.readUInt8(0) !== RENDEZVOUS_PROTOCOL_VERSION ||
    buffer.readUInt8(1) !== RendezvousMessageType.RENDEZVOUS_RESPONSE
  ) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  const status = buffer.readUInt8(2)
  if (status !== RendezvousResponseStatus.FOUND && status !== RendezvousResponseStatus.NOT_AVAILABLE) {
    throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  }
  const requestNonce = Buffer.from(buffer.subarray(3, 3 + RENDEZVOUS_REQUEST_NONCE_BYTES))
  const serverOffset = 3 + RENDEZVOUS_REQUEST_NONCE_BYTES
  const serverId = buffer.subarray(serverOffset, serverOffset + RENDEZVOUS_SERVER_ID_BYTES).toString('ascii')
  if (!isCanonicalServerId(serverId)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  const lengthOffset = serverOffset + RENDEZVOUS_SERVER_ID_BYTES
  const descriptorLength = buffer.readUInt16BE(lengthOffset)
  if (
    lengthOffset + 2 + descriptorLength !== buffer.length ||
    (status === RendezvousResponseStatus.FOUND && (descriptorLength < 1 || descriptorLength > MAX_CONNECTIVITY_DESCRIPTOR_BYTES)) ||
    (status === RendezvousResponseStatus.NOT_AVAILABLE && descriptorLength !== 0)
  ) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  return Object.freeze({
    status,
    requestNonce,
    serverId,
    descriptorBytes: Buffer.from(buffer.subarray(lengthOffset + 2))
  })
}

const SHAREABLE_TOKEN = Symbol('RendezvousShareableDescriptor')
const shareableDescriptors = new WeakSet<object>()

export class RendezvousShareableDescriptor {
  readonly serverId: string
  readonly issuedAt: number
  readonly expiresAt: number
  private readonly descriptorIdBytes: Buffer
  private readonly raw: Buffer

  constructor(token: symbol, descriptor: VerifiedConnectivityDescriptor) {
    if (token !== SHAREABLE_TOKEN) throw new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_INVALID')
    this.serverId = descriptor.serverId
    this.issuedAt = descriptor.issuedAt
    this.expiresAt = descriptor.expiresAt
    this.descriptorIdBytes = Buffer.from(descriptor.descriptorId)
    this.raw = Buffer.from(descriptor.rawEncoded)
    shareableDescriptors.add(this)
    Object.freeze(this)
  }

  getRawEncoded(): Buffer {
    return Buffer.from(this.raw)
  }

  getDescriptorId(): Buffer {
    return Buffer.from(this.descriptorIdBytes)
  }

  getVerifiedDescriptor(nowSeconds?: number): VerifiedConnectivityDescriptor {
    return verifyShareableRaw(this.raw, this.serverId, nowSeconds)
  }
}

export function isRendezvousShareableDescriptor(value: unknown): value is RendezvousShareableDescriptor {
  return typeof value === 'object' && value !== null && shareableDescriptors.has(value)
}

function verifyShareableRaw(raw: Buffer, expectedServerId: string, nowSeconds?: number): VerifiedConnectivityDescriptor {
  let verified: VerifiedConnectivityDescriptor
  try {
    verified = verifySignedConnectivityDescriptor({
      encodedDescriptor: raw,
      expectedServerId,
      nowSeconds,
      allowLoopbackForTesting: true
    })
  } catch (cause) {
    throw new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_INVALID', { cause })
  }
  if (
    verified.candidates.length === 0 ||
    verified.candidates.some((candidate) =>
      candidate.candidateType !== ConnectivityCandidateType.PORT_MAPPED_TCP &&
      candidate.candidateType !== ConnectivityCandidateType.DIRECT_GLOBAL_TCP
    )
  ) throw new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_NOT_SHAREABLE')
  return verified
}

export function markRendezvousShareable(
  descriptor: VerifiedConnectivityDescriptor,
  nowSeconds?: number
): RendezvousShareableDescriptor {
  if (!descriptor || typeof descriptor !== 'object' || !Buffer.isBuffer(descriptor.rawEncoded)) {
    throw new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_INVALID')
  }
  const verified = verifyShareableRaw(descriptor.rawEncoded, descriptor.serverId, nowSeconds)
  return new RendezvousShareableDescriptor(SHAREABLE_TOKEN, verified)
}

interface StoreEntry {
  readonly descriptor: RendezvousShareableDescriptor
  readonly rawBytes: number
}

export class RendezvousDescriptorStore {
  private readonly entries = new Map<string, StoreEntry>()
  private byteCount = 0

  constructor(
    private readonly nowSeconds: () => number = () => Math.floor(Date.now() / 1000),
    private readonly maxEntries = MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES,
    private readonly maxBytes = MAX_RENDEZVOUS_DESCRIPTOR_BYTES
  ) {
    if (
      !Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES ||
      !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_RENDEZVOUS_DESCRIPTOR_BYTES
    ) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  }

  put(descriptor: RendezvousShareableDescriptor): boolean {
    if (!isRendezvousShareableDescriptor(descriptor)) {
      throw new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_INVALID')
    }
    this.purgeExpired()
    descriptor.getVerifiedDescriptor(this.nowSeconds())
    const current = this.entries.get(descriptor.serverId)
    if (current && compareShareableDescriptors(descriptor, current.descriptor) <= 0) return false
    const rawBytes = descriptor.getRawEncoded().length
    const nextCount = this.entries.size + (current ? 0 : 1)
    const nextBytes = this.byteCount - (current?.rawBytes ?? 0) + rawBytes
    if (nextCount > this.maxEntries || nextBytes > this.maxBytes) {
      throw new PeerRendezvousError('RENDEZVOUS_STORE_FULL')
    }
    this.entries.set(descriptor.serverId, Object.freeze({ descriptor, rawBytes }))
    this.byteCount = nextBytes
    return true
  }

  get(serverId: string): RendezvousShareableDescriptor | null {
    if (!isCanonicalServerId(serverId)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
    const current = this.entries.get(serverId)
    if (!current) return null
    try {
      current.descriptor.getVerifiedDescriptor(this.nowSeconds())
      return current.descriptor
    } catch {
      this.entries.delete(serverId)
      this.byteCount -= current.rawBytes
      return null
    }
  }

  private purgeExpired(): void {
    for (const [serverId, entry] of this.entries) {
      if (this.nowSeconds() >= entry.descriptor.expiresAt) {
        this.entries.delete(serverId)
        this.byteCount -= entry.rawBytes
      }
    }
  }

  get size(): number {
    this.purgeExpired()
    return this.entries.size
  }

  get totalBytes(): number {
    this.purgeExpired()
    return this.byteCount
  }
}

function compareShareableDescriptors(a: RendezvousShareableDescriptor, b: RendezvousShareableDescriptor): number {
  if (a.issuedAt !== b.issuedAt) return a.issuedAt - b.issuedAt
  if (a.expiresAt !== b.expiresAt) return a.expiresAt - b.expiresAt
  return Buffer.compare(a.getDescriptorId(), b.getDescriptorId())
}

export class RendezvousGlobalRateLimiter {
  private readonly events: number[] = []

  constructor(private readonly monotonicNowMs: () => number = () => performance.now()) {}

  consume(): boolean {
    const now = this.monotonicNowMs()
    while (this.events.length > 0 && now - this.events[0]! >= RENDEZVOUS_RATE_WINDOW_MS) this.events.shift()
    if (this.events.length >= MAX_RENDEZVOUS_REQUESTS_GLOBAL) return false
    this.events.push(now)
    return true
  }
}

const defaultGlobalRateLimiter = new RendezvousGlobalRateLimiter()
const ENDPOINT_TOKEN = Symbol('PeerRendezvousEndpoint')
const rendezvousEndpoints = new WeakSet<object>()

interface PendingRequest {
  readonly serverId: string
  readonly resolve: (descriptor: RendezvousShareableDescriptor) => void
  readonly reject: (error: PeerRendezvousError) => void
  readonly timer: ReturnType<typeof setTimeout>
  readonly signal?: AbortSignal
  readonly onAbort?: () => void
  readonly resourceReservation: ConnectivityResourceReservation
}

export interface CreatePeerRendezvousEndpointOptions {
  readonly channel: AuthorizedPeerChannel
  readonly store?: RendezvousDescriptorStore
  readonly globalRateLimiter?: RendezvousGlobalRateLimiter
  readonly monotonicNowMs?: () => number
  readonly resourceGovernor?: ConnectivityResourceGovernor
  readonly subsystem?: ConnectivitySubsystem
}

export interface RequestRendezvousDescriptorOptions {
  readonly timeoutMs?: number
  readonly signal?: AbortSignal
}

export class PeerRendezvousEndpoint {
  private readonly pending = new Map<string, PendingRequest>()
  private readonly perConnectionEvents: number[] = []
  private readonly seenRequestNonces = new Set<string>()
  private closed = false
  private readonly removeCloseHandler: () => void
  private readonly removeMessageHandler: () => void
  readonly peerServerId?: string
  private readonly removeSubsystemResource: () => void

  constructor(
    token: symbol,
    private readonly channel: AuthorizedPeerChannel,
    private readonly store: RendezvousDescriptorStore | undefined,
    private readonly globalRateLimiter: RendezvousGlobalRateLimiter,
    private readonly monotonicNowMs: () => number,
    private readonly resourceGovernor: ConnectivityResourceGovernor,
    subsystem?: ConnectivitySubsystem
  ) {
    if (token !== ENDPOINT_TOKEN || !isAuthorizedPeerChannel(channel) || channel.isClosed()) {
      throw new PeerRendezvousError('RENDEZVOUS_NOT_AUTHORIZED')
    }
    rendezvousEndpoints.add(this)
    this.peerServerId = channel.getAuthorizationBinding().serverId
    this.removeMessageHandler = channel.registerMessageHandler(
      [RendezvousMessageType.RENDEZVOUS_REQUEST, RendezvousMessageType.RENDEZVOUS_RESPONSE],
      async (plaintext) => this.handlePlaintext(plaintext)
    )
    this.removeCloseHandler = channel.onClose(() => this.handleClose())
    this.removeSubsystemResource = subsystem?.registerResource({
      close: () => this.handleClose(),
      forceClose: () => this.handleClose()
    }) ?? (() => {})
  }

  requestDescriptor(
    serverId: string,
    options: RequestRendezvousDescriptorOptions = {}
  ): Promise<RendezvousShareableDescriptor> {
    if (this.closed) return Promise.reject(new PeerRendezvousError('RENDEZVOUS_CHANNEL_CLOSED'))
    if (!isCanonicalServerId(serverId)) return Promise.reject(new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID'))
    if (this.pending.size >= MAX_RENDEZVOUS_OUTSTANDING_REQUESTS) {
      return Promise.reject(new PeerRendezvousError('RENDEZVOUS_OUTSTANDING_LIMIT'))
    }
    if (options.signal?.aborted) return Promise.reject(new PeerRendezvousError('RENDEZVOUS_ABORTED'))
    const timeoutMs = options.timeoutMs ?? RENDEZVOUS_REQUEST_TIMEOUT_MS
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_RENDEZVOUS_REQUEST_TIMEOUT_MS) {
      return Promise.reject(new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID'))
    }
    let requestNonce: Buffer | undefined
    let nonceKey = ''
    for (let attempt = 0; attempt < 4; attempt++) {
      const candidate = randomBytes(RENDEZVOUS_REQUEST_NONCE_BYTES)
      const candidateKey = candidate.toString('hex')
      if (!this.pending.has(candidateKey)) {
        requestNonce = candidate
        nonceKey = candidateKey
        break
      }
    }
    if (!requestNonce) return Promise.reject(new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID'))
    let resourceReservation: ConnectivityResourceReservation
    try {
      resourceReservation = this.resourceGovernor.reserve('RENDEZVOUS_REQUEST')
    } catch (cause) {
      return Promise.reject(cause)
    }
    return new Promise<RendezvousShareableDescriptor>((resolve, reject) => {
      const finishReject = (error: PeerRendezvousError): void => {
        const pending = this.pending.get(nonceKey)
        if (!pending) return
        this.cleanupPending(nonceKey, pending)
        reject(error)
      }
      const onAbort = (): void => finishReject(new PeerRendezvousError('RENDEZVOUS_ABORTED'))
      const timer = setTimeout(() => finishReject(new PeerRendezvousError('RENDEZVOUS_TIMEOUT')), timeoutMs)
      const pending: PendingRequest = {
        serverId,
        resolve,
        reject,
        timer,
        signal: options.signal,
        onAbort,
        resourceReservation
      }
      this.pending.set(nonceKey, pending)
      options.signal?.addEventListener('abort', onAbort, { once: true })
      void this.channel.send(encodeRendezvousRequest({ requestNonce, serverId })).catch((cause) => {
        finishReject(new PeerRendezvousError('RENDEZVOUS_CHANNEL_CLOSED', { cause }))
      })
    })
  }

  private async handlePlaintext(plaintext: Buffer): Promise<void> {
    if (this.closed || plaintext.length < 2 || plaintext.readUInt8(0) !== RENDEZVOUS_PROTOCOL_VERSION) {
      throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
    }
    const messageType = plaintext.readUInt8(1)
    if (messageType === RendezvousMessageType.RENDEZVOUS_REQUEST) {
      await this.handleRequest(decodeRendezvousRequest(plaintext))
      return
    }
    if (messageType === RendezvousMessageType.RENDEZVOUS_RESPONSE) {
      this.handleResponse(decodeRendezvousResponse(plaintext))
      return
    }
    throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
  }

  private async handleRequest(request: RendezvousRequest): Promise<void> {
    const now = this.monotonicNowMs()
    while (
      this.perConnectionEvents.length > 0 &&
      now - this.perConnectionEvents[0]! >= RENDEZVOUS_RATE_WINDOW_MS
    ) this.perConnectionEvents.shift()
    if (
      this.perConnectionEvents.length >= MAX_RENDEZVOUS_REQUESTS_PER_CONNECTION ||
      !this.globalRateLimiter.consume()
    ) throw new PeerRendezvousError('RENDEZVOUS_RATE_LIMITED')
    this.perConnectionEvents.push(now)

    const nonceKey = request.requestNonce.toString('hex')
    if (this.seenRequestNonces.has(nonceKey)) throw new PeerRendezvousError('RENDEZVOUS_PROTOCOL_INVALID')
    this.seenRequestNonces.add(nonceKey)
    if (this.seenRequestNonces.size > 64) {
      const oldest = this.seenRequestNonces.values().next().value as string | undefined
      if (oldest) this.seenRequestNonces.delete(oldest)
    }
    const descriptor = this.store?.get(request.serverId) ?? null
    await this.channel.send(encodeRendezvousResponse({
      status: descriptor ? RendezvousResponseStatus.FOUND : RendezvousResponseStatus.NOT_AVAILABLE,
      requestNonce: request.requestNonce,
      serverId: request.serverId,
      descriptorBytes: descriptor?.getRawEncoded() ?? Buffer.alloc(0)
    }))
  }

  private handleResponse(response: RendezvousResponse): void {
    const nonceKey = response.requestNonce.toString('hex')
    const pending = this.pending.get(nonceKey)
    if (!pending) return
    if (response.serverId !== pending.serverId) {
      this.cleanupPending(nonceKey, pending)
      pending.reject(new PeerRendezvousError('RENDEZVOUS_SERVER_MISMATCH'))
      return
    }
    if (response.status === RendezvousResponseStatus.NOT_AVAILABLE) {
      this.cleanupPending(nonceKey, pending)
      pending.reject(new PeerRendezvousError('RENDEZVOUS_NOT_AVAILABLE'))
      return
    }
    try {
      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: response.descriptorBytes,
        expectedServerId: pending.serverId
      })
      const shareable = markRendezvousShareable(verified)
      this.cleanupPending(nonceKey, pending)
      pending.resolve(shareable)
    } catch (cause) {
      this.cleanupPending(nonceKey, pending)
      pending.reject(cause instanceof PeerRendezvousError
        ? cause
        : new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_INVALID', { cause }))
    }
  }

  private cleanupPending(nonceKey: string, pending: PendingRequest): void {
    clearTimeout(pending.timer)
    pending.signal?.removeEventListener('abort', pending.onAbort!)
    this.pending.delete(nonceKey)
    pending.resourceReservation.release()
  }

  private handleClose(): void {
    if (this.closed) return
    this.closed = true
    for (const [nonceKey, pending] of this.pending) {
      this.cleanupPending(nonceKey, pending)
      pending.reject(new PeerRendezvousError('RENDEZVOUS_CHANNEL_CLOSED'))
    }
    this.removeMessageHandler()
    this.removeCloseHandler?.()
    this.removeSubsystemResource()
  }

  get outstandingRequests(): number {
    return this.pending.size
  }
}

export function createPeerRendezvousEndpoint(
  options: CreatePeerRendezvousEndpointOptions
): PeerRendezvousEndpoint {
  return new PeerRendezvousEndpoint(
    ENDPOINT_TOKEN,
    options.channel,
    options.store,
    options.globalRateLimiter ?? defaultGlobalRateLimiter,
    options.monotonicNowMs ?? (() => performance.now()),
    options.resourceGovernor ?? options.subsystem?.governor ?? defaultConnectivityResourceGovernor,
    options.subsystem
  )
}

export function isPeerRendezvousEndpoint(value: unknown): value is PeerRendezvousEndpoint {
  return typeof value === 'object' && value !== null && rendezvousEndpoints.has(value)
}

export interface ConnectToServerViaRendezvousOptions {
  readonly rendezvous: PeerRendezvousEndpoint
  readonly targetServerId: string
  readonly device: CandidateRaceDeviceIdentity
  readonly authorization: CandidateAuthorization
  readonly signal?: AbortSignal
  readonly requestTimeoutMs?: number
  readonly successCache?: EphemeralCandidateSuccessCache
  readonly establishConnection?: SecureConnectionAttempt
}

/** Metadata lookup followed by the existing direct aggregation/racing pipeline. */
export async function connectToServerViaRendezvous(
  options: ConnectToServerViaRendezvousOptions
): Promise<ClientTcpPeerConnection> {
  if (!isPeerRendezvousEndpoint(options.rendezvous)) {
    throw new PeerRendezvousError('RENDEZVOUS_NOT_AUTHORIZED')
  }
  const shareable = await options.rendezvous.requestDescriptor(options.targetServerId, {
    timeoutMs: options.requestTimeoutMs,
    signal: options.signal
  })
  const descriptor = shareable.getVerifiedDescriptor()
  const plan = aggregateServerCandidates({
    expectedServerId: options.targetServerId,
    expectedServerPublicKey: descriptor.serverPublicKey,
    descriptors: [descriptor],
    successCache: options.successCache
  })
  return connectToServerUsingCandidates({
    plan,
    device: options.device,
    authorization: options.authorization,
    signal: options.signal,
    successCache: options.successCache,
    establishConnection: options.establishConnection
  })
}
