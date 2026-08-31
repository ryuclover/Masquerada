import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

import {
  createMasqueradaTransportStream,
  type MasqueradaTransportStream,
  type MasqueradaTransportStreamHandle
} from './masquerada-transport-stream'
import {
  isCanonicalServerId,
  RENDEZVOUS_SERVER_ID_BYTES
} from './peer-rendezvous'
import {
  isAuthorizedPeerChannel,
  type AuthorizedPeerChannel
} from './tcp-transport'
import {
  defaultConnectivityResourceGovernor,
  type ConnectivityResourceGovernor,
  type ConnectivityResourceReservation
} from './connectivity-resource-governor'
import type { ConnectivitySubsystem } from './connectivity-subsystem'

export const RELAY_PROTOCOL_VERSION = 1
export const RELAY_REQUEST_NONCE_BYTES = 32
export const RELAY_CHALLENGE_BYTES = 32
export const RELAY_CHANNEL_BINDING_BYTES = 32
export const RELAY_CIRCUIT_ID_BYTES = 16
export const RELAY_ED25519_PUBLIC_KEY_BYTES = 44
export const RELAY_ED25519_SIGNATURE_BYTES = 64
export const RELAY_REGISTRATION_CHALLENGE_TTL_MS = 10_000
export const RELAY_TARGET_REGISTRATION_MAX_LIFETIME_SECONDS = 300
export const RELAY_OPEN_TIMEOUT_MS = 3000
export const MAX_RELAY_OPEN_TIMEOUT_MS = 10_000
export const MAX_RELAY_OUTSTANDING_OPENS = 2
export const MAX_RELAY_CIRCUITS_PER_CHANNEL = 2
export const MAX_RELAY_CIRCUITS_GLOBAL = 32
export const MAX_RELAY_DATA_PAYLOAD_BYTES = 16 * 1024
export const MAX_RELAY_QUEUED_BYTES = 64 * 1024
export const MAX_RELAY_GLOBAL_QUEUED_BYTES = 1024 * 1024
export const MAX_RELAY_BYTES_PER_CIRCUIT = 32 * 1024 * 1024
export const MAX_RELAY_BYTES_PER_CIRCUIT_HARD = 256 * 1024 * 1024
export const RELAY_CIRCUIT_MAX_LIFETIME_MS = 300_000
export const RELAY_CIRCUIT_LEASE_SECONDS = 300
export const RELAY_CIRCUIT_RENEW_TIMEOUT_MS = 3000
export const RELAY_CIRCUIT_IDLE_TIMEOUT_MS = 60_000
export const RELAY_RATE_WINDOW_MS = 10_000
export const MAX_RELAY_OPENS_PER_CHANNEL = 5
export const MAX_RELAY_OPENS_GLOBAL = 50
export const MAX_RELAY_REGISTRATIONS_PER_CHANNEL = 1
export const MAX_RELAY_REGISTRATION_ATTEMPTS_PER_CHANNEL = 5
export const MAX_RELAY_DATA_MESSAGES_PER_CHANNEL = 1024
export const MAX_RELAY_DATA_MESSAGES_GLOBAL = 8192
export const RELAY_REGISTRATION_SIGNATURE_DOMAIN = 'Masquerada/peer-relay-target-registration/v1'

export enum RelayMessageType {
  REGISTER_BEGIN = 0x30,
  REGISTER_CHALLENGE = 0x31,
  REGISTER_PROOF = 0x32,
  REGISTER_RESULT = 0x33,
  UNREGISTER = 0x34,
  OPEN_REQUEST = 0x35,
  OPEN_RESPONSE = 0x36,
  INCOMING_CIRCUIT = 0x37,
  CIRCUIT_ACCEPT = 0x38,
  DATA = 0x39,
  CLOSE = 0x3a,
  OPEN_CANCEL = 0x3b,
  CIRCUIT_RENEW = 0x3c,
  CIRCUIT_RENEW_RESULT = 0x3d
}

export enum RelayStatus {
  READY = 0x01,
  NOT_AVAILABLE = 0x02
}

export enum RelayCloseReason {
  NORMAL = 0x01,
  PEER_CLOSED = 0x02,
  RESOURCE_LIMIT = 0x03,
  PROTOCOL_ERROR = 0x04,
  TIMEOUT = 0x05
}

export type PeerRelayErrorCode =
  | 'RELAY_NOT_AUTHORIZED'
  | 'RELAY_PROTOCOL_INVALID'
  | 'RELAY_TARGET_NOT_AVAILABLE'
  | 'RELAY_REGISTRATION_INVALID'
  | 'RELAY_REGISTRATION_CHALLENGE_EXPIRED'
  | 'RELAY_REGISTRATION_PROOF_INVALID'
  | 'RELAY_REGISTRATION_EXPIRED'
  | 'RELAY_OPEN_TIMEOUT'
  | 'RELAY_OPEN_ABORTED'
  | 'RELAY_CIRCUIT_LIMIT'
  | 'RELAY_CIRCUIT_INVALID'
  | 'RELAY_CIRCUIT_CLOSED'
  | 'RELAY_PAYLOAD_TOO_LARGE'
  | 'RELAY_RESOURCE_LIMIT'
  | 'RELAY_IDLE_TIMEOUT'
  | 'RELAY_LIFETIME_EXCEEDED'
  | 'RELAY_CHANNEL_CLOSED'

export class PeerRelayError extends Error {
  constructor(readonly code: PeerRelayErrorCode, options?: ErrorOptions) {
    super(code, options)
    this.name = 'PeerRelayError'
  }
}

type RelayMessage =
  | { readonly type: RelayMessageType.REGISTER_BEGIN; readonly targetServerId: string }
  | { readonly type: RelayMessageType.REGISTER_CHALLENGE; readonly targetServerId: string; readonly challenge: Buffer; readonly relayServerId: string; readonly channelBinding: Buffer; readonly outerDeviceFingerprint: string }
  | { readonly type: RelayMessageType.REGISTER_PROOF; readonly targetServerId: string; readonly targetServerPublicKey: Buffer; readonly challenge: Buffer; readonly signature: Buffer }
  | { readonly type: RelayMessageType.REGISTER_RESULT; readonly status: RelayStatus; readonly targetServerId: string; readonly lifetimeSeconds: number }
  | { readonly type: RelayMessageType.UNREGISTER; readonly targetServerId: string }
  | { readonly type: RelayMessageType.OPEN_REQUEST; readonly requestNonce: Buffer; readonly targetServerId: string }
  | { readonly type: RelayMessageType.OPEN_CANCEL; readonly requestNonce: Buffer; readonly targetServerId: string }
  | { readonly type: RelayMessageType.OPEN_RESPONSE; readonly status: RelayStatus; readonly requestNonce: Buffer; readonly targetServerId: string; readonly circuitId: Buffer }
  | { readonly type: RelayMessageType.INCOMING_CIRCUIT; readonly circuitId: Buffer; readonly targetServerId: string }
  | { readonly type: RelayMessageType.CIRCUIT_ACCEPT; readonly status: RelayStatus; readonly circuitId: Buffer; readonly targetServerId: string }
  | { readonly type: RelayMessageType.DATA; readonly circuitId: Buffer; readonly payload: Buffer }
  | { readonly type: RelayMessageType.CLOSE; readonly circuitId: Buffer; readonly reason: RelayCloseReason }
  | { readonly type: RelayMessageType.CIRCUIT_RENEW; readonly circuitId: Buffer; readonly renewNonce: Buffer }
  | { readonly type: RelayMessageType.CIRCUIT_RENEW_RESULT; readonly status: RelayStatus; readonly circuitId: Buffer; readonly renewNonce: Buffer }

const SERVER_BYTES = RENDEZVOUS_SERVER_ID_BYTES
const OPEN_REQUEST_BYTES = 2 + RELAY_REQUEST_NONCE_BYTES + SERVER_BYTES
const OPEN_RESPONSE_BYTES = 3 + RELAY_REQUEST_NONCE_BYTES + SERVER_BYTES + RELAY_CIRCUIT_ID_BYTES
const ZERO_CIRCUIT_ID = Buffer.alloc(RELAY_CIRCUIT_ID_BYTES)

function protocolError(): never {
  throw new PeerRelayError('RELAY_PROTOCOL_INVALID')
}

function assertFixed(buffer: Buffer, bytes: number): void {
  if (!Buffer.isBuffer(buffer) || buffer.length !== bytes) protocolError()
}

function assertServerId(serverId: string): void {
  if (!isCanonicalServerId(serverId)) protocolError()
}

function assertStatus(status: number): asserts status is RelayStatus {
  if (status !== RelayStatus.READY && status !== RelayStatus.NOT_AVAILABLE) protocolError()
}

function assertCircuitId(circuitId: Buffer, allowZero = false): void {
  assertFixed(circuitId, RELAY_CIRCUIT_ID_BYTES)
  if (!allowZero && circuitId.equals(ZERO_CIRCUIT_ID)) protocolError()
}

function header(type: RelayMessageType, bytes: number): Buffer {
  const result = Buffer.alloc(bytes)
  result.writeUInt8(RELAY_PROTOCOL_VERSION, 0)
  result.writeUInt8(type, 1)
  return result
}

export function encodeRelayMessage(message: RelayMessage): Buffer {
  switch (message.type) {
    case RelayMessageType.REGISTER_BEGIN:
    case RelayMessageType.UNREGISTER: {
      assertServerId(message.targetServerId)
      const result = header(message.type, 2 + SERVER_BYTES)
      result.write(message.targetServerId, 2, SERVER_BYTES, 'ascii')
      return result
    }
    case RelayMessageType.REGISTER_CHALLENGE: {
      assertServerId(message.targetServerId)
      assertServerId(message.relayServerId)
      assertServerId(message.outerDeviceFingerprint)
      assertFixed(message.challenge, RELAY_CHALLENGE_BYTES)
      assertFixed(message.channelBinding, RELAY_CHANNEL_BINDING_BYTES)
      const result = header(message.type, 2 + SERVER_BYTES * 3 + RELAY_CHALLENGE_BYTES + RELAY_CHANNEL_BINDING_BYTES)
      let offset = 2
      result.write(message.targetServerId, offset, SERVER_BYTES, 'ascii'); offset += SERVER_BYTES
      message.challenge.copy(result, offset); offset += RELAY_CHALLENGE_BYTES
      result.write(message.relayServerId, offset, SERVER_BYTES, 'ascii'); offset += SERVER_BYTES
      message.channelBinding.copy(result, offset); offset += RELAY_CHANNEL_BINDING_BYTES
      result.write(message.outerDeviceFingerprint, offset, SERVER_BYTES, 'ascii')
      return result
    }
    case RelayMessageType.REGISTER_PROOF: {
      assertServerId(message.targetServerId)
      assertFixed(message.targetServerPublicKey, RELAY_ED25519_PUBLIC_KEY_BYTES)
      assertFixed(message.challenge, RELAY_CHALLENGE_BYTES)
      assertFixed(message.signature, RELAY_ED25519_SIGNATURE_BYTES)
      const result = header(message.type, 2 + SERVER_BYTES + RELAY_ED25519_PUBLIC_KEY_BYTES + RELAY_CHALLENGE_BYTES + RELAY_ED25519_SIGNATURE_BYTES)
      let offset = 2
      result.write(message.targetServerId, offset, SERVER_BYTES, 'ascii'); offset += SERVER_BYTES
      message.targetServerPublicKey.copy(result, offset); offset += RELAY_ED25519_PUBLIC_KEY_BYTES
      message.challenge.copy(result, offset); offset += RELAY_CHALLENGE_BYTES
      message.signature.copy(result, offset)
      return result
    }
    case RelayMessageType.REGISTER_RESULT: {
      assertServerId(message.targetServerId)
      assertStatus(message.status)
      if (!Number.isInteger(message.lifetimeSeconds) || message.lifetimeSeconds < 0 || message.lifetimeSeconds > RELAY_TARGET_REGISTRATION_MAX_LIFETIME_SECONDS) protocolError()
      if (message.status === RelayStatus.NOT_AVAILABLE && message.lifetimeSeconds !== 0) protocolError()
      const result = header(message.type, 3 + SERVER_BYTES + 2)
      result.writeUInt8(message.status, 2)
      result.write(message.targetServerId, 3, SERVER_BYTES, 'ascii')
      result.writeUInt16BE(message.lifetimeSeconds, 3 + SERVER_BYTES)
      return result
    }
    case RelayMessageType.OPEN_REQUEST:
    case RelayMessageType.OPEN_CANCEL: {
      assertServerId(message.targetServerId)
      assertFixed(message.requestNonce, RELAY_REQUEST_NONCE_BYTES)
      const result = header(message.type, OPEN_REQUEST_BYTES)
      message.requestNonce.copy(result, 2)
      result.write(message.targetServerId, 2 + RELAY_REQUEST_NONCE_BYTES, SERVER_BYTES, 'ascii')
      return result
    }
    case RelayMessageType.OPEN_RESPONSE: {
      assertStatus(message.status)
      assertServerId(message.targetServerId)
      assertFixed(message.requestNonce, RELAY_REQUEST_NONCE_BYTES)
      assertCircuitId(message.circuitId, message.status === RelayStatus.NOT_AVAILABLE)
      if (message.status === RelayStatus.NOT_AVAILABLE && !message.circuitId.equals(ZERO_CIRCUIT_ID)) protocolError()
      const result = header(message.type, OPEN_RESPONSE_BYTES)
      result.writeUInt8(message.status, 2)
      message.requestNonce.copy(result, 3)
      result.write(message.targetServerId, 3 + RELAY_REQUEST_NONCE_BYTES, SERVER_BYTES, 'ascii')
      message.circuitId.copy(result, 3 + RELAY_REQUEST_NONCE_BYTES + SERVER_BYTES)
      return result
    }
    case RelayMessageType.INCOMING_CIRCUIT: {
      assertCircuitId(message.circuitId)
      assertServerId(message.targetServerId)
      const result = header(message.type, 2 + RELAY_CIRCUIT_ID_BYTES + SERVER_BYTES)
      message.circuitId.copy(result, 2)
      result.write(message.targetServerId, 2 + RELAY_CIRCUIT_ID_BYTES, SERVER_BYTES, 'ascii')
      return result
    }
    case RelayMessageType.CIRCUIT_ACCEPT: {
      assertStatus(message.status)
      assertCircuitId(message.circuitId)
      assertServerId(message.targetServerId)
      const result = header(message.type, 3 + RELAY_CIRCUIT_ID_BYTES + SERVER_BYTES)
      result.writeUInt8(message.status, 2)
      message.circuitId.copy(result, 3)
      result.write(message.targetServerId, 3 + RELAY_CIRCUIT_ID_BYTES, SERVER_BYTES, 'ascii')
      return result
    }
    case RelayMessageType.DATA: {
      assertCircuitId(message.circuitId)
      if (!Buffer.isBuffer(message.payload) || message.payload.length < 1 || message.payload.length > MAX_RELAY_DATA_PAYLOAD_BYTES) protocolError()
      const result = header(message.type, 2 + RELAY_CIRCUIT_ID_BYTES + 2 + message.payload.length)
      message.circuitId.copy(result, 2)
      result.writeUInt16BE(message.payload.length, 2 + RELAY_CIRCUIT_ID_BYTES)
      message.payload.copy(result, 2 + RELAY_CIRCUIT_ID_BYTES + 2)
      return result
    }
    case RelayMessageType.CLOSE: {
      assertCircuitId(message.circuitId)
      if (!Object.values(RelayCloseReason).includes(message.reason)) protocolError()
      const result = header(message.type, 3 + RELAY_CIRCUIT_ID_BYTES)
      message.circuitId.copy(result, 2)
      result.writeUInt8(message.reason, 2 + RELAY_CIRCUIT_ID_BYTES)
      return result
    }
    case RelayMessageType.CIRCUIT_RENEW: {
      assertCircuitId(message.circuitId)
      assertFixed(message.renewNonce, RELAY_REQUEST_NONCE_BYTES)
      const result = header(message.type, 2 + RELAY_CIRCUIT_ID_BYTES + RELAY_REQUEST_NONCE_BYTES)
      message.circuitId.copy(result, 2)
      message.renewNonce.copy(result, 2 + RELAY_CIRCUIT_ID_BYTES)
      return result
    }
    case RelayMessageType.CIRCUIT_RENEW_RESULT: {
      assertStatus(message.status)
      assertCircuitId(message.circuitId)
      assertFixed(message.renewNonce, RELAY_REQUEST_NONCE_BYTES)
      const result = header(message.type, 3 + RELAY_CIRCUIT_ID_BYTES + RELAY_REQUEST_NONCE_BYTES)
      result.writeUInt8(message.status, 2)
      message.circuitId.copy(result, 3)
      message.renewNonce.copy(result, 3 + RELAY_CIRCUIT_ID_BYTES)
      return result
    }
  }
}

export function decodeRelayMessage(buffer: Buffer): RelayMessage {
  if (!Buffer.isBuffer(buffer) || buffer.length < 2 || buffer.readUInt8(0) !== RELAY_PROTOCOL_VERSION) protocolError()
  const type = buffer.readUInt8(1) as RelayMessageType
  if (type === RelayMessageType.REGISTER_BEGIN || type === RelayMessageType.UNREGISTER) {
    assertFixed(buffer, 2 + SERVER_BYTES)
    const targetServerId = buffer.subarray(2).toString('ascii'); assertServerId(targetServerId)
    return Object.freeze({ type, targetServerId })
  }
  if (type === RelayMessageType.REGISTER_CHALLENGE) {
    assertFixed(buffer, 2 + SERVER_BYTES * 3 + RELAY_CHALLENGE_BYTES + RELAY_CHANNEL_BINDING_BYTES)
    let offset = 2
    const targetServerId = buffer.subarray(offset, offset += SERVER_BYTES).toString('ascii')
    const challenge = Buffer.from(buffer.subarray(offset, offset += RELAY_CHALLENGE_BYTES))
    const relayServerId = buffer.subarray(offset, offset += SERVER_BYTES).toString('ascii')
    const channelBinding = Buffer.from(buffer.subarray(offset, offset += RELAY_CHANNEL_BINDING_BYTES))
    const outerDeviceFingerprint = buffer.subarray(offset).toString('ascii')
    assertServerId(targetServerId); assertServerId(relayServerId); assertServerId(outerDeviceFingerprint)
    return Object.freeze({ type, targetServerId, challenge, relayServerId, channelBinding, outerDeviceFingerprint })
  }
  if (type === RelayMessageType.REGISTER_PROOF) {
    assertFixed(buffer, 2 + SERVER_BYTES + RELAY_ED25519_PUBLIC_KEY_BYTES + RELAY_CHALLENGE_BYTES + RELAY_ED25519_SIGNATURE_BYTES)
    let offset = 2
    const targetServerId = buffer.subarray(offset, offset += SERVER_BYTES).toString('ascii'); assertServerId(targetServerId)
    return Object.freeze({
      type,
      targetServerId,
      targetServerPublicKey: Buffer.from(buffer.subarray(offset, offset += RELAY_ED25519_PUBLIC_KEY_BYTES)),
      challenge: Buffer.from(buffer.subarray(offset, offset += RELAY_CHALLENGE_BYTES)),
      signature: Buffer.from(buffer.subarray(offset))
    })
  }
  if (type === RelayMessageType.REGISTER_RESULT) {
    assertFixed(buffer, 3 + SERVER_BYTES + 2)
    const status = buffer.readUInt8(2); assertStatus(status)
    const targetServerId = buffer.subarray(3, 3 + SERVER_BYTES).toString('ascii'); assertServerId(targetServerId)
    const lifetimeSeconds = buffer.readUInt16BE(3 + SERVER_BYTES)
    if (lifetimeSeconds > RELAY_TARGET_REGISTRATION_MAX_LIFETIME_SECONDS || (status === RelayStatus.NOT_AVAILABLE && lifetimeSeconds !== 0)) protocolError()
    return Object.freeze({ type, status, targetServerId, lifetimeSeconds })
  }
  if (type === RelayMessageType.OPEN_REQUEST || type === RelayMessageType.OPEN_CANCEL) {
    assertFixed(buffer, OPEN_REQUEST_BYTES)
    const targetServerId = buffer.subarray(2 + RELAY_REQUEST_NONCE_BYTES).toString('ascii'); assertServerId(targetServerId)
    return Object.freeze({ type, requestNonce: Buffer.from(buffer.subarray(2, 2 + RELAY_REQUEST_NONCE_BYTES)), targetServerId })
  }
  if (type === RelayMessageType.OPEN_RESPONSE) {
    assertFixed(buffer, OPEN_RESPONSE_BYTES)
    const status = buffer.readUInt8(2); assertStatus(status)
    const targetServerId = buffer.subarray(3 + RELAY_REQUEST_NONCE_BYTES, 3 + RELAY_REQUEST_NONCE_BYTES + SERVER_BYTES).toString('ascii'); assertServerId(targetServerId)
    const circuitId = Buffer.from(buffer.subarray(3 + RELAY_REQUEST_NONCE_BYTES + SERVER_BYTES)); assertCircuitId(circuitId, status === RelayStatus.NOT_AVAILABLE)
    if (status === RelayStatus.NOT_AVAILABLE && !circuitId.equals(ZERO_CIRCUIT_ID)) protocolError()
    return Object.freeze({ type, status, requestNonce: Buffer.from(buffer.subarray(3, 3 + RELAY_REQUEST_NONCE_BYTES)), targetServerId, circuitId })
  }
  if (type === RelayMessageType.INCOMING_CIRCUIT) {
    assertFixed(buffer, 2 + RELAY_CIRCUIT_ID_BYTES + SERVER_BYTES)
    const circuitId = Buffer.from(buffer.subarray(2, 2 + RELAY_CIRCUIT_ID_BYTES)); assertCircuitId(circuitId)
    const targetServerId = buffer.subarray(2 + RELAY_CIRCUIT_ID_BYTES).toString('ascii'); assertServerId(targetServerId)
    return Object.freeze({ type, circuitId, targetServerId })
  }
  if (type === RelayMessageType.CIRCUIT_ACCEPT) {
    assertFixed(buffer, 3 + RELAY_CIRCUIT_ID_BYTES + SERVER_BYTES)
    const status = buffer.readUInt8(2); assertStatus(status)
    const circuitId = Buffer.from(buffer.subarray(3, 3 + RELAY_CIRCUIT_ID_BYTES)); assertCircuitId(circuitId)
    const targetServerId = buffer.subarray(3 + RELAY_CIRCUIT_ID_BYTES).toString('ascii'); assertServerId(targetServerId)
    return Object.freeze({ type, status, circuitId, targetServerId })
  }
  if (type === RelayMessageType.DATA) {
    if (buffer.length < 2 + RELAY_CIRCUIT_ID_BYTES + 2 || buffer.length > 2 + RELAY_CIRCUIT_ID_BYTES + 2 + MAX_RELAY_DATA_PAYLOAD_BYTES) protocolError()
    const circuitId = Buffer.from(buffer.subarray(2, 2 + RELAY_CIRCUIT_ID_BYTES)); assertCircuitId(circuitId)
    const length = buffer.readUInt16BE(2 + RELAY_CIRCUIT_ID_BYTES)
    if (length < 1 || length > MAX_RELAY_DATA_PAYLOAD_BYTES || buffer.length !== 2 + RELAY_CIRCUIT_ID_BYTES + 2 + length) protocolError()
    return Object.freeze({ type, circuitId, payload: Buffer.from(buffer.subarray(2 + RELAY_CIRCUIT_ID_BYTES + 2)) })
  }
  if (type === RelayMessageType.CLOSE) {
    assertFixed(buffer, 3 + RELAY_CIRCUIT_ID_BYTES)
    const circuitId = Buffer.from(buffer.subarray(2, 2 + RELAY_CIRCUIT_ID_BYTES)); assertCircuitId(circuitId)
    const reason = buffer.readUInt8(2 + RELAY_CIRCUIT_ID_BYTES)
    if (reason < RelayCloseReason.NORMAL || reason > RelayCloseReason.TIMEOUT) protocolError()
    return Object.freeze({ type, circuitId, reason }) as RelayMessage
  }
  if (type === RelayMessageType.CIRCUIT_RENEW) {
    assertFixed(buffer, 2 + RELAY_CIRCUIT_ID_BYTES + RELAY_REQUEST_NONCE_BYTES)
    const circuitId = Buffer.from(buffer.subarray(2, 2 + RELAY_CIRCUIT_ID_BYTES)); assertCircuitId(circuitId)
    return Object.freeze({ type, circuitId, renewNonce: Buffer.from(buffer.subarray(2 + RELAY_CIRCUIT_ID_BYTES)) })
  }
  if (type === RelayMessageType.CIRCUIT_RENEW_RESULT) {
    assertFixed(buffer, 3 + RELAY_CIRCUIT_ID_BYTES + RELAY_REQUEST_NONCE_BYTES)
    const status = buffer.readUInt8(2); assertStatus(status)
    const circuitId = Buffer.from(buffer.subarray(3, 3 + RELAY_CIRCUIT_ID_BYTES)); assertCircuitId(circuitId)
    return Object.freeze({ type, status, circuitId, renewNonce: Buffer.from(buffer.subarray(3 + RELAY_CIRCUIT_ID_BYTES)) })
  }
  return protocolError()
}

export function createRelayRegistrationTranscript(options: {
  readonly relayServerId: string
  readonly targetServerId: string
  readonly targetServerPublicKey: Buffer
  readonly challenge: Buffer
  readonly channelBinding: Buffer
  readonly outerDeviceFingerprint: string
}): Buffer {
  assertServerId(options.relayServerId); assertServerId(options.targetServerId); assertServerId(options.outerDeviceFingerprint)
  assertFixed(options.targetServerPublicKey, RELAY_ED25519_PUBLIC_KEY_BYTES)
  assertFixed(options.challenge, RELAY_CHALLENGE_BYTES); assertFixed(options.channelBinding, RELAY_CHANNEL_BINDING_BYTES)
  const domain = Buffer.from(RELAY_REGISTRATION_SIGNATURE_DOMAIN, 'utf8')
  return Buffer.concat([
    Buffer.from([RELAY_PROTOCOL_VERSION, domain.length]), domain,
    Buffer.from(options.relayServerId, 'ascii'), Buffer.from(options.targetServerId, 'ascii'),
    options.targetServerPublicKey, options.challenge, options.channelBinding,
    Buffer.from(options.outerDeviceFingerprint, 'ascii')
  ])
}

function canonicalEd25519PublicKey(publicKeyDer: Buffer): KeyObject {
  try {
    assertFixed(publicKeyDer, RELAY_ED25519_PUBLIC_KEY_BYTES)
    const key = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' })
    const canonical = Buffer.from(key.export({ format: 'der', type: 'spki' }))
    if (key.asymmetricKeyType !== 'ed25519' || !canonical.equals(publicKeyDer)) throw new Error()
    return key
  } catch (cause) {
    throw new PeerRelayError('RELAY_REGISTRATION_PROOF_INVALID', { cause })
  }
}

function deriveServerId(publicKey: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
}

class SlidingRateLimiter {
  private readonly events: number[] = []
  constructor(private readonly limit: number, private readonly now: () => number) {}
  consume(): boolean {
    const current = this.now()
    while (this.events.length && current - this.events[0]! >= RELAY_RATE_WINDOW_MS) this.events.shift()
    if (this.events.length >= this.limit) return false
    this.events.push(current)
    return true
  }
}

export type RelayTransportStream = MasqueradaTransportStream
const relayStreams = new WeakSet<object>()

interface LocalStreamEntry {
  readonly handle: MasqueradaTransportStreamHandle
  readonly targetServerId: string
  readonly circuitId: Buffer
  readonly autoRenew: boolean
  renewTimer?: ReturnType<typeof setTimeout>
  pendingRenew?: {
    readonly nonce: Buffer
    readonly timer: ReturnType<typeof setTimeout>
  }
}

interface PendingOpen {
  readonly targetServerId: string
  readonly resolve: (stream: RelayTransportStream) => void
  readonly reject: (error: PeerRelayError) => void
  readonly timer: ReturnType<typeof setTimeout>
  readonly signal?: AbortSignal
  readonly onAbort: () => void
  readonly autoRenew: boolean
}

interface PendingLocalRegistration {
  readonly targetServerId: string
  readonly targetServerPublicKey: Buffer
  readonly targetServerPrivateKey: KeyObject
  readonly outerDeviceFingerprint: string
  readonly expectedRelayServerId: string
  readonly onIncomingCircuit: (stream: RelayTransportStream) => void | Promise<void>
  readonly resolve: (registration: RelayTargetRegistration) => void
  readonly reject: (error: PeerRelayError) => void
  readonly timer: ReturnType<typeof setTimeout>
  readonly replacing?: RelayTargetRegistration
}

const REGISTRATION_TOKEN = Symbol('RelayTargetRegistration')
const registrations = new WeakSet<object>()

export class RelayTargetRegistration {
  private closed = false
  constructor(
    token: symbol,
    readonly targetServerId: string,
    readonly expiresAtMs: number,
    private readonly closeRegistration: () => void
  ) {
    if (token !== REGISTRATION_TOKEN) throw new PeerRelayError('RELAY_REGISTRATION_INVALID')
    registrations.add(this)
  }
  close(): void {
    if (this.closed) return
    this.closed = true
    this.closeRegistration()
  }
  isClosed(): boolean { return this.closed }
  retire(token: symbol): void {
    if (token === REGISTRATION_TOKEN) this.closed = true
  }
}

export function isRelayTargetRegistration(value: unknown): value is RelayTargetRegistration {
  return typeof value === 'object' && value !== null && registrations.has(value)
}

interface ServiceChallenge {
  readonly targetServerId: string
  readonly challenge: Buffer
  readonly channelBinding: Buffer
  readonly outerDeviceFingerprint: string
  readonly expiresAt: number
  readonly replacesExisting: boolean
}

interface ServiceRegistration {
  readonly targetServerId: string
  readonly endpoint: PeerRelayEndpoint
  readonly expiresAt: number
  readonly timer: ReturnType<typeof setTimeout>
}

type CircuitState = 'OPENING' | 'ACTIVE' | 'CLOSING' | 'CLOSED'

interface ServiceCircuit {
  readonly key: string
  readonly circuitId: Buffer
  readonly targetServerId: string
  readonly requester: PeerRelayEndpoint
  readonly target: PeerRelayEndpoint
  readonly requestNonce: Buffer
  readonly createdAt: number
  leaseExpiresAt: number
  lastActivity: number
  bytes: number
  queuedRequesterToTarget: number
  queuedTargetToRequester: number
  state: CircuitState
  timer: ReturnType<typeof setTimeout>
  openTimer: ReturnType<typeof setTimeout>
  readonly resourceReservation: ConnectivityResourceReservation
}

export interface PeerRelayServiceOptions {
  readonly relayServerId: string
  readonly nowMs?: () => number
  readonly random?: (bytes: number) => Buffer
  readonly registrationLifetimeSeconds?: number
  readonly openTimeoutMs?: number
  readonly maxCircuitsGlobal?: number
  readonly maxCircuitsPerChannel?: number
  readonly maxQueuedBytes?: number
  readonly maxGlobalQueuedBytes?: number
  readonly maxBytesPerCircuit?: number
  readonly maxLifetimeMs?: number
  readonly idleTimeoutMs?: number
  readonly resourceGovernor?: ConnectivityResourceGovernor
}

/** In-memory relay switch. It only binds attached authorized channels; it performs no network I/O. */
export class PeerRelayService {
  readonly relayServerId: string
  private readonly challenges = new Map<PeerRelayEndpoint, ServiceChallenge>()
  private readonly targetRegistrations = new Map<string, ServiceRegistration>()
  private readonly circuits = new Map<string, ServiceCircuit>()
  private globalQueuedBytes = 0
  private readonly globalOpenRate: SlidingRateLimiter
  private readonly globalDataRate: SlidingRateLimiter
  private readonly now: () => number
  private readonly random: (bytes: number) => Buffer
  private readonly registrationLifetimeSeconds: number
  private readonly openTimeoutMs: number
  private readonly maxCircuitsGlobal: number
  private readonly maxCircuitsPerChannel: number
  private readonly maxQueuedBytes: number
  private readonly maxGlobalQueuedBytes: number
  private readonly maxBytesPerCircuit: number
  private readonly maxLifetimeMs: number
  private readonly idleTimeoutMs: number
  private readonly resourceGovernor: ConnectivityResourceGovernor

  constructor(options: PeerRelayServiceOptions) {
    assertServerId(options.relayServerId)
    this.relayServerId = options.relayServerId
    this.now = options.nowMs ?? (() => performance.now())
    this.random = options.random ?? randomBytes
    this.registrationLifetimeSeconds = options.registrationLifetimeSeconds ?? RELAY_TARGET_REGISTRATION_MAX_LIFETIME_SECONDS
    this.openTimeoutMs = options.openTimeoutMs ?? RELAY_OPEN_TIMEOUT_MS
    this.maxCircuitsGlobal = options.maxCircuitsGlobal ?? MAX_RELAY_CIRCUITS_GLOBAL
    this.maxCircuitsPerChannel = options.maxCircuitsPerChannel ?? MAX_RELAY_CIRCUITS_PER_CHANNEL
    this.maxQueuedBytes = options.maxQueuedBytes ?? MAX_RELAY_QUEUED_BYTES
    this.maxGlobalQueuedBytes = options.maxGlobalQueuedBytes ?? MAX_RELAY_GLOBAL_QUEUED_BYTES
    this.maxBytesPerCircuit = options.maxBytesPerCircuit ?? MAX_RELAY_BYTES_PER_CIRCUIT
    this.maxLifetimeMs = options.maxLifetimeMs ?? RELAY_CIRCUIT_MAX_LIFETIME_MS
    this.idleTimeoutMs = options.idleTimeoutMs ?? RELAY_CIRCUIT_IDLE_TIMEOUT_MS
    this.resourceGovernor = options.resourceGovernor ?? defaultConnectivityResourceGovernor
    if (
      this.registrationLifetimeSeconds < 1 || this.registrationLifetimeSeconds > RELAY_TARGET_REGISTRATION_MAX_LIFETIME_SECONDS ||
      this.openTimeoutMs < 1 || this.openTimeoutMs > MAX_RELAY_OPEN_TIMEOUT_MS ||
      this.maxCircuitsGlobal < 1 || this.maxCircuitsGlobal > MAX_RELAY_CIRCUITS_GLOBAL ||
      this.maxCircuitsPerChannel < 1 || this.maxCircuitsPerChannel > MAX_RELAY_CIRCUITS_PER_CHANNEL ||
      this.maxQueuedBytes < 1 || this.maxQueuedBytes > MAX_RELAY_QUEUED_BYTES ||
      this.maxGlobalQueuedBytes < 1 || this.maxGlobalQueuedBytes > MAX_RELAY_GLOBAL_QUEUED_BYTES ||
      this.maxBytesPerCircuit < 1 || this.maxBytesPerCircuit > MAX_RELAY_BYTES_PER_CIRCUIT_HARD ||
      this.maxLifetimeMs < 1 || this.maxLifetimeMs > RELAY_CIRCUIT_MAX_LIFETIME_MS ||
      this.idleTimeoutMs < 1 || this.idleTimeoutMs > RELAY_CIRCUIT_IDLE_TIMEOUT_MS
    ) protocolError()
    this.globalOpenRate = new SlidingRateLimiter(MAX_RELAY_OPENS_GLOBAL, this.now)
    this.globalDataRate = new SlidingRateLimiter(MAX_RELAY_DATA_MESSAGES_GLOBAL, this.now)
  }

  beginRegistration(endpoint: PeerRelayEndpoint, targetServerId: string): RelayMessage {
    assertServerId(targetServerId)
    const current = this.targetRegistrations.get(targetServerId)
    const replacesExisting = current?.endpoint === endpoint
    if (
      !endpoint.peerDeviceFingerprint || !endpoint.registrationRate.consume() || this.challenges.has(endpoint) ||
      (current !== undefined && !replacesExisting) ||
      (!replacesExisting && this.countRegistrations(endpoint) >= MAX_RELAY_REGISTRATIONS_PER_CHANNEL)
    ) {
      return { type: RelayMessageType.REGISTER_RESULT, status: RelayStatus.NOT_AVAILABLE, targetServerId, lifetimeSeconds: 0 }
    }
    const challenge = this.randomExact(RELAY_CHALLENGE_BYTES)
    const channelBinding = this.randomExact(RELAY_CHANNEL_BINDING_BYTES)
    const record: ServiceChallenge = {
      targetServerId,
      challenge,
      channelBinding,
      outerDeviceFingerprint: endpoint.peerDeviceFingerprint,
      expiresAt: this.now() + RELAY_REGISTRATION_CHALLENGE_TTL_MS,
      replacesExisting
    }
    this.challenges.set(endpoint, record)
    return {
      type: RelayMessageType.REGISTER_CHALLENGE,
      targetServerId,
      challenge,
      relayServerId: this.relayServerId,
      channelBinding,
      outerDeviceFingerprint: record.outerDeviceFingerprint
    }
  }

  proveRegistration(endpoint: PeerRelayEndpoint, proof: Extract<RelayMessage, { type: RelayMessageType.REGISTER_PROOF }>): RelayMessage {
    const challenge = this.challenges.get(endpoint)
    this.challenges.delete(endpoint)
    if (!challenge || this.now() > challenge.expiresAt) throw new PeerRelayError('RELAY_REGISTRATION_CHALLENGE_EXPIRED')
    if (challenge.targetServerId !== proof.targetServerId || !challenge.challenge.equals(proof.challenge)) {
      throw new PeerRelayError('RELAY_REGISTRATION_PROOF_INVALID')
    }
    const key = canonicalEd25519PublicKey(proof.targetServerPublicKey)
    if (deriveServerId(proof.targetServerPublicKey) !== proof.targetServerId) throw new PeerRelayError('RELAY_REGISTRATION_PROOF_INVALID')
    const transcript = createRelayRegistrationTranscript({
      relayServerId: this.relayServerId,
      targetServerId: proof.targetServerId,
      targetServerPublicKey: proof.targetServerPublicKey,
      challenge: proof.challenge,
      channelBinding: challenge.channelBinding,
      outerDeviceFingerprint: challenge.outerDeviceFingerprint
    })
    const current = this.targetRegistrations.get(proof.targetServerId)
    if (
      !verify(null, transcript, key, proof.signature) ||
      (current !== undefined && (!challenge.replacesExisting || current.endpoint !== endpoint))
    ) {
      throw new PeerRelayError('RELAY_REGISTRATION_PROOF_INVALID')
    }
    const expiresAt = this.now() + this.registrationLifetimeSeconds * 1000
    const timer = setTimeout(() => this.removeRegistration(proof.targetServerId, RelayCloseReason.TIMEOUT), this.registrationLifetimeSeconds * 1000)
    if (current) clearTimeout(current.timer)
    this.targetRegistrations.set(proof.targetServerId, { targetServerId: proof.targetServerId, endpoint, expiresAt, timer })
    return { type: RelayMessageType.REGISTER_RESULT, status: RelayStatus.READY, targetServerId: proof.targetServerId, lifetimeSeconds: this.registrationLifetimeSeconds }
  }

  unregister(endpoint: PeerRelayEndpoint, targetServerId: string): void {
    const registration = this.targetRegistrations.get(targetServerId)
    if (registration?.endpoint === endpoint) this.removeRegistration(targetServerId, RelayCloseReason.PEER_CLOSED)
  }

  async open(endpoint: PeerRelayEndpoint, request: Extract<RelayMessage, { type: RelayMessageType.OPEN_REQUEST }>): Promise<void> {
    const registration = this.getFreshRegistration(request.targetServerId)
    if (
      !registration || !endpoint.openRate.consume() || !this.globalOpenRate.consume() ||
      this.circuits.size >= this.maxCircuitsGlobal || this.countCircuits(endpoint) >= this.maxCircuitsPerChannel ||
      this.countCircuits(registration.endpoint) >= this.maxCircuitsPerChannel
    ) {
      await endpoint.sendControl({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.NOT_AVAILABLE, requestNonce: request.requestNonce, targetServerId: request.targetServerId, circuitId: ZERO_CIRCUIT_ID })
      return
    }
    const circuitId = this.uniqueCircuitId()
    let resourceReservation: ConnectivityResourceReservation
    try {
      resourceReservation = this.resourceGovernor.reserve('RELAY_CIRCUIT')
    } catch {
      await endpoint.sendControl({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.NOT_AVAILABLE, requestNonce: request.requestNonce, targetServerId: request.targetServerId, circuitId: ZERO_CIRCUIT_ID })
      return
    }
    const key = circuitId.toString('hex')
    const now = this.now()
    const placeholder = setTimeout(() => {}, 1)
    const circuit: ServiceCircuit = {
      key, circuitId, targetServerId: request.targetServerId, requester: endpoint,
      target: registration.endpoint, requestNonce: Buffer.from(request.requestNonce), createdAt: now,
      leaseExpiresAt: now + this.maxLifetimeMs,
      lastActivity: now, bytes: 0, queuedRequesterToTarget: 0, queuedTargetToRequester: 0,
      state: 'OPENING', timer: placeholder, openTimer: placeholder, resourceReservation
    }
    clearTimeout(placeholder)
    circuit.timer = setTimeout(() => this.closeCircuit(circuit, RelayCloseReason.TIMEOUT), this.idleTimeoutMs)
    circuit.openTimer = setTimeout(() => {
      if (circuit.state !== 'OPENING') return
      void circuit.requester.sendControl({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.NOT_AVAILABLE, requestNonce: circuit.requestNonce, targetServerId: circuit.targetServerId, circuitId: ZERO_CIRCUIT_ID }).finally(() => this.closeCircuit(circuit, RelayCloseReason.TIMEOUT, false))
    }, this.openTimeoutMs)
    this.circuits.set(key, circuit)
    try {
      await registration.endpoint.sendControl({ type: RelayMessageType.INCOMING_CIRCUIT, circuitId, targetServerId: request.targetServerId })
    } catch {
      this.closeCircuit(circuit, RelayCloseReason.PEER_CLOSED, false)
      await endpoint.sendControl({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.NOT_AVAILABLE, requestNonce: request.requestNonce, targetServerId: request.targetServerId, circuitId: ZERO_CIRCUIT_ID })
    }
  }

  async accept(endpoint: PeerRelayEndpoint, message: Extract<RelayMessage, { type: RelayMessageType.CIRCUIT_ACCEPT }>): Promise<void> {
    const circuit = this.circuits.get(message.circuitId.toString('hex'))
    if (!circuit || circuit.target !== endpoint || circuit.targetServerId !== message.targetServerId || circuit.state !== 'OPENING') {
      throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
    }
    clearTimeout(circuit.openTimer)
    if (message.status !== RelayStatus.READY) {
      await circuit.requester.sendControl({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.NOT_AVAILABLE, requestNonce: circuit.requestNonce, targetServerId: circuit.targetServerId, circuitId: ZERO_CIRCUIT_ID })
      this.closeCircuit(circuit, RelayCloseReason.PEER_CLOSED, false)
      return
    }
    circuit.state = 'ACTIVE'
    this.refreshCircuitTimer(circuit)
    await circuit.requester.sendControl({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.READY, requestNonce: circuit.requestNonce, targetServerId: circuit.targetServerId, circuitId: circuit.circuitId })
  }

  cancelOpen(endpoint: PeerRelayEndpoint, message: Extract<RelayMessage, { type: RelayMessageType.OPEN_CANCEL }>): void {
    for (const circuit of this.circuits.values()) {
      if (
        circuit.requester === endpoint && circuit.targetServerId === message.targetServerId &&
        circuit.requestNonce.equals(message.requestNonce) && circuit.state === 'OPENING'
      ) {
        this.closeCircuit(circuit, RelayCloseReason.PEER_CLOSED)
        return
      }
    }
  }

  async renewCircuit(
    endpoint: PeerRelayEndpoint,
    message: Extract<RelayMessage, { type: RelayMessageType.CIRCUIT_RENEW }>
  ): Promise<void> {
    const circuit = this.circuits.get(message.circuitId.toString('hex'))
    const registration = circuit ? this.getFreshRegistration(circuit.targetServerId) : null
    if (
      !circuit || circuit.requester !== endpoint || circuit.state !== 'ACTIVE' ||
      !registration || registration.endpoint !== circuit.target
    ) {
      if (circuit?.requester === endpoint) {
        await endpoint.sendControl({
          type: RelayMessageType.CIRCUIT_RENEW_RESULT,
          status: RelayStatus.NOT_AVAILABLE,
          circuitId: message.circuitId,
          renewNonce: message.renewNonce
        })
      } else {
        throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
      }
      return
    }
    circuit.leaseExpiresAt = this.now() + this.maxLifetimeMs
    this.refreshCircuitTimer(circuit)
    await endpoint.sendControl({
      type: RelayMessageType.CIRCUIT_RENEW_RESULT,
      status: RelayStatus.READY,
      circuitId: message.circuitId,
      renewNonce: message.renewNonce
    })
  }

  async data(endpoint: PeerRelayEndpoint, message: Extract<RelayMessage, { type: RelayMessageType.DATA }>): Promise<void> {
    const circuit = this.circuits.get(message.circuitId.toString('hex'))
    if (!circuit || (circuit.requester !== endpoint && circuit.target !== endpoint)) throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
    if (circuit.state !== 'ACTIVE') {
      this.closeCircuit(circuit, RelayCloseReason.PROTOCOL_ERROR)
      throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
    }
    if (!endpoint.dataRate.consume() || !this.globalDataRate.consume()) {
      this.closeCircuit(circuit, RelayCloseReason.RESOURCE_LIMIT)
      throw new PeerRelayError('RELAY_RESOURCE_LIMIT')
    }
    const fromRequester = circuit.requester === endpoint
    const queued = fromRequester ? circuit.queuedRequesterToTarget : circuit.queuedTargetToRequester
    if (queued + message.payload.length > this.maxQueuedBytes || this.globalQueuedBytes + message.payload.length > this.maxGlobalQueuedBytes || circuit.bytes + message.payload.length > this.maxBytesPerCircuit) {
      this.closeCircuit(circuit, RelayCloseReason.RESOURCE_LIMIT)
      throw new PeerRelayError('RELAY_RESOURCE_LIMIT')
    }
    let queuedReservation: ConnectivityResourceReservation
    try {
      queuedReservation = this.resourceGovernor.reserve('RELAY_QUEUED_BYTES', message.payload.length)
    } catch {
      this.closeCircuit(circuit, RelayCloseReason.RESOURCE_LIMIT)
      throw new PeerRelayError('RELAY_RESOURCE_LIMIT')
    }
    if (fromRequester) circuit.queuedRequesterToTarget += message.payload.length
    else circuit.queuedTargetToRequester += message.payload.length
    this.globalQueuedBytes += message.payload.length
    circuit.bytes += message.payload.length
    circuit.lastActivity = this.now()
    this.refreshCircuitTimer(circuit)
    try {
      await (fromRequester ? circuit.target : circuit.requester).sendControl(message)
    } finally {
      if (fromRequester) circuit.queuedRequesterToTarget -= message.payload.length
      else circuit.queuedTargetToRequester -= message.payload.length
      this.globalQueuedBytes -= message.payload.length
      queuedReservation.release()
    }
  }

  closeFrom(endpoint: PeerRelayEndpoint, message: Extract<RelayMessage, { type: RelayMessageType.CLOSE }>): void {
    const circuit = this.circuits.get(message.circuitId.toString('hex'))
    if (!circuit || (circuit.requester !== endpoint && circuit.target !== endpoint)) throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
    this.closeCircuit(circuit, message.reason, true, endpoint)
  }

  detach(endpoint: PeerRelayEndpoint): void {
    this.challenges.delete(endpoint)
    for (const [serverId, registration] of this.targetRegistrations) {
      if (registration.endpoint === endpoint) this.removeRegistration(serverId, RelayCloseReason.PEER_CLOSED)
    }
    for (const circuit of Array.from(this.circuits.values())) {
      if (circuit.requester === endpoint || circuit.target === endpoint) this.closeCircuit(circuit, RelayCloseReason.PEER_CLOSED, true, endpoint)
    }
  }

  get activeCircuitCount(): number { return this.circuits.size }
  hasRegistration(targetServerId: string): boolean { return this.getFreshRegistration(targetServerId) !== null }

  private randomExact(bytes: number): Buffer {
    const result = this.random(bytes)
    if (!Buffer.isBuffer(result) || result.length !== bytes) throw new PeerRelayError('RELAY_RESOURCE_LIMIT')
    return Buffer.from(result)
  }
  private uniqueCircuitId(): Buffer {
    for (let attempt = 0; attempt < 4; attempt++) {
      const id = this.randomExact(RELAY_CIRCUIT_ID_BYTES)
      if (!id.equals(ZERO_CIRCUIT_ID) && !this.circuits.has(id.toString('hex'))) return id
    }
    throw new PeerRelayError('RELAY_RESOURCE_LIMIT')
  }
  private countRegistrations(endpoint: PeerRelayEndpoint): number {
    let count = 0
    for (const registration of this.targetRegistrations.values()) if (registration.endpoint === endpoint) count++
    return count
  }
  private countCircuits(endpoint: PeerRelayEndpoint): number {
    let count = 0
    for (const circuit of this.circuits.values()) if (circuit.requester === endpoint || circuit.target === endpoint) count++
    return count
  }
  private getFreshRegistration(serverId: string): ServiceRegistration | null {
    const registration = this.targetRegistrations.get(serverId)
    if (!registration) return null
    if (this.now() >= registration.expiresAt || registration.endpoint.closed) {
      this.removeRegistration(serverId, RelayCloseReason.TIMEOUT)
      return null
    }
    return registration
  }
  private removeRegistration(serverId: string, reason: RelayCloseReason): void {
    const registration = this.targetRegistrations.get(serverId)
    if (!registration) return
    clearTimeout(registration.timer)
    this.targetRegistrations.delete(serverId)
    for (const circuit of Array.from(this.circuits.values())) if (circuit.targetServerId === serverId) this.closeCircuit(circuit, reason)
  }
  private refreshCircuitTimer(circuit: ServiceCircuit): void {
    clearTimeout(circuit.timer)
    const lifetimeRemaining = circuit.leaseExpiresAt - this.now()
    const idleRemaining = this.idleTimeoutMs - (this.now() - circuit.lastActivity)
    const remaining = Math.min(lifetimeRemaining, idleRemaining)
    if (remaining <= 0) {
      this.closeCircuit(circuit, lifetimeRemaining <= 0 ? RelayCloseReason.TIMEOUT : RelayCloseReason.TIMEOUT)
      return
    }
    circuit.timer = setTimeout(() => this.refreshCircuitTimer(circuit), remaining)
  }
  private closeCircuit(circuit: ServiceCircuit, reason: RelayCloseReason, notify = true, source?: PeerRelayEndpoint): void {
    if (circuit.state === 'CLOSED' || circuit.state === 'CLOSING') return
    circuit.state = 'CLOSING'
    clearTimeout(circuit.timer); clearTimeout(circuit.openTimer)
    this.circuits.delete(circuit.key)
    circuit.resourceReservation.release()
    if (notify) {
      if (source !== circuit.requester) void circuit.requester.sendControl({ type: RelayMessageType.CLOSE, circuitId: circuit.circuitId, reason }).catch(() => {})
      if (source !== circuit.target) void circuit.target.sendControl({ type: RelayMessageType.CLOSE, circuitId: circuit.circuitId, reason }).catch(() => {})
    }
    circuit.state = 'CLOSED'
  }
}

export interface CreatePeerRelayEndpointOptions {
  readonly channel: AuthorizedPeerChannel
  readonly service?: PeerRelayService
  readonly nowMs?: () => number
  readonly random?: (bytes: number) => Buffer
  /** Test/internal timing seam; production uses the fixed 300-second lease. */
  readonly circuitLeaseMs?: number
  readonly subsystem?: ConnectivitySubsystem
}

export interface RegisterRelayTargetOptions {
  readonly targetServerId: string
  readonly targetServerPublicKey: Buffer
  readonly targetServerPrivateKey: KeyObject
  readonly relayServerId: string
  readonly outerDeviceFingerprint: string
  readonly onIncomingCircuit: (stream: RelayTransportStream) => void | Promise<void>
  readonly timeoutMs?: number
}

export interface OpenRelayCircuitOptions {
  readonly timeoutMs?: number
  readonly signal?: AbortSignal
  /** Used by the 7.11 high-level orchestrator; low-level 7.10 remains finite by default. */
  readonly autoRenew?: boolean
}

const ENDPOINT_TOKEN = Symbol('PeerRelayEndpoint')
const endpoints = new WeakSet<object>()

export class PeerRelayEndpoint {
  readonly peerDeviceFingerprint?: string
  readonly openRate: SlidingRateLimiter
  readonly registrationRate: SlidingRateLimiter
  readonly dataRate: SlidingRateLimiter
  closed = false
  private readonly pendingOpens = new Map<string, PendingOpen>()
  private pendingRegistration?: PendingLocalRegistration
  private localRegistration?: { readonly registration: RelayTargetRegistration; readonly onIncomingCircuit: (stream: RelayTransportStream) => void | Promise<void>; readonly timer: ReturnType<typeof setTimeout> }
  private readonly streams = new Map<string, LocalStreamEntry>()
  private readonly removeMessageHandler: () => void
  private readonly removeCloseHandler: () => void
  private readonly now: () => number
  private readonly random: (bytes: number) => Buffer
  private readonly circuitLeaseMs: number
  private readonly endpointCloseHandlers = new Set<() => void>()
  private readonly removeSubsystemResource: () => void
  readonly relayPeerId?: string

  constructor(token: symbol, private readonly channel: AuthorizedPeerChannel, private readonly service: PeerRelayService | undefined, options: CreatePeerRelayEndpointOptions) {
    if (token !== ENDPOINT_TOKEN || !isAuthorizedPeerChannel(channel) || channel.isClosed()) throw new PeerRelayError('RELAY_NOT_AUTHORIZED')
    const binding = channel.getAuthorizationBinding()
    if (service && (binding.serverId !== service.relayServerId || !isCanonicalServerId(binding.peerDeviceFingerprint))) {
      throw new PeerRelayError('RELAY_NOT_AUTHORIZED')
    }
    this.peerDeviceFingerprint = binding.peerDeviceFingerprint
    this.relayPeerId = binding.serverId
    this.now = options.nowMs ?? (() => performance.now())
    this.random = options.random ?? randomBytes
    this.circuitLeaseMs = options.circuitLeaseMs ?? RELAY_CIRCUIT_MAX_LIFETIME_MS
    if (!Number.isInteger(this.circuitLeaseMs) || this.circuitLeaseMs < 2 || this.circuitLeaseMs > RELAY_CIRCUIT_MAX_LIFETIME_MS) {
      throw new PeerRelayError('RELAY_PROTOCOL_INVALID')
    }
    this.openRate = new SlidingRateLimiter(MAX_RELAY_OPENS_PER_CHANNEL, this.now)
    this.registrationRate = new SlidingRateLimiter(MAX_RELAY_REGISTRATION_ATTEMPTS_PER_CHANNEL, this.now)
    this.dataRate = new SlidingRateLimiter(MAX_RELAY_DATA_MESSAGES_PER_CHANNEL, this.now)
    endpoints.add(this)
    this.removeMessageHandler = channel.registerMessageHandler(Object.values(RelayMessageType).filter((value): value is number => typeof value === 'number'), async (plaintext) => this.handleMessage(decodeRelayMessage(plaintext)))
    this.removeCloseHandler = channel.onClose(() => this.handleChannelClose())
    this.removeSubsystemResource = options.subsystem?.registerResource({
      close: () => this.shutdown(),
      forceClose: () => this.close()
    }) ?? (() => {})
  }

  registerTarget(options: RegisterRelayTargetOptions): Promise<RelayTargetRegistration> {
    if (this.localRegistration) return Promise.reject(new PeerRelayError('RELAY_REGISTRATION_INVALID'))
    return this.startTargetRegistration(options)
  }

  refreshTargetRegistration(
    current: RelayTargetRegistration,
    options: RegisterRelayTargetOptions
  ): Promise<RelayTargetRegistration> {
    if (
      !isRelayTargetRegistration(current) || current.isClosed() ||
      this.localRegistration?.registration !== current || current.targetServerId !== options.targetServerId
    ) return Promise.reject(new PeerRelayError('RELAY_REGISTRATION_INVALID'))
    return this.startTargetRegistration(options, current)
  }

  private startTargetRegistration(
    options: RegisterRelayTargetOptions,
    replacing?: RelayTargetRegistration
  ): Promise<RelayTargetRegistration> {
    if (this.closed || this.service || this.pendingRegistration) return Promise.reject(new PeerRelayError('RELAY_REGISTRATION_INVALID'))
    assertServerId(options.targetServerId); assertServerId(options.relayServerId); assertServerId(options.outerDeviceFingerprint)
    canonicalEd25519PublicKey(options.targetServerPublicKey)
    if (deriveServerId(options.targetServerPublicKey) !== options.targetServerId || options.targetServerPrivateKey.asymmetricKeyType !== 'ed25519') return Promise.reject(new PeerRelayError('RELAY_REGISTRATION_INVALID'))
    const timeoutMs = options.timeoutMs ?? RELAY_OPEN_TIMEOUT_MS
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_RELAY_OPEN_TIMEOUT_MS) return Promise.reject(new PeerRelayError('RELAY_PROTOCOL_INVALID'))
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.pendingRegistration) return
        this.pendingRegistration = undefined
        reject(new PeerRelayError('RELAY_OPEN_TIMEOUT'))
      }, timeoutMs)
      this.pendingRegistration = {
        targetServerId: options.targetServerId,
        targetServerPublicKey: Buffer.from(options.targetServerPublicKey),
        targetServerPrivateKey: options.targetServerPrivateKey,
        outerDeviceFingerprint: options.outerDeviceFingerprint,
        expectedRelayServerId: options.relayServerId,
        onIncomingCircuit: options.onIncomingCircuit,
        resolve,
        reject,
        timer,
        replacing
      }
      void this.sendControl({ type: RelayMessageType.REGISTER_BEGIN, targetServerId: options.targetServerId }).catch((cause) => this.failRegistration(new PeerRelayError('RELAY_CHANNEL_CLOSED', { cause })))
    })
  }

  openCircuit(targetServerId: string, options: OpenRelayCircuitOptions = {}): Promise<RelayTransportStream> {
    if (this.closed || this.service) return Promise.reject(new PeerRelayError('RELAY_NOT_AUTHORIZED'))
    assertServerId(targetServerId)
    if (this.pendingOpens.size >= MAX_RELAY_OUTSTANDING_OPENS) return Promise.reject(new PeerRelayError('RELAY_CIRCUIT_LIMIT'))
    if (options.signal?.aborted) return Promise.reject(new PeerRelayError('RELAY_OPEN_ABORTED'))
    const timeoutMs = options.timeoutMs ?? RELAY_OPEN_TIMEOUT_MS
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_RELAY_OPEN_TIMEOUT_MS) return Promise.reject(new PeerRelayError('RELAY_PROTOCOL_INVALID'))
    let nonce: Buffer | undefined
    for (let attempt = 0; attempt < 4; attempt++) {
      const candidate = this.random(RELAY_REQUEST_NONCE_BYTES)
      if (Buffer.isBuffer(candidate) && candidate.length === RELAY_REQUEST_NONCE_BYTES && !this.pendingOpens.has(candidate.toString('hex'))) { nonce = Buffer.from(candidate); break }
    }
    if (!nonce) return Promise.reject(new PeerRelayError('RELAY_RESOURCE_LIMIT'))
    const key = nonce.toString('hex')
    return new Promise((resolve, reject) => {
      const finishReject = (error: PeerRelayError, notifyRelay = true): void => {
        const pending = this.pendingOpens.get(key)
        if (!pending) return
        this.cleanupPendingOpen(key, pending)
        reject(error)
        if (notifyRelay && !this.closed) {
          void this.sendControl({ type: RelayMessageType.OPEN_CANCEL, requestNonce: nonce!, targetServerId }).catch(() => {})
        }
      }
      const onAbort = () => finishReject(new PeerRelayError('RELAY_OPEN_ABORTED'))
      const timer = setTimeout(() => finishReject(new PeerRelayError('RELAY_OPEN_TIMEOUT')), timeoutMs)
      const pending: PendingOpen = {
        targetServerId,
        resolve,
        reject,
        timer,
        signal: options.signal,
        onAbort,
        autoRenew: options.autoRenew === true
      }
      this.pendingOpens.set(key, pending)
      options.signal?.addEventListener('abort', onAbort, { once: true })
      void this.sendControl({ type: RelayMessageType.OPEN_REQUEST, requestNonce: nonce!, targetServerId }).catch((cause) => finishReject(new PeerRelayError('RELAY_CHANNEL_CLOSED', { cause }), false))
    })
  }

  async sendControl(message: RelayMessage): Promise<void> {
    if (this.closed) throw new PeerRelayError('RELAY_CHANNEL_CLOSED')
    await this.channel.send(encodeRelayMessage(message))
  }

  close(): void { this.handleChannelClose() }
  async shutdown(): Promise<void> {
    if (this.closed) return
    const messages: RelayMessage[] = []
    if (this.localRegistration) {
      messages.push({ type: RelayMessageType.UNREGISTER, targetServerId: this.localRegistration.registration.targetServerId })
    }
    for (const entry of this.streams.values()) {
      messages.push({ type: RelayMessageType.CLOSE, circuitId: entry.circuitId, reason: RelayCloseReason.PEER_CLOSED })
    }
    await Promise.allSettled(messages.map((message) => this.sendControl(message)))
    this.handleChannelClose()
  }
  onClose(handler: () => void): () => void {
    if (this.closed) {
      handler()
      return () => {}
    }
    this.endpointCloseHandlers.add(handler)
    return () => this.endpointCloseHandlers.delete(handler)
  }
  get activeLocalStreamCount(): number { return this.streams.size }
  get outstandingOpenCount(): number { return this.pendingOpens.size }

  private async handleMessage(message: RelayMessage): Promise<void> {
    if (this.closed) throw new PeerRelayError('RELAY_CHANNEL_CLOSED')
    if (this.service) {
      switch (message.type) {
        case RelayMessageType.REGISTER_BEGIN: await this.sendControl(this.service.beginRegistration(this, message.targetServerId)); return
        case RelayMessageType.REGISTER_PROOF:
          try { await this.sendControl(this.service.proveRegistration(this, message)) }
          catch { await this.sendControl({ type: RelayMessageType.REGISTER_RESULT, status: RelayStatus.NOT_AVAILABLE, targetServerId: message.targetServerId, lifetimeSeconds: 0 }) }
          return
        case RelayMessageType.UNREGISTER: this.service.unregister(this, message.targetServerId); return
        case RelayMessageType.OPEN_REQUEST: await this.service.open(this, message); return
        case RelayMessageType.OPEN_CANCEL: this.service.cancelOpen(this, message); return
        case RelayMessageType.CIRCUIT_ACCEPT: await this.service.accept(this, message); return
        case RelayMessageType.DATA: await this.service.data(this, message); return
        case RelayMessageType.CLOSE: this.service.closeFrom(this, message); return
        case RelayMessageType.CIRCUIT_RENEW: await this.service.renewCircuit(this, message); return
        default: throw new PeerRelayError('RELAY_PROTOCOL_INVALID')
      }
    }
    switch (message.type) {
      case RelayMessageType.REGISTER_CHALLENGE: await this.handleRegistrationChallenge(message); return
      case RelayMessageType.REGISTER_RESULT: this.handleRegistrationResult(message); return
      case RelayMessageType.OPEN_RESPONSE: this.handleOpenResponse(message); return
      case RelayMessageType.INCOMING_CIRCUIT: await this.handleIncomingCircuit(message); return
      case RelayMessageType.DATA: this.handleLocalData(message); return
      case RelayMessageType.CLOSE: this.handleLocalClose(message); return
      case RelayMessageType.CIRCUIT_RENEW_RESULT: this.handleRenewResult(message); return
      default: throw new PeerRelayError('RELAY_PROTOCOL_INVALID')
    }
  }

  private async handleRegistrationChallenge(message: Extract<RelayMessage, { type: RelayMessageType.REGISTER_CHALLENGE }>): Promise<void> {
    const pending = this.pendingRegistration
    if (!pending || pending.targetServerId !== message.targetServerId || pending.expectedRelayServerId !== message.relayServerId || pending.outerDeviceFingerprint !== message.outerDeviceFingerprint) throw new PeerRelayError('RELAY_REGISTRATION_INVALID')
    const transcript = createRelayRegistrationTranscript({ relayServerId: message.relayServerId, targetServerId: message.targetServerId, targetServerPublicKey: pending.targetServerPublicKey, challenge: message.challenge, channelBinding: message.channelBinding, outerDeviceFingerprint: message.outerDeviceFingerprint })
    const signature = sign(null, transcript, pending.targetServerPrivateKey)
    await this.sendControl({ type: RelayMessageType.REGISTER_PROOF, targetServerId: pending.targetServerId, targetServerPublicKey: pending.targetServerPublicKey, challenge: message.challenge, signature })
  }

  private handleRegistrationResult(message: Extract<RelayMessage, { type: RelayMessageType.REGISTER_RESULT }>): void {
    const pending = this.pendingRegistration
    if (!pending || pending.targetServerId !== message.targetServerId) throw new PeerRelayError('RELAY_REGISTRATION_INVALID')
    clearTimeout(pending.timer)
    this.pendingRegistration = undefined
    if (message.status !== RelayStatus.READY) { pending.reject(new PeerRelayError('RELAY_TARGET_NOT_AVAILABLE')); return }
    const expiresAt = this.now() + message.lifetimeSeconds * 1000
    const registration: RelayTargetRegistration = new RelayTargetRegistration(REGISTRATION_TOKEN, message.targetServerId, expiresAt, () => {
      const local = this.localRegistration
      if (local?.registration !== registration) return
      clearTimeout(local.timer)
      this.localRegistration = undefined
      for (const [key, stream] of this.streams) if (stream.targetServerId === message.targetServerId) { stream.handle.stream.destroy(); this.streams.delete(key) }
      if (!this.closed) void this.sendControl({ type: RelayMessageType.UNREGISTER, targetServerId: message.targetServerId }).catch(() => {})
    })
    const previous = this.localRegistration
    const timer = setTimeout(() => registration.close(), message.lifetimeSeconds * 1000)
    this.localRegistration = { registration, onIncomingCircuit: pending.onIncomingCircuit, timer }
    if (pending.replacing && previous?.registration === pending.replacing) {
      clearTimeout(previous.timer)
      pending.replacing.retire(REGISTRATION_TOKEN)
    }
    pending.resolve(registration)
  }

  private handleOpenResponse(message: Extract<RelayMessage, { type: RelayMessageType.OPEN_RESPONSE }>): void {
    const key = message.requestNonce.toString('hex')
    const pending = this.pendingOpens.get(key)
    if (!pending) return
    if (pending.targetServerId !== message.targetServerId) { this.cleanupPendingOpen(key, pending); pending.reject(new PeerRelayError('RELAY_PROTOCOL_INVALID')); return }
    if (message.status !== RelayStatus.READY) { this.cleanupPendingOpen(key, pending); pending.reject(new PeerRelayError('RELAY_TARGET_NOT_AVAILABLE')); return }
    const stream = this.createLocalStream(message.circuitId, message.targetServerId, pending.autoRenew)
    this.cleanupPendingOpen(key, pending)
    pending.resolve(stream)
  }

  private async handleIncomingCircuit(message: Extract<RelayMessage, { type: RelayMessageType.INCOMING_CIRCUIT }>): Promise<void> {
    const local = this.localRegistration
    if (!local || local.registration.isClosed() || local.registration.targetServerId !== message.targetServerId || this.now() >= local.registration.expiresAtMs) {
      await this.sendControl({ type: RelayMessageType.CIRCUIT_ACCEPT, status: RelayStatus.NOT_AVAILABLE, circuitId: message.circuitId, targetServerId: message.targetServerId }); return
    }
    if (this.streams.size >= MAX_RELAY_CIRCUITS_PER_CHANNEL) {
      await this.sendControl({ type: RelayMessageType.CIRCUIT_ACCEPT, status: RelayStatus.NOT_AVAILABLE, circuitId: message.circuitId, targetServerId: message.targetServerId }); return
    }
    const key = message.circuitId.toString('hex')
    if (this.streams.has(key)) throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
    const stream = this.createLocalStream(message.circuitId, message.targetServerId, false)
    try {
      await local.onIncomingCircuit(stream)
      await this.sendControl({ type: RelayMessageType.CIRCUIT_ACCEPT, status: RelayStatus.READY, circuitId: message.circuitId, targetServerId: message.targetServerId })
    } catch {
      await this.sendControl({ type: RelayMessageType.CIRCUIT_ACCEPT, status: RelayStatus.NOT_AVAILABLE, circuitId: message.circuitId, targetServerId: message.targetServerId })
      stream.destroy()
    }
  }

  private createLocalStream(circuitId: Buffer, targetServerId: string, autoRenew: boolean): RelayTransportStream {
    const key = circuitId.toString('hex')
    let localClosing = false
    const handle = createMasqueradaTransportStream({
      maxQueuedBytes: MAX_RELAY_QUEUED_BYTES,
      onWrite: async (bytes) => {
        if (bytes.length === 0) return
        for (let offset = 0; offset < bytes.length; offset += MAX_RELAY_DATA_PAYLOAD_BYTES) {
          await this.sendControl({ type: RelayMessageType.DATA, circuitId, payload: Buffer.from(bytes.subarray(offset, offset + MAX_RELAY_DATA_PAYLOAD_BYTES)) })
        }
      },
      onLocalClose: () => {
        if (localClosing) return
        localClosing = true
        const entry = this.streams.get(key)
        if (entry?.renewTimer) clearTimeout(entry.renewTimer)
        if (entry?.pendingRenew) clearTimeout(entry.pendingRenew.timer)
        this.streams.delete(key)
        if (!this.closed) void this.sendControl({ type: RelayMessageType.CLOSE, circuitId, reason: RelayCloseReason.NORMAL }).catch(() => {})
      }
    })
    relayStreams.add(handle.stream)
    const entry: LocalStreamEntry = {
      handle,
      targetServerId,
      circuitId: Buffer.from(circuitId),
      autoRenew
    }
    this.streams.set(key, entry)
    if (autoRenew) this.scheduleCircuitRenew(entry)
    return handle.stream
  }

  private scheduleCircuitRenew(entry: LocalStreamEntry): void {
    if (!entry.autoRenew || this.closed || entry.handle.stream.destroyed || !this.streams.has(entry.circuitId.toString('hex'))) return
    if (entry.renewTimer) clearTimeout(entry.renewTimer)
    entry.renewTimer = setTimeout(() => this.startCircuitRenew(entry), Math.floor(this.circuitLeaseMs / 2))
  }

  private startCircuitRenew(entry: LocalStreamEntry): void {
    entry.renewTimer = undefined
    if (this.closed || entry.handle.stream.destroyed || entry.pendingRenew) return
    let nonce: Buffer | undefined
    for (let attempt = 0; attempt < 4; attempt++) {
      const candidate = this.random(RELAY_REQUEST_NONCE_BYTES)
      if (Buffer.isBuffer(candidate) && candidate.length === RELAY_REQUEST_NONCE_BYTES) {
        nonce = Buffer.from(candidate)
        break
      }
    }
    if (!nonce) return
    const timer = setTimeout(() => {
      if (entry.pendingRenew?.nonce.equals(nonce!)) entry.pendingRenew = undefined
    }, Math.min(RELAY_CIRCUIT_RENEW_TIMEOUT_MS, Math.max(1, Math.floor(this.circuitLeaseMs / 2))))
    entry.pendingRenew = { nonce, timer }
    void this.sendControl({
      type: RelayMessageType.CIRCUIT_RENEW,
      circuitId: entry.circuitId,
      renewNonce: nonce
    }).catch(() => {
      if (entry.pendingRenew?.nonce.equals(nonce!)) {
        clearTimeout(entry.pendingRenew.timer)
        entry.pendingRenew = undefined
      }
    })
  }

  private handleRenewResult(message: Extract<RelayMessage, { type: RelayMessageType.CIRCUIT_RENEW_RESULT }>): void {
    const entry = this.streams.get(message.circuitId.toString('hex'))
    if (!entry?.pendingRenew || !entry.pendingRenew.nonce.equals(message.renewNonce)) return
    clearTimeout(entry.pendingRenew.timer)
    entry.pendingRenew = undefined
    if (message.status === RelayStatus.READY) this.scheduleCircuitRenew(entry)
  }

  private handleLocalData(message: Extract<RelayMessage, { type: RelayMessageType.DATA }>): void {
    const entry = this.streams.get(message.circuitId.toString('hex'))
    if (!entry) throw new PeerRelayError('RELAY_CIRCUIT_INVALID')
    entry.handle.deliver(message.payload)
  }
  private handleLocalClose(message: Extract<RelayMessage, { type: RelayMessageType.CLOSE }>): void {
    const key = message.circuitId.toString('hex')
    const entry = this.streams.get(key)
    if (!entry) return
    if (entry.renewTimer) clearTimeout(entry.renewTimer)
    if (entry.pendingRenew) clearTimeout(entry.pendingRenew.timer)
    this.streams.delete(key)
    entry.handle.remoteClose()
  }
  private cleanupPendingOpen(key: string, pending: PendingOpen): void {
    clearTimeout(pending.timer); pending.signal?.removeEventListener('abort', pending.onAbort); this.pendingOpens.delete(key)
  }
  private failRegistration(error: PeerRelayError): void {
    const pending = this.pendingRegistration
    if (!pending) return
    clearTimeout(pending.timer); this.pendingRegistration = undefined; pending.reject(error)
  }
  private handleChannelClose(): void {
    if (this.closed) return
    this.closed = true
    this.removeMessageHandler()
    this.removeCloseHandler()
    this.removeSubsystemResource()
    this.service?.detach(this)
    this.failRegistration(new PeerRelayError('RELAY_CHANNEL_CLOSED'))
    for (const [key, pending] of this.pendingOpens) { this.cleanupPendingOpen(key, pending); pending.reject(new PeerRelayError('RELAY_CHANNEL_CLOSED')) }
    if (this.localRegistration) {
      clearTimeout(this.localRegistration.timer)
      this.localRegistration.registration.retire(REGISTRATION_TOKEN)
      this.localRegistration = undefined
    }
    for (const entry of this.streams.values()) {
      if (entry.renewTimer) clearTimeout(entry.renewTimer)
      if (entry.pendingRenew) clearTimeout(entry.pendingRenew.timer)
      entry.handle.remoteClose()
    }
    this.streams.clear()
    for (const handler of this.endpointCloseHandlers) handler()
    this.endpointCloseHandlers.clear()
  }
}

export function createPeerRelayService(options: PeerRelayServiceOptions): PeerRelayService {
  return new PeerRelayService(options)
}

export function createPeerRelayEndpoint(options: CreatePeerRelayEndpointOptions): PeerRelayEndpoint {
  return new PeerRelayEndpoint(ENDPOINT_TOKEN, options.channel, options.service, options)
}

export function isPeerRelayEndpoint(value: unknown): value is PeerRelayEndpoint {
  return typeof value === 'object' && value !== null && endpoints.has(value)
}

export function isRelayTransportStream(value: unknown): value is RelayTransportStream {
  return typeof value === 'object' && value !== null && relayStreams.has(value)
}
