import { isUtf8 } from 'node:buffer'
import { randomBytes } from 'node:crypto'
import { types } from 'node:util'

export const APPLICATION_VERSION = 1
export const APPLICATION_MESSAGE_TYPE = 0x70
export const MAX_APPLICATION_BODY_BYTES = 40 * 1024
export const MAX_APPLICATION_PAYLOAD_BYTES = 32 * 1024

export interface ServerState {
  displayName: string
  channels: readonly { channelId: string; name: string }[]
}

export type ServerStateResponsePayload =
  | {
      status: 'ok'
      server: { displayName: string }
      channels: readonly { channelId: string; name: string }[]
    }
  | { status: 'error'; code: 'UNAVAILABLE' }

export interface HistoryWireMessage {
  sequence: number
  messageId: string
  authorFingerprint: string
  content: string
  createdAt: number
  editedAt: number | null
  deletedAt: number | null
}

export interface HistoryQuery {
  channelId: string
  afterSequence: number
  limit: number
}

export type HistoryResponsePayload =
  | {
      status: 'ok'
      messages: readonly HistoryWireMessage[]
      hasMore: boolean
    }
  | { status: 'error'; code: 'UNAVAILABLE' }

export const MAX_HISTORY_BATCH = 100
export const MAX_MESSAGE_CONTENT_CODE_POINTS_WIRE = 4096

export type ApplicationEnvelope = {
  messageId: string
  serverId: string
  channelId: null
} & (
  | {
      kind: 'request'
      messageType: 'server-state.request' | 'history.request'
      correlationId: null
      sequence: null
      payload: Record<string, never> | HistoryQuery
    }
  | {
      kind: 'response'
      messageType: 'server-state.response' | 'history.response'
      correlationId: string
      sequence: number
      payload: ServerStateResponsePayload | HistoryResponsePayload
    }
)

export class ApplicationProtocolError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'ApplicationProtocolError'
  }
}

const HEADER_BYTES = 6
const MAX_DEPTH = 8
const MAX_NODES = 2048
const ID = /^[0-9a-f]{32}$/
const SERVER_ID = /^sha256:[0-9a-f]{64}$/
type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

function invalid(): never {
  throw new ApplicationProtocolError('APPLICATION_INVALID_ENVELOPE')
}

function validUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
  }
  return true
}

// Copy only data descriptors. No caller-owned object reaches JSON serialization.
function snapshot(input: unknown): Json {
  let nodes = 0
  let stringBytes = 0
  const ancestors = new Set<object>()
  function checkString(value: string): void {
    if (value.length > MAX_APPLICATION_BODY_BYTES) invalid()
    stringBytes += Buffer.byteLength(value, 'utf8')
    if (stringBytes > MAX_APPLICATION_BODY_BYTES || !validUnicode(value)) invalid()
  }
  function visit(value: unknown, depth: number): Json {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) invalid()
    if (value === null || typeof value === 'boolean') return value
    if (typeof value === 'string') {
      checkString(value)
      return value
    }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) invalid()
      return value
    }
    if (typeof value !== 'object' || types.isProxy(value) || ancestors.has(value)) invalid()
    const array = Array.isArray(value)
    const prototype: unknown = Object.getPrototypeOf(value)
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
      invalid()
    }
    const keys = Reflect.ownKeys(value)
    if (keys.length > MAX_NODES - nodes + (array ? 1 : 0)) invalid()
    ancestors.add(value)
    const result: Json[] | { [key: string]: Json } = array ? [] : Object.create(null)
    if (array) {
      const length = Object.getOwnPropertyDescriptor(value, 'length')?.value as unknown
      if (typeof length !== 'number' || length !== keys.length - 1) invalid()
    }
    let index = 0
    for (const key of keys) {
      if (array && key === 'length') continue
      if (typeof key !== 'string') invalid()
      checkString(key)
      if (array && key !== String(index++)) invalid()
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
      const child = visit(descriptor.value, depth + 1)
      if (Array.isArray(result)) result.push(child)
      else result[key] = child
    }
    ancestors.delete(value)
    return result
  }
  return visit(input, 1)
}

function record(value: Json): { [key: string]: Json } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  return value
}

function exactKeys(value: { [key: string]: Json }, expected: readonly string[]): void {
  const keys = Object.keys(value)
  if (keys.length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) invalid()
}

function text(value: Json, maxBytes: number): void {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > maxBytes) invalid()
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit <= 0x1f || (unit >= 0x7f && unit <= 0x9f)) invalid()
  }
}

function validate(value: Json): asserts value is Json & ApplicationEnvelope {
  const envelope = record(value)
  exactKeys(envelope, [
    'messageId', 'serverId', 'channelId', 'kind', 'messageType',
    'correlationId', 'sequence', 'payload'
  ])
  if (
    typeof envelope.messageId !== 'string' || !ID.test(envelope.messageId) ||
    typeof envelope.serverId !== 'string' || !SERVER_ID.test(envelope.serverId) ||
    envelope.channelId !== null
  ) invalid()
  const envelopePayload: Json | undefined = envelope.payload
  if (envelopePayload === undefined) invalid()
  const payload = record(envelopePayload)
  if (envelope.kind === 'request') {
    if (envelope.correlationId !== null || envelope.sequence !== null) invalid()
    if (envelope.messageType === 'server-state.request') {
      exactKeys(payload, [])
      return
    }
    if (envelope.messageType === 'history.request') {
      exactKeys(payload, ['channelId', 'afterSequence', 'limit'])
      if (
        typeof payload.channelId !== 'string' || !ID.test(payload.channelId) ||
        typeof payload.afterSequence !== 'number' || !Number.isSafeInteger(payload.afterSequence) ||
        payload.afterSequence < 0 ||
        typeof payload.limit !== 'number' || !Number.isSafeInteger(payload.limit) ||
        payload.limit < 1 || payload.limit > MAX_HISTORY_BATCH
      ) invalid()
      return
    }
    invalid()
  }
  if (
    envelope.kind !== 'response' ||
    typeof envelope.correlationId !== 'string' || !ID.test(envelope.correlationId) ||
    typeof envelope.sequence !== 'number' || envelope.sequence <= 0
  ) invalid()
  if (envelope.messageType === 'server-state.response') {
    validateServerStateResponse(payload)
    return
  }
  if (envelope.messageType === 'history.response') {
    validateHistoryResponse(payload)
    return
  }
  invalid()
}

function validateServerStateResponse(payload: { [key: string]: Json }): void {
  if (payload.status === 'error') {
    exactKeys(payload, ['status', 'code'])
    if (payload.code !== 'UNAVAILABLE') invalid()
    return
  }
  exactKeys(payload, ['status', 'server', 'channels'])
  if (payload.status !== 'ok') invalid()
  const serverValue: Json | undefined = payload.server
  if (serverValue === undefined || serverValue === null) invalid()
  const server = record(serverValue)
  exactKeys(server, ['displayName'])
  const displayName = server.displayName
  if (typeof displayName !== 'string') invalid()
  text(displayName, 256)
  if (!Array.isArray(payload.channels) || payload.channels.length > 128) invalid()
  let previous = ''
  for (const entry of payload.channels) {
    const channel = record(entry)
    exactKeys(channel, ['channelId', 'name'])
    const channelId = channel.channelId
    const channelName = channel.name
    if (
      typeof channelId !== 'string' || !ID.test(channelId) ||
      channelId <= previous || typeof channelName !== 'string'
    ) invalid()
    previous = channelId
    text(channelName, 128)
  }
}

function validateHistoryResponse(payload: { [key: string]: Json }): void {
  if (payload.status === 'error') {
    exactKeys(payload, ['status', 'code'])
    if (payload.code !== 'UNAVAILABLE') invalid()
    return
  }
  exactKeys(payload, ['status', 'messages', 'hasMore'])
  if (payload.status !== 'ok') invalid()
  if (typeof payload.hasMore !== 'boolean') invalid()
  if (!Array.isArray(payload.messages) || payload.messages.length > MAX_HISTORY_BATCH) invalid()
  let previousSequence = 0
  for (const entry of payload.messages) {
    const message = record(entry)
    exactKeys(message, ['sequence', 'messageId', 'authorFingerprint', 'content', 'createdAt', 'editedAt', 'deletedAt'])
    const { sequence, messageId, authorFingerprint, content, createdAt, editedAt, deletedAt } = message
    if (
      typeof sequence !== 'number' || !Number.isSafeInteger(sequence) || sequence < 1 ||
      sequence <= previousSequence ||
      typeof messageId !== 'string' || !ID.test(messageId) ||
      typeof authorFingerprint !== 'string' || !SERVER_ID.test(authorFingerprint) ||
      typeof createdAt !== 'number' || !Number.isInteger(createdAt) || createdAt < 0 ||
      (editedAt !== null && (typeof editedAt !== 'number' || !Number.isInteger(editedAt))) ||
      (deletedAt !== null && (typeof deletedAt !== 'number' || !Number.isInteger(deletedAt)))
    ) invalid()
    previousSequence = sequence
    const contentValue: Json | undefined = content
    if (contentValue === undefined || contentValue === null) invalid()
    // Tombstones (deletedAt set) carry empty content by design.
    historyContent(contentValue, MAX_MESSAGE_CONTENT_CODE_POINTS_WIRE, deletedAt !== null)
  }
}

function historyContent(value: Json, maxCodePoints: number, allowEmpty: boolean): void {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || [...value].length > maxCodePoints) invalid()
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit <= 0x1f || (unit >= 0x7f && unit <= 0x9f)) invalid()
  }
}

// This recursion only sees the depth- and node-bounded snapshot, never raw input.
function canonical(value: Json): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  const recordValue = value as { [key: string]: Json }
  return `{${Object.keys(recordValue).sort().map((key) => `${JSON.stringify(key)}:${canonical(recordValue[key]!)}`).join(',')}}`
}

export function createApplicationMessageId(): string {
  return randomBytes(16).toString('hex')
}

export function encodeApplicationEnvelope(envelope: ApplicationEnvelope): Buffer {
  const value = snapshot(envelope)
  validate(value)
  const payloadBytes = Buffer.from(canonical((value as { payload: Json }).payload), 'utf8')
  if (payloadBytes.length > MAX_APPLICATION_PAYLOAD_BYTES) {
    throw new ApplicationProtocolError('APPLICATION_PAYLOAD_TOO_LARGE')
  }
  const body = Buffer.from(canonical(value), 'utf8')
  if (body.length > MAX_APPLICATION_BODY_BYTES) {
    throw new ApplicationProtocolError('APPLICATION_BODY_TOO_LARGE')
  }
  const bytes = Buffer.allocUnsafe(HEADER_BYTES + body.length)
  bytes[0] = APPLICATION_VERSION
  bytes[1] = APPLICATION_MESSAGE_TYPE
  bytes.writeUInt32BE(body.length, 2)
  body.copy(bytes, HEADER_BYTES)
  return bytes
}

export function decodeApplicationEnvelope(bytes: Buffer): ApplicationEnvelope {
  if (!Buffer.isBuffer(bytes) || bytes.length < HEADER_BYTES) {
    throw new ApplicationProtocolError('APPLICATION_INVALID_FRAME')
  }
  const length = bytes.readUInt32BE(2)
  if (length > MAX_APPLICATION_BODY_BYTES || bytes.length > HEADER_BYTES + MAX_APPLICATION_BODY_BYTES) {
    throw new ApplicationProtocolError('APPLICATION_BODY_TOO_LARGE')
  }
  if (bytes[0] !== APPLICATION_VERSION || bytes[1] !== APPLICATION_MESSAGE_TYPE || bytes.length !== HEADER_BYTES + length) {
    throw new ApplicationProtocolError('APPLICATION_INVALID_FRAME')
  }
  const body = bytes.subarray(HEADER_BYTES)
  if (!isUtf8(body) || (body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf)) {
    throw new ApplicationProtocolError('APPLICATION_INVALID_UTF8')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(body.toString('utf8')) as unknown
  } catch {
    throw new ApplicationProtocolError('APPLICATION_INVALID_JSON')
  }
  const value = snapshot(parsed)
  validate(value)
  if (!encodeApplicationEnvelope(value).equals(bytes)) {
    throw new ApplicationProtocolError('APPLICATION_NON_CANONICAL')
  }
  return value
}
