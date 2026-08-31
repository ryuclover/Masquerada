import { classifyNetworkAddress, type AddressScope } from './network-interfaces'

export const STUN_HEADER_BYTES = 20
export const STUN_MAGIC_COOKIE = 0x2112a442
export const STUN_BINDING_REQUEST = 0x0001
export const STUN_BINDING_SUCCESS_RESPONSE = 0x0101
export const STUN_BINDING_ERROR_RESPONSE = 0x0111
export const STUN_TRANSACTION_ID_BYTES = 12
export const STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS = 0x0020
export const STUN_ATTRIBUTE_FINGERPRINT = 0x8028
export const STUN_FINGERPRINT_XOR = 0x5354554e
export const MAX_STUN_DATAGRAM_BYTES = 2048
export const MAX_STUN_ATTRIBUTES = 32
export const MAX_STUN_ERROR_REASON_BYTES = 128

const STUN_ATTRIBUTE_ERROR_CODE = 0x0009
const KNOWN_COMPREHENSION_REQUIRED_ATTRIBUTES = new Set([
  0x0001, // MAPPED-ADDRESS (legacy; never substitutes XOR-MAPPED-ADDRESS)
  0x0006, // USERNAME
  0x0008, // MESSAGE-INTEGRITY
  STUN_ATTRIBUTE_ERROR_CODE,
  0x000a, // UNKNOWN-ATTRIBUTES
  0x0014, // REALM
  0x0015, // NONCE
  0x001c, // MESSAGE-INTEGRITY-SHA256
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS
])

export type StunProtocolErrorCode =
  | 'STUN_RESPONSE_INVALID'
  | 'STUN_TRANSACTION_MISMATCH'
  | 'STUN_XOR_MAPPED_ADDRESS_INVALID'
  | 'STUN_FINGERPRINT_INVALID'
  | 'STUN_UNSUPPORTED_ATTRIBUTE'
  | 'STUN_AUTH_REQUIRED'
  | 'STUN_SERVER_ERROR'

export class StunProtocolError extends Error {
  readonly code: StunProtocolErrorCode
  readonly responseCode?: number

  constructor(code: StunProtocolErrorCode, responseCode?: number) {
    super(code)
    this.name = 'StunProtocolError'
    this.code = code
    this.responseCode = responseCode
  }
}

export interface DecodedStunBindingSuccess {
  readonly kind: 'success'
  readonly observedAddress: string
  readonly observedPort: number
  readonly family: 4 | 6
  readonly observedScope: AddressScope
  readonly hasFingerprint: boolean
}

interface ParsedAttribute {
  readonly type: number
  readonly value: Buffer
  readonly startOffset: number
}

function crc32(bytes: Buffer): number {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0)
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

function validateTransactionId(transactionId: Buffer): void {
  if (!Buffer.isBuffer(transactionId) || transactionId.length !== STUN_TRANSACTION_ID_BYTES) {
    throw new StunProtocolError('STUN_RESPONSE_INVALID')
  }
}

/** Creates a minimal RFC 8489 Binding Request with FINGERPRINT as the final attribute. */
export function createStunBindingRequest(transactionId: Buffer): Buffer {
  validateTransactionId(transactionId)
  const request = Buffer.alloc(STUN_HEADER_BYTES + 8)
  request.writeUInt16BE(STUN_BINDING_REQUEST, 0)
  request.writeUInt16BE(8, 2)
  request.writeUInt32BE(STUN_MAGIC_COOKIE, 4)
  transactionId.copy(request, 8)
  request.writeUInt16BE(STUN_ATTRIBUTE_FINGERPRINT, STUN_HEADER_BYTES)
  request.writeUInt16BE(4, STUN_HEADER_BYTES + 2)
  const fingerprint = (crc32(request.subarray(0, STUN_HEADER_BYTES)) ^ STUN_FINGERPRINT_XOR) >>> 0
  request.writeUInt32BE(fingerprint, STUN_HEADER_BYTES + 4)
  return request
}

function parseAttributes(datagram: Buffer): readonly ParsedAttribute[] {
  const attributes: ParsedAttribute[] = []
  let offset = STUN_HEADER_BYTES

  while (offset < datagram.length) {
    if (attributes.length >= MAX_STUN_ATTRIBUTES || offset + 4 > datagram.length) {
      throw new StunProtocolError('STUN_RESPONSE_INVALID')
    }
    const startOffset = offset
    const type = datagram.readUInt16BE(offset)
    const length = datagram.readUInt16BE(offset + 2)
    offset += 4
    const paddedLength = (length + 3) & ~3
    if (offset + paddedLength > datagram.length || offset + length > datagram.length) {
      throw new StunProtocolError('STUN_RESPONSE_INVALID')
    }
    attributes.push(Object.freeze({
      type,
      value: Buffer.from(datagram.subarray(offset, offset + length)),
      startOffset
    }))
    offset += paddedLength
  }

  if (offset !== datagram.length) throw new StunProtocolError('STUN_RESPONSE_INVALID')
  return Object.freeze(attributes)
}

function validateFingerprint(datagram: Buffer, attributes: readonly ParsedAttribute[]): boolean {
  const fingerprints = attributes.filter((attribute) => attribute.type === STUN_ATTRIBUTE_FINGERPRINT)
  if (fingerprints.length === 0) return false
  if (fingerprints.length !== 1) throw new StunProtocolError('STUN_FINGERPRINT_INVALID')
  const fingerprint = fingerprints[0]!
  if (fingerprint.value.length !== 4 || attributes.at(-1) !== fingerprint) {
    throw new StunProtocolError('STUN_FINGERPRINT_INVALID')
  }
  const expected = (crc32(datagram.subarray(0, fingerprint.startOffset)) ^ STUN_FINGERPRINT_XOR) >>> 0
  if (fingerprint.value.readUInt32BE(0) !== expected) {
    throw new StunProtocolError('STUN_FINGERPRINT_INVALID')
  }
  return true
}

function rejectUnknownRequiredAttributes(attributes: readonly ParsedAttribute[]): void {
  for (const attribute of attributes) {
    if (
      attribute.type < 0x8000 &&
      !KNOWN_COMPREHENSION_REQUIRED_ATTRIBUTES.has(attribute.type)
    ) {
      throw new StunProtocolError('STUN_UNSUPPORTED_ATTRIBUTE')
    }
  }
}

function decodeXorMappedAddress(attribute: ParsedAttribute, transactionId: Buffer): DecodedStunBindingSuccess {
  const value = attribute.value
  if (value.length < 4 || value[0] !== 0) {
    throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
  }
  const familyByte = value[1]
  const observedPort = value.readUInt16BE(2) ^ (STUN_MAGIC_COOKIE >>> 16)
  if (observedPort < 1 || observedPort > 65535) {
    throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
  }

  let rawAddress: string
  let family: 4 | 6
  if (familyByte === 0x01) {
    if (value.length !== 8) throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
    const cookie = Buffer.alloc(4)
    cookie.writeUInt32BE(STUN_MAGIC_COOKIE)
    const octets = Array.from(value.subarray(4, 8), (byte, index) => byte ^ cookie[index]!)
    rawAddress = octets.join('.')
    family = 4
  } else if (familyByte === 0x02) {
    if (value.length !== 20) throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
    const mask = Buffer.alloc(16)
    mask.writeUInt32BE(STUN_MAGIC_COOKIE, 0)
    transactionId.copy(mask, 4)
    const decoded = Buffer.alloc(16)
    for (let index = 0; index < decoded.length; index += 1) {
      decoded[index] = value[index + 4]! ^ mask[index]!
    }
    const words: string[] = []
    for (let offset = 0; offset < decoded.length; offset += 2) {
      words.push(decoded.readUInt16BE(offset).toString(16))
    }
    rawAddress = words.join(':')
    family = 6
  } else {
    throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
  }

  const classification = classifyNetworkAddress(rawAddress)
  if (
    (family === 4 && classification.family !== 'IPv4') ||
    (family === 6 && classification.family !== 'IPv6') ||
    classification.scope === 'UNSUPPORTED'
  ) {
    throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
  }

  return Object.freeze({
    kind: 'success',
    observedAddress: classification.normalizedAddress,
    observedPort,
    family,
    observedScope: classification.scope,
    hasFingerprint: false
  })
}

function parseErrorResponse(attributes: readonly ParsedAttribute[]): never {
  const errorAttributes = attributes.filter((attribute) => attribute.type === STUN_ATTRIBUTE_ERROR_CODE)
  if (errorAttributes.length !== 1) throw new StunProtocolError('STUN_RESPONSE_INVALID')
  const value = errorAttributes[0]!.value
  if (value.length < 4 || value.length > 4 + MAX_STUN_ERROR_REASON_BYTES) {
    throw new StunProtocolError('STUN_RESPONSE_INVALID')
  }
  const errorClass = value[2]! & 0x07
  const errorNumber = value[3]!
  if (errorClass < 3 || errorClass > 6 || errorNumber > 99) {
    throw new StunProtocolError('STUN_RESPONSE_INVALID')
  }
  const responseCode = errorClass * 100 + errorNumber
  if (responseCode === 401 || responseCode === 438) {
    throw new StunProtocolError('STUN_AUTH_REQUIRED', responseCode)
  }
  throw new StunProtocolError('STUN_SERVER_ERROR', responseCode)
}

/** Validates and decodes one correlated Binding success/error response. */
export function parseStunBindingResponse(
  datagram: Buffer,
  expectedTransactionId: Buffer
): DecodedStunBindingSuccess {
  validateTransactionId(expectedTransactionId)
  if (
    !Buffer.isBuffer(datagram) ||
    datagram.length < STUN_HEADER_BYTES ||
    datagram.length > MAX_STUN_DATAGRAM_BYTES
  ) {
    throw new StunProtocolError('STUN_RESPONSE_INVALID')
  }
  const messageType = datagram.readUInt16BE(0)
  const messageLength = datagram.readUInt16BE(2)
  if (
    messageLength % 4 !== 0 ||
    messageLength !== datagram.length - STUN_HEADER_BYTES ||
    datagram.readUInt32BE(4) !== STUN_MAGIC_COOKIE
  ) {
    throw new StunProtocolError('STUN_RESPONSE_INVALID')
  }
  if (!datagram.subarray(8, 20).equals(expectedTransactionId)) {
    throw new StunProtocolError('STUN_TRANSACTION_MISMATCH')
  }
  if (messageType !== STUN_BINDING_SUCCESS_RESPONSE && messageType !== STUN_BINDING_ERROR_RESPONSE) {
    throw new StunProtocolError('STUN_RESPONSE_INVALID')
  }

  const attributes = parseAttributes(datagram)
  rejectUnknownRequiredAttributes(attributes)
  const hasFingerprint = validateFingerprint(datagram, attributes)

  if (messageType === STUN_BINDING_ERROR_RESPONSE) parseErrorResponse(attributes)

  const xorMapped = attributes.filter(
    (attribute) => attribute.type === STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS
  )
  if (xorMapped.length !== 1) {
    throw new StunProtocolError('STUN_XOR_MAPPED_ADDRESS_INVALID')
  }
  const decoded = decodeXorMappedAddress(xorMapped[0]!, expectedTransactionId)
  return Object.freeze({ ...decoded, hasFingerprint })
}

/** @internal Pure helpers used only by deterministic protocol tests. */
export const stunProtocolTestOnly = Object.freeze({ crc32 })
