import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

import type { InitialOwnerDeviceIdentity } from './initial-owner-binding'

export const SERVER_INVITE_VERSION = 1
export const SERVER_INVITE_TYPE = 'server-invite'
export const SERVER_INVITE_DOMAIN = 'Masquerada/server-invite/v1'
export const INVITE_PREFIX = 'MQR1.'
export const MAX_SERVER_INVITE_STRING_LENGTH = 4 * 1024 // 4 KB
export const MAX_SERVER_INVITE_METADATA_BYTES = 4 * 1024 // 4 KB
export const ED25519_SIGNATURE_BYTES = 64
export const INVITE_ID_HEX_LENGTH = 32 // 16 bytes = 128 bits
export const INVITE_SECRET_HEX_LENGTH = 64 // 32 bytes = 256 bits

const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/
const HEX_32_PATTERN = /^[0-9a-f]{32}$/
const HEX_64_PATTERN = /^[0-9a-f]{64}$/

export type ServerInviteErrorCode =
  | 'SERVER_INVITE_INVALID'
  | 'SERVER_INVITE_VERSION_UNSUPPORTED'
  | 'SERVER_INVITE_EXPIRED'
  | 'SERVER_INVITE_UNAUTHORIZED'
  | 'SERVER_INVITE_CREATION_FAILED'
  | 'SERVER_INVITE_SERVER_MISMATCH'

const ERROR_MESSAGES: Record<ServerInviteErrorCode, string> = {
  SERVER_INVITE_INVALID: 'O convite do servidor é inválido ou está malformado.',
  SERVER_INVITE_VERSION_UNSUPPORTED: 'A versão do convite não é suportada.',
  SERVER_INVITE_EXPIRED: 'O convite do servidor expirou.',
  SERVER_INVITE_UNAUTHORIZED: 'Apenas a autoridade inicial do servidor pode emitir convites.',
  SERVER_INVITE_CREATION_FAILED: 'Não foi possível criar o convite do servidor com segurança.',
  SERVER_INVITE_SERVER_MISMATCH: 'O convite não pertence ao servidor especificado.'
}

export class ServerInviteError extends Error {
  readonly code: ServerInviteErrorCode

  constructor(code: ServerInviteErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'ServerInviteError'
    this.code = code
  }
}

export interface ServerInvite {
  readonly version: typeof SERVER_INVITE_VERSION
  readonly type: typeof SERVER_INVITE_TYPE
  readonly serverId: string
  readonly inviteId: string
  readonly inviteSecret: string
  readonly issuedByDeviceFingerprint: string
  readonly expiresAt: number
  readonly maxUses: number
  readonly signature: Buffer
}

interface ServerInviteMetadata {
  readonly version: typeof SERVER_INVITE_VERSION
  readonly type: typeof SERVER_INVITE_TYPE
  readonly serverId: string
  readonly inviteId: string
  readonly inviteSecret: string
  readonly issuedByDeviceFingerprint: string
  readonly expiresAt: number
  readonly maxUses: number
  readonly signature: string
}

export interface CreateServerInviteOptions {
  readonly expiresAt: number
  readonly maxUses?: number
}

export interface VerifyServerInviteOptions {
  readonly expectedServerId?: string
  readonly nowSeconds?: number
}

export function createServerInvite(
  serverId: string,
  serverPrivateKey: KeyObject,
  issuedByDeviceIdentity: InitialOwnerDeviceIdentity,
  options: CreateServerInviteOptions
): ServerInvite {
  try {
    assertValidFingerprint(serverId, 'SERVER_INVITE_CREATION_FAILED')
    assertValidFingerprint(
      issuedByDeviceIdentity.fingerprint,
      'SERVER_INVITE_CREATION_FAILED'
    )

    const serverPublicKeyDer = exportCanonicalEd25519PublicKey(
      createPublicKey(serverPrivateKey),
      'SERVER_INVITE_CREATION_FAILED'
    )

    if (calculateFingerprint(serverPublicKeyDer) !== serverId) {
      throw new ServerInviteError('SERVER_INVITE_CREATION_FAILED')
    }

    if (
      typeof options.expiresAt !== 'number' ||
      !Number.isInteger(options.expiresAt) ||
      options.expiresAt <= 0
    ) {
      throw new ServerInviteError('SERVER_INVITE_CREATION_FAILED')
    }

    const maxUses = options.maxUses ?? 1

    if (typeof maxUses !== 'number' || !Number.isInteger(maxUses) || maxUses <= 0) {
      throw new ServerInviteError('SERVER_INVITE_CREATION_FAILED')
    }

    const inviteId = randomBytes(16).toString('hex')
    const inviteSecret = randomBytes(32).toString('hex')

    const payload = encodeInviteSigningPayload(
      serverId,
      inviteId,
      inviteSecret,
      issuedByDeviceIdentity.fingerprint,
      options.expiresAt,
      maxUses,
      SERVER_INVITE_DOMAIN
    )

    const signature = sign(null, payload, serverPrivateKey)

    if (signature.length !== ED25519_SIGNATURE_BYTES) {
      throw new ServerInviteError('SERVER_INVITE_CREATION_FAILED')
    }

    return Object.freeze({
      version: SERVER_INVITE_VERSION,
      type: SERVER_INVITE_TYPE,
      serverId,
      inviteId,
      inviteSecret,
      issuedByDeviceFingerprint: issuedByDeviceIdentity.fingerprint,
      expiresAt: options.expiresAt,
      maxUses,
      signature: Buffer.from(signature)
    })
  } catch (error) {
    if (error instanceof ServerInviteError) {
      throw error
    }

    throw new ServerInviteError('SERVER_INVITE_CREATION_FAILED')
  }
}

export function encodeServerInvite(invite: ServerInvite): string {
  const metadata: ServerInviteMetadata = {
    version: SERVER_INVITE_VERSION,
    type: SERVER_INVITE_TYPE,
    serverId: invite.serverId,
    inviteId: invite.inviteId,
    inviteSecret: invite.inviteSecret,
    issuedByDeviceFingerprint: invite.issuedByDeviceFingerprint,
    expiresAt: invite.expiresAt,
    maxUses: invite.maxUses,
    signature: invite.signature.toString('base64url')
  }

  const jsonString = JSON.stringify(metadata)
  const base64UrlPayload = Buffer.from(jsonString, 'utf8').toString('base64url')
  const encoded = `${INVITE_PREFIX}${base64UrlPayload}`

  if (encoded.length > MAX_SERVER_INVITE_STRING_LENGTH) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  return encoded
}

export function decodeServerInvite(encoded: string): ServerInvite {
  if (
    typeof encoded !== 'string' ||
    encoded.length === 0 ||
    encoded.length > MAX_SERVER_INVITE_STRING_LENGTH ||
    !encoded.startsWith(INVITE_PREFIX)
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  const payloadPart = encoded.slice(INVITE_PREFIX.length)

  if (payloadPart.length === 0 || !/^[A-Za-z0-9_-]+$/.test(payloadPart)) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  let jsonBytes: Buffer
  try {
    jsonBytes = Buffer.from(payloadPart, 'base64url')

    if (jsonBytes.toString('base64url') !== payloadPart) {
      throw new ServerInviteError('SERVER_INVITE_INVALID')
    }
  } catch {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (
    jsonBytes.length === 0 ||
    jsonBytes.length > MAX_SERVER_INVITE_METADATA_BYTES
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  const metadata = parseInviteMetadata(jsonBytes)
  const signature = decodeCanonicalBase64Url(
    metadata.signature,
    ED25519_SIGNATURE_BYTES
  )

  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  return Object.freeze({
    version: metadata.version,
    type: metadata.type,
    serverId: metadata.serverId,
    inviteId: metadata.inviteId,
    inviteSecret: metadata.inviteSecret,
    issuedByDeviceFingerprint: metadata.issuedByDeviceFingerprint,
    expiresAt: metadata.expiresAt,
    maxUses: metadata.maxUses,
    signature
  })
}

export function verifyServerInvite(
  inviteOrEncoded: ServerInvite | string,
  serverPublicKeyDer: Buffer,
  options: VerifyServerInviteOptions = {}
): ServerInvite {
  const invite =
    typeof inviteOrEncoded === 'string'
      ? decodeServerInvite(inviteOrEncoded)
      : inviteOrEncoded

  assertValidFingerprint(invite.serverId, 'SERVER_INVITE_INVALID')
  assertValidFingerprint(
    invite.issuedByDeviceFingerprint,
    'SERVER_INVITE_INVALID'
  )

  if (options.expectedServerId && invite.serverId !== options.expectedServerId) {
    throw new ServerInviteError('SERVER_INVITE_SERVER_MISMATCH')
  }

  const canonicalServerPublicKey = exportCanonicalEd25519PublicKey(
    parsePublicKey(serverPublicKeyDer),
    'SERVER_INVITE_INVALID'
  )

  if (!canonicalServerPublicKey.equals(serverPublicKeyDer)) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (calculateFingerprint(canonicalServerPublicKey) !== invite.serverId) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (!HEX_32_PATTERN.test(invite.inviteId) || !HEX_64_PATTERN.test(invite.inviteSecret)) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (
    typeof invite.expiresAt !== 'number' ||
    !Number.isInteger(invite.expiresAt) ||
    invite.expiresAt <= 0
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000)

  if (nowSeconds > invite.expiresAt) {
    throw new ServerInviteError('SERVER_INVITE_EXPIRED')
  }

  if (
    typeof invite.maxUses !== 'number' ||
    !Number.isInteger(invite.maxUses) ||
    invite.maxUses <= 0
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (invite.signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  const payload = encodeInviteSigningPayload(
    invite.serverId,
    invite.inviteId,
    invite.inviteSecret,
    invite.issuedByDeviceFingerprint,
    invite.expiresAt,
    invite.maxUses,
    SERVER_INVITE_DOMAIN
  )

  const serverPublicKey = parsePublicKey(serverPublicKeyDer)

  if (!verify(null, payload, serverPublicKey, invite.signature)) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  return Object.freeze({
    ...invite,
    signature: Buffer.from(invite.signature)
  })
}

function parseInviteMetadata(jsonBytes: Buffer): ServerInviteMetadata {
  let value: unknown

  try {
    value = JSON.parse(jsonBytes.toString('utf8'))
  } catch {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (!isRecord(value)) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  if (value.version !== SERVER_INVITE_VERSION) {
    if (typeof value.version === 'number' && Number.isInteger(value.version)) {
      throw new ServerInviteError('SERVER_INVITE_VERSION_UNSUPPORTED')
    }

    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  const expectedKeys = [
    'expiresAt',
    'inviteId',
    'inviteSecret',
    'issuedByDeviceFingerprint',
    'maxUses',
    'serverId',
    'signature',
    'type',
    'version'
  ]

  if (
    Object.keys(value).sort().join(',') !== expectedKeys.join(',') ||
    value.type !== SERVER_INVITE_TYPE ||
    typeof value.serverId !== 'string' ||
    typeof value.inviteId !== 'string' ||
    typeof value.inviteSecret !== 'string' ||
    typeof value.issuedByDeviceFingerprint !== 'string' ||
    typeof value.expiresAt !== 'number' ||
    !Number.isInteger(value.expiresAt) ||
    value.expiresAt <= 0 ||
    typeof value.maxUses !== 'number' ||
    !Number.isInteger(value.maxUses) ||
    value.maxUses <= 0 ||
    typeof value.signature !== 'string' ||
    !FINGERPRINT_PATTERN.test(value.serverId) ||
    !FINGERPRINT_PATTERN.test(value.issuedByDeviceFingerprint) ||
    !HEX_32_PATTERN.test(value.inviteId) ||
    !HEX_64_PATTERN.test(value.inviteSecret)
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  return {
    version: SERVER_INVITE_VERSION,
    type: SERVER_INVITE_TYPE,
    serverId: value.serverId,
    inviteId: value.inviteId,
    inviteSecret: value.inviteSecret,
    issuedByDeviceFingerprint: value.issuedByDeviceFingerprint,
    expiresAt: value.expiresAt,
    maxUses: value.maxUses,
    signature: value.signature
  }
}

export function encodeInviteSigningPayload(
  serverId: string,
  inviteId: string,
  inviteSecret: string,
  issuedByDeviceFingerprint: string,
  expiresAt: number,
  maxUses: number,
  domain: string
): Buffer {
  const expiresAtBuffer = Buffer.allocUnsafe(8)
  expiresAtBuffer.writeBigUInt64BE(BigInt(expiresAt))

  const maxUsesBuffer = Buffer.allocUnsafe(4)
  maxUsesBuffer.writeUInt32BE(maxUses)

  const fields = [
    Buffer.from(domain, 'utf8'),
    Buffer.from(String(SERVER_INVITE_VERSION), 'ascii'),
    Buffer.from(SERVER_INVITE_TYPE, 'utf8'),
    Buffer.from(serverId, 'ascii'),
    Buffer.from(inviteId, 'ascii'),
    Buffer.from(inviteSecret, 'ascii'),
    Buffer.from(issuedByDeviceFingerprint, 'ascii'),
    expiresAtBuffer,
    maxUsesBuffer
  ]

  const framedFields: Buffer[] = []

  for (const field of fields) {
    const length = Buffer.allocUnsafe(4)
    length.writeUInt32BE(field.length)
    framedFields.push(length, field)
  }

  return Buffer.concat(framedFields)
}

function parsePublicKey(
  publicKeyDer: Buffer,
  errorCode: ServerInviteErrorCode = 'SERVER_INVITE_INVALID'
): KeyObject {
  try {
    return createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' })
  } catch {
    throw new ServerInviteError(errorCode)
  }
}

function exportCanonicalEd25519PublicKey(
  publicKey: KeyObject,
  errorCode: ServerInviteErrorCode
): Buffer {
  try {
    if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
      throw new ServerInviteError(errorCode)
    }

    return Buffer.from(publicKey.export({ format: 'der', type: 'spki' }))
  } catch (error) {
    if (error instanceof ServerInviteError) {
      throw error
    }

    throw new ServerInviteError(errorCode)
  }
}

function calculateFingerprint(publicKeyDer: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKeyDer).digest('hex')}`
}

function assertValidFingerprint(
  value: unknown,
  errorCode: ServerInviteErrorCode
): asserts value is string {
  if (typeof value !== 'string' || !FINGERPRINT_PATTERN.test(value)) {
    throw new ServerInviteError(errorCode)
  }
}

function decodeCanonicalBase64Url(value: string, expectedLength: number): Buffer {
  if (
    value.length === 0 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  const decoded = Buffer.from(value, 'base64url')

  if (
    decoded.length !== expectedLength ||
    decoded.toString('base64url') !== value
  ) {
    throw new ServerInviteError('SERVER_INVITE_INVALID')
  }

  return decoded
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
