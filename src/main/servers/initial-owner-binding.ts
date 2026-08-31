import {
  createHash,
  createPublicKey,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

const OWNER_BINDING_VERSION = 1
const OWNER_BINDING_TYPE = 'initial-owner'
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/
const ED25519_SIGNATURE_BYTES = 64

export const INITIAL_OWNER_BINDING_DOMAIN = 'Masquerada/server-initial-owner/v1'
export const MAX_INITIAL_OWNER_METADATA_BYTES = 4 * 1024
export const MAX_INITIAL_OWNER_PUBLIC_KEY_BASE64_LENGTH = 2 * 1024
export const MAX_INITIAL_OWNER_SIGNATURE_BASE64_LENGTH = 128

export type InitialOwnerBindingErrorCode =
  | 'SERVER_OWNER_BINDING_INVALID'
  | 'SERVER_OWNER_BINDING_VERSION_UNSUPPORTED'
  | 'SERVER_OWNER_BINDING_CREATION_FAILED'

const ERROR_MESSAGES: Record<InitialOwnerBindingErrorCode, string> = {
  SERVER_OWNER_BINDING_INVALID: 'O vínculo de autoridade inicial do servidor é inválido.',
  SERVER_OWNER_BINDING_VERSION_UNSUPPORTED:
    'A versão do vínculo de autoridade inicial não é suportada.',
  SERVER_OWNER_BINDING_CREATION_FAILED:
    'Não foi possível criar o vínculo de autoridade inicial do servidor.'
}

export class InitialOwnerBindingError extends Error {
  readonly code: InitialOwnerBindingErrorCode

  constructor(code: InitialOwnerBindingErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'InitialOwnerBindingError'
    this.code = code
  }
}

export interface InitialOwnerDeviceIdentity {
  readonly fingerprint: string
  readonly publicKey: Buffer
}

export interface InitialOwnerBinding {
  readonly version: typeof OWNER_BINDING_VERSION
  readonly type: typeof OWNER_BINDING_TYPE
  readonly serverId: string
  readonly deviceFingerprint: string
  readonly publicKey: Buffer
  readonly signature: Buffer
}

interface InitialOwnerBindingMetadata {
  readonly version: typeof OWNER_BINDING_VERSION
  readonly type: typeof OWNER_BINDING_TYPE
  readonly serverId: string
  readonly ownerDeviceFingerprint: string
  readonly ownerDevicePublicKey: string
  readonly signature: string
}

export interface InitialOwnerBindingMaterial {
  readonly binding: InitialOwnerBinding
  readonly metadataBytes: Buffer
}

export function createInitialOwnerBinding(
  serverId: string,
  ownerDeviceIdentity: InitialOwnerDeviceIdentity,
  serverPrivateKey: KeyObject
): InitialOwnerBindingMaterial {
  try {
    assertValidFingerprint(serverId, 'SERVER_OWNER_BINDING_CREATION_FAILED')
    const serverPublicKeyDer = exportCanonicalEd25519PublicKey(
      createPublicKey(serverPrivateKey),
      'SERVER_OWNER_BINDING_CREATION_FAILED'
    )

    if (calculateFingerprint(serverPublicKeyDer) !== serverId) {
      throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_CREATION_FAILED')
    }

    const ownerPublicKeyDer = validateDeviceIdentity(
      ownerDeviceIdentity,
      'SERVER_OWNER_BINDING_CREATION_FAILED'
    )
    const payload = encodeSigningPayload(
      serverId,
      ownerDeviceIdentity.fingerprint,
      ownerPublicKeyDer,
      INITIAL_OWNER_BINDING_DOMAIN
    )
    const signature = sign(null, payload, serverPrivateKey)

    if (signature.length !== ED25519_SIGNATURE_BYTES) {
      throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_CREATION_FAILED')
    }

    const metadata: InitialOwnerBindingMetadata = {
      version: OWNER_BINDING_VERSION,
      type: OWNER_BINDING_TYPE,
      serverId,
      ownerDeviceFingerprint: ownerDeviceIdentity.fingerprint,
      ownerDevicePublicKey: ownerPublicKeyDer.toString('base64'),
      signature: signature.toString('base64')
    }
    const metadataBytes = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8')

    if (metadataBytes.length > MAX_INITIAL_OWNER_METADATA_BYTES) {
      throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_CREATION_FAILED')
    }

    return Object.freeze({
      binding: createPublicBinding(metadata, ownerPublicKeyDer, signature),
      metadataBytes
    })
  } catch (error) {
    if (error instanceof InitialOwnerBindingError) {
      throw error
    }

    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_CREATION_FAILED')
  }
}

export function loadInitialOwnerBinding(
  metadataBytes: Buffer,
  expectedServerId: string,
  serverPublicKeyDer: Buffer
): InitialOwnerBinding {
  if (
    metadataBytes.length === 0 ||
    metadataBytes.length > MAX_INITIAL_OWNER_METADATA_BYTES
  ) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  assertValidFingerprint(expectedServerId, 'SERVER_OWNER_BINDING_INVALID')
  const canonicalServerPublicKey = exportCanonicalEd25519PublicKey(
    parsePublicKey(serverPublicKeyDer),
    'SERVER_OWNER_BINDING_INVALID'
  )

  if (
    !canonicalServerPublicKey.equals(serverPublicKeyDer) ||
    calculateFingerprint(canonicalServerPublicKey) !== expectedServerId
  ) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  const metadata = parseMetadata(metadataBytes)

  if (metadata.serverId !== expectedServerId) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  const ownerPublicKeyDer = decodeCanonicalBase64(
    metadata.ownerDevicePublicKey,
    MAX_INITIAL_OWNER_PUBLIC_KEY_BASE64_LENGTH
  )
  const canonicalOwnerPublicKey = exportCanonicalEd25519PublicKey(
    parsePublicKey(ownerPublicKeyDer),
    'SERVER_OWNER_BINDING_INVALID'
  )

  if (!canonicalOwnerPublicKey.equals(ownerPublicKeyDer)) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  if (calculateFingerprint(ownerPublicKeyDer) !== metadata.ownerDeviceFingerprint) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  const signature = decodeCanonicalBase64(
    metadata.signature,
    MAX_INITIAL_OWNER_SIGNATURE_BASE64_LENGTH
  )

  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  const payload = encodeSigningPayload(
    metadata.serverId,
    metadata.ownerDeviceFingerprint,
    ownerPublicKeyDer,
    INITIAL_OWNER_BINDING_DOMAIN
  )
  const serverPublicKey = parsePublicKey(serverPublicKeyDer)

  if (!verify(null, payload, serverPublicKey, signature)) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  return createPublicBinding(metadata, ownerPublicKeyDer, signature)
}

function parseMetadata(metadataBytes: Buffer): InitialOwnerBindingMetadata {
  let value: unknown

  try {
    value = JSON.parse(metadataBytes.toString('utf8'))
  } catch {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  if (!isRecord(value)) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  if (value.version !== OWNER_BINDING_VERSION) {
    if (typeof value.version === 'number' && Number.isInteger(value.version)) {
      throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_VERSION_UNSUPPORTED')
    }

    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  const expectedKeys = [
    'ownerDeviceFingerprint',
    'ownerDevicePublicKey',
    'serverId',
    'signature',
    'type',
    'version'
  ]

  if (
    Object.keys(value).sort().join(',') !== expectedKeys.join(',') ||
    value.type !== OWNER_BINDING_TYPE ||
    typeof value.serverId !== 'string' ||
    typeof value.ownerDeviceFingerprint !== 'string' ||
    typeof value.ownerDevicePublicKey !== 'string' ||
    typeof value.signature !== 'string' ||
    !FINGERPRINT_PATTERN.test(value.serverId) ||
    !FINGERPRINT_PATTERN.test(value.ownerDeviceFingerprint)
  ) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  return {
    version: OWNER_BINDING_VERSION,
    type: OWNER_BINDING_TYPE,
    serverId: value.serverId,
    ownerDeviceFingerprint: value.ownerDeviceFingerprint,
    ownerDevicePublicKey: value.ownerDevicePublicKey,
    signature: value.signature
  }
}

function validateDeviceIdentity(
  identity: InitialOwnerDeviceIdentity,
  errorCode: Extract<
    InitialOwnerBindingErrorCode,
    'SERVER_OWNER_BINDING_CREATION_FAILED'
  >
): Buffer {
  assertValidFingerprint(identity.fingerprint, errorCode)

  if (!Buffer.isBuffer(identity.publicKey)) {
    throw new InitialOwnerBindingError(errorCode)
  }

  const publicKeyDer = Buffer.from(identity.publicKey)
  const canonicalPublicKey = exportCanonicalEd25519PublicKey(
    parsePublicKey(publicKeyDer, errorCode),
    errorCode
  )

  if (
    !canonicalPublicKey.equals(publicKeyDer) ||
    calculateFingerprint(publicKeyDer) !== identity.fingerprint
  ) {
    throw new InitialOwnerBindingError(errorCode)
  }

  return publicKeyDer
}

function encodeSigningPayload(
  serverId: string,
  ownerDeviceFingerprint: string,
  ownerDevicePublicKey: Buffer,
  domain: string
): Buffer {
  // Framing canônico: seis campos em ordem fixa, cada um precedido por uint32 BE.
  const fields = [
    Buffer.from(domain, 'utf8'),
    Buffer.from(String(OWNER_BINDING_VERSION), 'ascii'),
    Buffer.from(OWNER_BINDING_TYPE, 'utf8'),
    Buffer.from(serverId, 'ascii'),
    Buffer.from(ownerDeviceFingerprint, 'ascii'),
    ownerDevicePublicKey
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
  errorCode: InitialOwnerBindingErrorCode = 'SERVER_OWNER_BINDING_INVALID'
): KeyObject {
  try {
    return createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' })
  } catch {
    throw new InitialOwnerBindingError(errorCode)
  }
}

function exportCanonicalEd25519PublicKey(
  publicKey: KeyObject,
  errorCode: InitialOwnerBindingErrorCode
): Buffer {
  try {
    if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
      throw new InitialOwnerBindingError(errorCode)
    }

    return Buffer.from(publicKey.export({ format: 'der', type: 'spki' }))
  } catch (error) {
    if (error instanceof InitialOwnerBindingError) {
      throw error
    }

    throw new InitialOwnerBindingError(errorCode)
  }
}

function calculateFingerprint(publicKeyDer: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKeyDer).digest('hex')}`
}

function assertValidFingerprint(
  value: unknown,
  errorCode: InitialOwnerBindingErrorCode
): asserts value is string {
  if (typeof value !== 'string' || !FINGERPRINT_PATTERN.test(value)) {
    throw new InitialOwnerBindingError(errorCode)
  }
}

function decodeCanonicalBase64(value: string, maximumLength: number): Buffer {
  if (
    value.length === 0 ||
    value.length > maximumLength ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  const decoded = Buffer.from(value, 'base64')

  if (decoded.toString('base64') !== value) {
    throw new InitialOwnerBindingError('SERVER_OWNER_BINDING_INVALID')
  }

  return decoded
}

function createPublicBinding(
  metadata: InitialOwnerBindingMetadata,
  ownerPublicKeyDer: Buffer,
  signature: Buffer
): InitialOwnerBinding {
  const canonicalPublicKey = Buffer.from(ownerPublicKeyDer)
  const canonicalSignature = Buffer.from(signature)

  return Object.freeze({
    version: OWNER_BINDING_VERSION,
    type: OWNER_BINDING_TYPE,
    serverId: metadata.serverId,
    deviceFingerprint: metadata.ownerDeviceFingerprint,
    get publicKey(): Buffer {
      return Buffer.from(canonicalPublicKey)
    },
    get signature(): Buffer {
      return Buffer.from(canonicalSignature)
    }
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
