import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject
} from 'node:crypto'

import type { SafeStorage } from 'electron'

import {
  createInitialOwnerBinding,
  InitialOwnerBindingError,
  type InitialOwnerBinding,
  type InitialOwnerDeviceIdentity
} from './initial-owner-binding'

const SERVER_IDENTITY_VERSION = 1
const SERVER_IDENTITY_ALGORITHM = 'Ed25519'
const SERVER_ID_PATTERN = /^sha256:[0-9a-f]{64}$/

export const MAX_SERVER_IDENTITY_METADATA_BYTES = 4 * 1024
export const MAX_SERVER_PUBLIC_KEY_BASE64_LENGTH = 2 * 1024
export const MAX_SERVER_PRIVATE_KEY_BASE64_LENGTH = 4 * 1024
export const MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES = 16 * 1024

export type ServerIdentitySafeStorage = Pick<
  SafeStorage,
  'decryptString' | 'encryptString' | 'getSelectedStorageBackend' | 'isEncryptionAvailable'
>

export type ServerIdentityErrorCode =
  | 'SERVER_IDENTITY_CORRUPTED'
  | 'SERVER_IDENTITY_VERSION_UNSUPPORTED'
  | 'SERVER_IDENTITY_KEY_MISMATCH'
  | 'SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE'
  | 'SERVER_IDENTITY_INVALID_PUBLIC_KEY'
  | 'SERVER_IDENTITY_ID_MISMATCH'
  | 'SERVER_IDENTITY_CRYPTO_FAILED'

const ERROR_MESSAGES: Record<ServerIdentityErrorCode, string> = {
  SERVER_IDENTITY_CORRUPTED: 'A identidade criptográfica do servidor é inválida.',
  SERVER_IDENTITY_VERSION_UNSUPPORTED: 'A versão da identidade do servidor não é suportada.',
  SERVER_IDENTITY_KEY_MISMATCH: 'As chaves da identidade do servidor não correspondem.',
  SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE:
    'O armazenamento seguro da identidade do servidor não está disponível.',
  SERVER_IDENTITY_INVALID_PUBLIC_KEY: 'A chave pública da identidade do servidor é inválida.',
  SERVER_IDENTITY_ID_MISMATCH: 'O identificador criptográfico do servidor não corresponde.',
  SERVER_IDENTITY_CRYPTO_FAILED: 'Não foi possível gerar a identidade criptográfica do servidor.'
}

export class ServerIdentityError extends Error {
  readonly code: ServerIdentityErrorCode

  constructor(code: ServerIdentityErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'ServerIdentityError'
    this.code = code
  }
}

export interface ServerIdentity {
  readonly version: typeof SERVER_IDENTITY_VERSION
  readonly algorithm: typeof SERVER_IDENTITY_ALGORITHM
  readonly serverId: string
  readonly publicKey: Buffer
}

interface ServerIdentityMetadata {
  readonly version: typeof SERVER_IDENTITY_VERSION
  readonly algorithm: typeof SERVER_IDENTITY_ALGORITHM
  readonly publicKey: string
  readonly fingerprint: string
}

export interface ServerIdentityMaterial {
  readonly identity: ServerIdentity
  readonly metadataBytes: Buffer
  readonly encryptedPrivateKey: Buffer
  readonly initialOwner: InitialOwnerBinding
  readonly initialOwnerMetadataBytes: Buffer
}

type GenerateServerKeyPair = () => {
  readonly publicKey: KeyObject
  readonly privateKey: KeyObject
}

export function assertServerIdentitySecureStorageAvailable(
  secureStorage: ServerIdentitySafeStorage,
  platform: NodeJS.Platform = process.platform
): void {
  try {
    if (!secureStorage.isEncryptionAvailable()) {
      throw new ServerIdentityError('SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE')
    }

    if (platform === 'linux') {
      const backend = secureStorage.getSelectedStorageBackend()

      if (backend === 'basic_text' || backend === 'unknown') {
        throw new ServerIdentityError('SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE')
      }
    }
  } catch (error) {
    if (error instanceof ServerIdentityError) {
      throw error
    }

    throw new ServerIdentityError('SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE')
  }
}

export function createServerIdentityMaterial(
  secureStorage: ServerIdentitySafeStorage,
  ownerDeviceIdentity: InitialOwnerDeviceIdentity,
  platform: NodeJS.Platform = process.platform,
  generateKeyPair: GenerateServerKeyPair = () => generateKeyPairSync('ed25519')
): ServerIdentityMaterial {
  assertServerIdentitySecureStorageAvailable(secureStorage, platform)

  let privateKeyDer: Buffer | undefined

  try {
    const keyPair = generateKeyPair()

    if (
      keyPair.publicKey.type !== 'public' ||
      keyPair.publicKey.asymmetricKeyType !== 'ed25519' ||
      keyPair.privateKey.type !== 'private' ||
      keyPair.privateKey.asymmetricKeyType !== 'ed25519' ||
      !createPublicKey(keyPair.privateKey).equals(keyPair.publicKey)
    ) {
      throw new ServerIdentityError('SERVER_IDENTITY_CRYPTO_FAILED')
    }

    const publicKeyDer = Buffer.from(
      keyPair.publicKey.export({ format: 'der', type: 'spki' })
    )
    privateKeyDer = Buffer.from(keyPair.privateKey.export({ format: 'der', type: 'pkcs8' }))

    const serverId = calculateServerId(publicKeyDer)
    const initialOwnerMaterial = createInitialOwnerBinding(
      serverId,
      ownerDeviceIdentity,
      keyPair.privateKey
    )
    const encryptedPrivateKey = protectPrivateKey(privateKeyDer, secureStorage)
    const metadata: ServerIdentityMetadata = {
      version: SERVER_IDENTITY_VERSION,
      algorithm: SERVER_IDENTITY_ALGORITHM,
      publicKey: publicKeyDer.toString('base64'),
      fingerprint: serverId
    }
    const metadataBytes = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8')

    if (
      metadataBytes.length > MAX_SERVER_IDENTITY_METADATA_BYTES ||
      encryptedPrivateKey.length === 0 ||
      encryptedPrivateKey.length > MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES
    ) {
      throw new ServerIdentityError('SERVER_IDENTITY_CRYPTO_FAILED')
    }

    return Object.freeze({
      identity: createPublicServerIdentity(serverId, publicKeyDer),
      metadataBytes,
      encryptedPrivateKey: Buffer.from(encryptedPrivateKey),
      initialOwner: initialOwnerMaterial.binding,
      initialOwnerMetadataBytes: initialOwnerMaterial.metadataBytes
    })
  } catch (error) {
    if (error instanceof ServerIdentityError || error instanceof InitialOwnerBindingError) {
      throw error
    }

    throw new ServerIdentityError('SERVER_IDENTITY_CRYPTO_FAILED')
  } finally {
    privateKeyDer?.fill(0)
  }
}

export function loadServerIdentity(
  metadataBytes: Buffer,
  encryptedPrivateKey: Buffer,
  secureStorage: ServerIdentitySafeStorage,
  platform: NodeJS.Platform = process.platform
): ServerIdentity {
  assertServerIdentitySecureStorageAvailable(secureStorage, platform)

  if (
    metadataBytes.length === 0 ||
    metadataBytes.length > MAX_SERVER_IDENTITY_METADATA_BYTES ||
    encryptedPrivateKey.length === 0 ||
    encryptedPrivateKey.length > MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES
  ) {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  const metadata = parseIdentityMetadata(metadataBytes)
  const publicKeyDer = decodeCanonicalBase64(
    metadata.publicKey,
    MAX_SERVER_PUBLIC_KEY_BASE64_LENGTH
  )
  const publicKey = parsePublicKey(publicKeyDer)
  const expectedServerId = calculateServerId(publicKeyDer)

  if (metadata.fingerprint !== expectedServerId) {
    throw new ServerIdentityError('SERVER_IDENTITY_ID_MISMATCH')
  }

  const privateKeyDer = decryptPrivateKey(encryptedPrivateKey, secureStorage)
  let privateKey: KeyObject

  try {
    privateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' })
  } catch {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  } finally {
    privateKeyDer.fill(0)
  }

  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  if (!createPublicKey(privateKey).equals(publicKey)) {
    throw new ServerIdentityError('SERVER_IDENTITY_KEY_MISMATCH')
  }

  return createPublicServerIdentity(expectedServerId, publicKeyDer)
}

export function calculateServerId(publicKeyDer: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKeyDer).digest('hex')}`
}

export function isValidServerId(value: unknown): value is string {
  return typeof value === 'string' && SERVER_ID_PATTERN.test(value)
}

function createPublicServerIdentity(serverId: string, publicKeyDer: Buffer): ServerIdentity {
  const canonicalPublicKey = Buffer.from(publicKeyDer)

  return Object.freeze({
    version: SERVER_IDENTITY_VERSION,
    algorithm: SERVER_IDENTITY_ALGORITHM,
    serverId,
    get publicKey(): Buffer {
      return Buffer.from(canonicalPublicKey)
    }
  })
}

function parseIdentityMetadata(metadataBytes: Buffer): ServerIdentityMetadata {
  let value: unknown

  try {
    value = JSON.parse(metadataBytes.toString('utf8'))
  } catch {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  if (!isRecord(value)) {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  if (value.version !== SERVER_IDENTITY_VERSION) {
    if (typeof value.version === 'number' && Number.isInteger(value.version)) {
      throw new ServerIdentityError('SERVER_IDENTITY_VERSION_UNSUPPORTED')
    }

    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  const expectedKeys = ['algorithm', 'fingerprint', 'publicKey', 'version']

  if (
    Object.keys(value).sort().join(',') !== expectedKeys.join(',') ||
    value.algorithm !== SERVER_IDENTITY_ALGORITHM ||
    typeof value.publicKey !== 'string' ||
    typeof value.fingerprint !== 'string' ||
    !SERVER_ID_PATTERN.test(value.fingerprint)
  ) {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  return {
    version: SERVER_IDENTITY_VERSION,
    algorithm: SERVER_IDENTITY_ALGORITHM,
    publicKey: value.publicKey,
    fingerprint: value.fingerprint
  }
}

function parsePublicKey(publicKeyDer: Buffer): KeyObject {
  try {
    const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' })
    const canonicalPublicKey = Buffer.from(publicKey.export({ format: 'der', type: 'spki' }))

    if (
      publicKey.type !== 'public' ||
      publicKey.asymmetricKeyType !== 'ed25519' ||
      !canonicalPublicKey.equals(publicKeyDer)
    ) {
      throw new ServerIdentityError('SERVER_IDENTITY_INVALID_PUBLIC_KEY')
    }

    return publicKey
  } catch (error) {
    if (error instanceof ServerIdentityError) {
      throw error
    }

    throw new ServerIdentityError('SERVER_IDENTITY_INVALID_PUBLIC_KEY')
  }
}

function protectPrivateKey(
  privateKeyDer: Buffer,
  secureStorage: ServerIdentitySafeStorage
): Buffer {
  try {
    return secureStorage.encryptString(privateKeyDer.toString('base64'))
  } catch {
    throw new ServerIdentityError('SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE')
  }
}

function decryptPrivateKey(
  encryptedPrivateKey: Buffer,
  secureStorage: ServerIdentitySafeStorage
): Buffer {
  let privateKeyBase64: string

  try {
    privateKeyBase64 = secureStorage.decryptString(encryptedPrivateKey)
  } catch {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  return decodeCanonicalBase64(privateKeyBase64, MAX_SERVER_PRIVATE_KEY_BASE64_LENGTH)
}

function decodeCanonicalBase64(value: string, maximumLength: number): Buffer {
  if (
    value.length === 0 ||
    value.length > maximumLength ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  const decoded = Buffer.from(value, 'base64')

  if (decoded.toString('base64') !== value) {
    decoded.fill(0)
    throw new ServerIdentityError('SERVER_IDENTITY_CORRUPTED')
  }

  return decoded
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
