import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject
} from 'node:crypto'
import { lstat, mkdir, open, readFile, rename, rm, rmdir } from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve } from 'node:path'

import type { SafeStorage } from 'electron'

import {
  createDeviceAuthChallengeSigner,
  type SignDeviceAuthChallenge
} from './device-auth'

const IDENTITY_VERSION = 1
const IDENTITY_ALGORITHM = 'Ed25519'
const METADATA_FILE_NAME = 'identity.json'
const PRIVATE_KEY_FILE_NAME = 'private-key.enc'
const MAX_METADATA_BYTES = 8 * 1024
const MAX_ENCRYPTED_PRIVATE_KEY_BYTES = 64 * 1024
const MAX_PRIVATE_KEY_BASE64_LENGTH = 8 * 1024

type DeviceIdentitySafeStorage = Pick<
  SafeStorage,
  'decryptString' | 'encryptString' | 'getSelectedStorageBackend' | 'isEncryptionAvailable'
>

export type DeviceIdentityErrorCode =
  | 'SECURE_STORAGE_UNAVAILABLE'
  | 'IDENTITY_CORRUPTED'
  | 'IDENTITY_VERSION_UNSUPPORTED'
  | 'IDENTITY_KEY_MISMATCH'
  | 'IDENTITY_STORAGE_FAILED'
  | 'IDENTITY_CRYPTO_FAILED'

const ERROR_MESSAGES: Record<DeviceIdentityErrorCode, string> = {
  SECURE_STORAGE_UNAVAILABLE: 'O armazenamento seguro do sistema não está disponível.',
  IDENTITY_CORRUPTED: 'A identidade local está ausente, corrompida ou inválida.',
  IDENTITY_VERSION_UNSUPPORTED: 'A versão da identidade local não é suportada.',
  IDENTITY_KEY_MISMATCH: 'As chaves pública e privada da identidade não correspondem.',
  IDENTITY_STORAGE_FAILED: 'Não foi possível persistir a identidade local com segurança.',
  IDENTITY_CRYPTO_FAILED: 'Não foi possível processar a identidade criptográfica.'
}

export class DeviceIdentityError extends Error {
  readonly code: DeviceIdentityErrorCode

  constructor(code: DeviceIdentityErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'DeviceIdentityError'
    this.code = code
  }
}

export interface DeviceIdentity {
  readonly algorithm: typeof IDENTITY_ALGORITHM
  readonly fingerprint: string
  readonly publicKey: Buffer
  readonly signDeviceAuthChallenge: SignDeviceAuthChallenge
}

interface DeviceIdentityMetadata {
  readonly version: typeof IDENTITY_VERSION
  readonly algorithm: typeof IDENTITY_ALGORITHM
  readonly publicKey: string
  readonly fingerprint: string
}

export async function loadOrCreateDeviceIdentity(
  identityDirectory: string,
  secureStorage: DeviceIdentitySafeStorage,
  platform: NodeJS.Platform = process.platform
): Promise<DeviceIdentity> {
  assertSecureStorageAvailable(secureStorage, platform)
  assertIdentityDirectoryPath(identityDirectory)

  const directoryCreated = await createIdentityDirectory(identityDirectory)

  if (directoryCreated) {
    return createAndPersistIdentity(identityDirectory, secureStorage)
  }

  return loadIdentity(identityDirectory, secureStorage)
}

function assertSecureStorageAvailable(
  secureStorage: DeviceIdentitySafeStorage,
  platform: NodeJS.Platform
): void {
  try {
    if (!secureStorage.isEncryptionAvailable()) {
      throw new DeviceIdentityError('SECURE_STORAGE_UNAVAILABLE')
    }

    if (platform === 'linux') {
      const backend = secureStorage.getSelectedStorageBackend()

      if (backend === 'basic_text' || backend === 'unknown') {
        throw new DeviceIdentityError('SECURE_STORAGE_UNAVAILABLE')
      }
    }
  } catch (error) {
    if (error instanceof DeviceIdentityError) {
      throw error
    }

    throw new DeviceIdentityError('SECURE_STORAGE_UNAVAILABLE')
  }
}

function assertIdentityDirectoryPath(identityDirectory: string): void {
  if (!isAbsolute(identityDirectory) || resolve(identityDirectory) !== identityDirectory) {
    throw new DeviceIdentityError('IDENTITY_STORAGE_FAILED')
  }

  const resolvedDirectory = resolve(identityDirectory)
  const criticalFiles = [METADATA_FILE_NAME, PRIVATE_KEY_FILE_NAME]

  for (const fileName of criticalFiles) {
    const filePath = resolve(resolvedDirectory, fileName)

    if (dirname(filePath) !== resolvedDirectory) {
      throw new DeviceIdentityError('IDENTITY_STORAGE_FAILED')
    }
  }
}

async function createIdentityDirectory(identityDirectory: string): Promise<boolean> {
  try {
    await mkdir(identityDirectory, { mode: 0o700 })
    return true
  } catch (error) {
    if (!isErrorWithCode(error) || error.code !== 'EEXIST') {
      throw new DeviceIdentityError('IDENTITY_STORAGE_FAILED')
    }
  }

  try {
    const directoryStats = await lstat(identityDirectory)

    if (!directoryStats.isDirectory() || directoryStats.isSymbolicLink()) {
      throw new DeviceIdentityError('IDENTITY_CORRUPTED')
    }
  } catch (error) {
    if (error instanceof DeviceIdentityError) {
      throw error
    }

    throw new DeviceIdentityError('IDENTITY_STORAGE_FAILED')
  }

  return false
}

async function createAndPersistIdentity(
  identityDirectory: string,
  secureStorage: DeviceIdentitySafeStorage
): Promise<DeviceIdentity> {
  let identity: DeviceIdentity
  let metadata: DeviceIdentityMetadata
  let encryptedPrivateKey: Buffer

  try {
    const keyPair = generateKeyPairSync('ed25519')
    const publicKeyDer = keyPair.publicKey.export({ format: 'der', type: 'spki' })
    const privateKeyDer = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' })
    encryptedPrivateKey = protectPrivateKey(privateKeyDer, secureStorage)

    if (encryptedPrivateKey.length === 0) {
      throw new DeviceIdentityError('SECURE_STORAGE_UNAVAILABLE')
    }

    const fingerprint = calculateFingerprint(publicKeyDer)
    metadata = {
      version: IDENTITY_VERSION,
      algorithm: IDENTITY_ALGORITHM,
      publicKey: publicKeyDer.toString('base64'),
      fingerprint
    }
    identity = createDeviceIdentity(fingerprint, publicKeyDer, keyPair.privateKey)
  } catch (error) {
    await removeEmptyIdentityDirectory(identityDirectory)

    if (error instanceof DeviceIdentityError) {
      throw error
    }

    throw new DeviceIdentityError('IDENTITY_CRYPTO_FAILED')
  }

  const privateKeyPath = join(identityDirectory, PRIVATE_KEY_FILE_NAME)
  const metadataPath = join(identityDirectory, METADATA_FILE_NAME)
  let privateKeyCommitted = false

  try {
    await writeFileAtomically(privateKeyPath, encryptedPrivateKey)
    privateKeyCommitted = true
    await writeFileAtomically(metadataPath, Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`))
  } catch {
    if (!privateKeyCommitted) {
      await removeEmptyIdentityDirectory(identityDirectory)
    }

    throw new DeviceIdentityError('IDENTITY_STORAGE_FAILED')
  }

  return identity
}

async function loadIdentity(
  identityDirectory: string,
  secureStorage: DeviceIdentitySafeStorage
): Promise<DeviceIdentity> {
  const metadataBytes = await readCriticalFile(
    join(identityDirectory, METADATA_FILE_NAME),
    MAX_METADATA_BYTES
  )
  const encryptedPrivateKey = await readCriticalFile(
    join(identityDirectory, PRIVATE_KEY_FILE_NAME),
    MAX_ENCRYPTED_PRIVATE_KEY_BYTES
  )
  const metadata = parseMetadata(metadataBytes)
  const publicKeyDer = decodeCanonicalBase64(metadata.publicKey, MAX_METADATA_BYTES)
  const publicKey = parsePublicKey(publicKeyDer)
  const expectedFingerprint = calculateFingerprint(publicKeyDer)

  if (metadata.fingerprint !== expectedFingerprint) {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  const privateKeyDer = decryptPrivateKey(encryptedPrivateKey, secureStorage)
  let privateKey: KeyObject

  try {
    privateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' })
  } catch {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  } finally {
    privateKeyDer.fill(0)
  }

  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  const derivedPublicKey = createPublicKey(privateKey)

  if (!derivedPublicKey.equals(publicKey)) {
    throw new DeviceIdentityError('IDENTITY_KEY_MISMATCH')
  }

  return createDeviceIdentity(metadata.fingerprint, publicKeyDer, privateKey)
}

function createDeviceIdentity(
  fingerprint: string,
  publicKeySpki: Buffer,
  privateKey: KeyObject
): DeviceIdentity {
  const canonicalPublicKey = Buffer.from(publicKeySpki)

  return Object.freeze({
    algorithm: IDENTITY_ALGORITHM,
    fingerprint,
    get publicKey(): Buffer {
      return Buffer.from(canonicalPublicKey)
    },
    signDeviceAuthChallenge: createDeviceAuthChallengeSigner(privateKey)
  })
}

function parseMetadata(metadataBytes: Buffer): DeviceIdentityMetadata {
  let value: unknown

  try {
    value = JSON.parse(metadataBytes.toString('utf8'))
  } catch {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  if (!isRecord(value)) {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  if (value.version !== IDENTITY_VERSION) {
    if (typeof value.version === 'number' && Number.isInteger(value.version)) {
      throw new DeviceIdentityError('IDENTITY_VERSION_UNSUPPORTED')
    }

    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  const expectedKeys = ['algorithm', 'fingerprint', 'publicKey', 'version']

  if (
    Object.keys(value).sort().join(',') !== expectedKeys.join(',') ||
    value.algorithm !== IDENTITY_ALGORITHM ||
    typeof value.publicKey !== 'string' ||
    typeof value.fingerprint !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/.test(value.fingerprint)
  ) {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  return {
    version: IDENTITY_VERSION,
    algorithm: IDENTITY_ALGORITHM,
    publicKey: value.publicKey,
    fingerprint: value.fingerprint
  }
}

function parsePublicKey(publicKeyDer: Buffer): KeyObject {
  try {
    const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' })
    const canonicalPublicKey = publicKey.export({ format: 'der', type: 'spki' })

    if (
      publicKey.type !== 'public' ||
      publicKey.asymmetricKeyType !== 'ed25519' ||
      !canonicalPublicKey.equals(publicKeyDer)
    ) {
      throw new DeviceIdentityError('IDENTITY_CORRUPTED')
    }

    return publicKey
  } catch (error) {
    if (error instanceof DeviceIdentityError) {
      throw error
    }

    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }
}

function calculateFingerprint(publicKeyDer: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKeyDer).digest('hex')}`
}

function protectPrivateKey(
  privateKeyDer: Buffer,
  secureStorage: DeviceIdentitySafeStorage
): Buffer {
  try {
    return secureStorage.encryptString(privateKeyDer.toString('base64'))
  } catch {
    throw new DeviceIdentityError('SECURE_STORAGE_UNAVAILABLE')
  } finally {
    privateKeyDer.fill(0)
  }
}

function decryptPrivateKey(
  encryptedPrivateKey: Buffer,
  secureStorage: DeviceIdentitySafeStorage
): Buffer {
  let privateKeyBase64: string

  try {
    privateKeyBase64 = secureStorage.decryptString(encryptedPrivateKey)
  } catch {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  return decodeCanonicalBase64(privateKeyBase64, MAX_PRIVATE_KEY_BASE64_LENGTH)
}

function decodeCanonicalBase64(value: string, maximumLength: number): Buffer {
  if (
    value.length === 0 ||
    value.length > maximumLength ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  const decoded = Buffer.from(value, 'base64')

  if (decoded.toString('base64') !== value) {
    decoded.fill(0)
    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }

  return decoded
}

async function readCriticalFile(filePath: string, maximumBytes: number): Promise<Buffer> {
  try {
    const fileStats = await lstat(filePath)

    if (!fileStats.isFile() || fileStats.isSymbolicLink() || fileStats.size === 0) {
      throw new DeviceIdentityError('IDENTITY_CORRUPTED')
    }

    if (fileStats.size > maximumBytes) {
      throw new DeviceIdentityError('IDENTITY_CORRUPTED')
    }

    return await readFile(filePath)
  } catch (error) {
    if (error instanceof DeviceIdentityError) {
      throw error
    }

    throw new DeviceIdentityError('IDENTITY_CORRUPTED')
  }
}

async function writeFileAtomically(filePath: string, contents: Buffer): Promise<void> {
  const temporaryPath = `${filePath}.tmp`
  let fileHandle: Awaited<ReturnType<typeof open>> | undefined

  try {
    fileHandle = await open(temporaryPath, 'wx', 0o600)
    await fileHandle.writeFile(contents)
    await fileHandle.sync()
    await fileHandle.close()
    fileHandle = undefined
    await rename(temporaryPath, filePath)
  } catch {
    if (fileHandle) {
      await fileHandle.close().catch(() => undefined)
    }

    await rm(temporaryPath, { force: true }).catch(() => undefined)
    throw new DeviceIdentityError('IDENTITY_STORAGE_FAILED')
  }
}

async function removeEmptyIdentityDirectory(identityDirectory: string): Promise<void> {
  await rmdir(identityDirectory).catch(() => undefined)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isErrorWithCode(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error
}
