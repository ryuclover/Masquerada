import { mkdtemp, mkdir, readFile, rm, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  loadOrCreateDeviceIdentity,
  type DeviceIdentityErrorCode
} from './device-identity'
import {
  generateDeviceAuthChallenge,
  verifyDeviceAuthSignature
} from './device-auth'

const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('identidade criptográfica do dispositivo', () => {
  it('gera e persiste uma identidade Ed25519 quando ela não existe', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()

    const identity = await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    const metadata = await readMetadata(identityDirectory)

    expect(identity.algorithm).toBe('Ed25519')
    expect(Buffer.isBuffer(identity.publicKey)).toBe(true)
    expect(identity).not.toHaveProperty('privateKey')
    expect(metadata).toMatchObject({
      version: 1,
      algorithm: 'Ed25519',
      fingerprint: identity.fingerprint
    })
    await expect(readFile(join(identityDirectory, 'private-key.enc'))).resolves.not.toHaveLength(0)
  })

  it('carrega a mesma identidade em uma segunda inicialização', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    const created = await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)

    const loaded = await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    const challenge = generateDeviceAuthChallenge()
    const signature = loaded.signDeviceAuthChallenge(challenge)

    expect(loaded.fingerprint).toBe(created.fingerprint)
    expect(loaded.publicKey.equals(created.publicKey)).toBe(true)
    expect(verifyDeviceAuthSignature(loaded.publicKey, challenge, signature)).toBe(true)
    expect(fake.encryptCalls()).toBe(1)
  })

  it('não expõe private key nem plaintext PKCS#8 pela API carregada', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()

    const identity = await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)

    expect(Object.keys(identity).sort()).toEqual([
      'algorithm',
      'fingerprint',
      'publicKey',
      'signDeviceAuthChallenge'
    ])
    expect(identity).not.toHaveProperty('privateKey')
    expect(identity).not.toHaveProperty('privateKeyDer')
    expect(identity).not.toHaveProperty('privateKeyBase64')
    expect(JSON.stringify(identity)).not.toContain(fake.protectedPlaintexts()[0])
  })

  it('persiste apenas o ciphertext retornado pelo armazenamento seguro', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()

    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)

    const encryptedFile = await readFile(join(identityDirectory, 'private-key.enc'))
    const metadataFile = await readFile(join(identityDirectory, 'identity.json'), 'utf8')
    const privateKeyPlaintext = fake.protectedPlaintexts()[0]

    expect(privateKeyPlaintext).toBeDefined()
    expect(encryptedFile.toString('utf8')).not.toContain(privateKeyPlaintext)
    expect(metadataFile).not.toContain(privateKeyPlaintext)
    expect(metadataFile).not.toContain('privateKey')
  })

  it('falha sem criar arquivos quando o armazenamento seguro está indisponível', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage({ available: false })

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'SECURE_STORAGE_UNAVAILABLE'
    )
    await expect(readFile(join(identityDirectory, 'identity.json'))).rejects.toMatchObject({
      code: 'ENOENT'
    })
    expect(fake.encryptCalls()).toBe(0)
  })

  it('rejeita o backend Linux sem secret store', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage({ backend: 'basic_text' })

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage, 'linux'),
      'SECURE_STORAGE_UNAVAILABLE'
    )
    expect(fake.encryptCalls()).toBe(0)
  })

  it('falha sem fallback quando a operação de proteção do sistema falha', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage({ encryptionFails: true })

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'SECURE_STORAGE_UNAVAILABLE'
    )
    await expect(readFile(join(identityDirectory, 'private-key.enc'))).rejects.toMatchObject({
      code: 'ENOENT'
    })
  })

  it('rejeita metadata adulterado', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    const metadata = await readMetadata(identityDirectory)
    metadata.algorithm = 'X25519'
    await writeMetadata(identityDirectory, metadata)

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_CORRUPTED'
    )
  })

  it('rejeita a private key protegida quando adulterada', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    await writeFile(join(identityDirectory, 'private-key.enc'), 'ciphertext-adulterado')

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_CORRUPTED'
    )
  })

  it('rejeita fingerprint adulterado', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    const metadata = await readMetadata(identityDirectory)
    metadata.fingerprint = `sha256:${'0'.repeat(64)}`
    await writeMetadata(identityDirectory, metadata)

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_CORRUPTED'
    )
  })

  it('rejeita chaves pública e privada de keypairs diferentes', async () => {
    const firstDirectory = await createIdentityDirectoryPath()
    const secondDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(firstDirectory, fake.storage)
    await loadOrCreateDeviceIdentity(secondDirectory, fake.storage)
    const secondMetadata = await readMetadata(secondDirectory)
    await writeMetadata(firstDirectory, secondMetadata)

    await expectIdentityError(
      loadOrCreateDeviceIdentity(firstDirectory, fake.storage),
      'IDENTITY_KEY_MISMATCH'
    )
  })

  it('rejeita versão desconhecida', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    const metadata = await readMetadata(identityDirectory)
    metadata.version = 2
    await writeMetadata(identityDirectory, metadata)

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_VERSION_UNSUPPORTED'
    )
  })

  it('rejeita JSON corrompido sem regenerar a identidade', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    await writeFile(join(identityDirectory, 'identity.json'), '{')

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_CORRUPTED'
    )
    expect(fake.encryptCalls()).toBe(1)
  })

  it('rejeita persistência parcial sem regenerar a identidade', async () => {
    const identityDirectory = await createIdentityDirectoryPath()
    const fake = createFakeSecureStorage()
    await loadOrCreateDeviceIdentity(identityDirectory, fake.storage)
    await unlink(join(identityDirectory, 'private-key.enc'))

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_CORRUPTED'
    )
    expect(fake.encryptCalls()).toBe(1)
  })

  it('rejeita um diretório de identidade que seja symlink', async () => {
    const root = await createTestRoot()
    const target = join(root, 'target')
    const identityDirectory = join(root, 'identity')
    const fake = createFakeSecureStorage()
    await mkdir(target)

    try {
      const { symlink } = await import('node:fs/promises')
      await symlink(target, identityDirectory, 'junction')
    } catch (error) {
      if (isPermissionError(error)) {
        return
      }
      throw error
    }

    await expectIdentityError(
      loadOrCreateDeviceIdentity(identityDirectory, fake.storage),
      'IDENTITY_CORRUPTED'
    )
  })
})

async function createTestRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-identity-'))
  testRoots.push(root)
  return root
}

async function createIdentityDirectoryPath(): Promise<string> {
  return join(await createTestRoot(), 'identity')
}

async function readMetadata(identityDirectory: string): Promise<Record<string, unknown>> {
  const contents = await readFile(join(identityDirectory, 'identity.json'), 'utf8')
  return JSON.parse(contents) as Record<string, unknown>
}

async function writeMetadata(
  identityDirectory: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeFile(join(identityDirectory, 'identity.json'), JSON.stringify(metadata))
}

async function expectIdentityError(
  operation: Promise<unknown>,
  code: DeviceIdentityErrorCode
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code })
}

function createFakeSecureStorage(
  options: {
    available?: boolean
    backend?: 'basic_text' | 'gnome_libsecret'
    encryptionFails?: boolean
  } = {}
) {
  const plaintextByCiphertext = new Map<string, string>()
  const plaintexts: string[] = []
  let encryptionCount = 0

  return {
    storage: {
      isEncryptionAvailable: () => options.available ?? true,
      getSelectedStorageBackend: () => options.backend ?? 'gnome_libsecret',
      encryptString: (plaintext: string) => {
        encryptionCount += 1

        if (options.encryptionFails) {
          throw new Error('Falha simulada do armazenamento seguro.')
        }

        plaintexts.push(plaintext)
        const ciphertext = `protected:${encryptionCount}`
        plaintextByCiphertext.set(ciphertext, plaintext)
        return Buffer.from(ciphertext)
      },
      decryptString: (encrypted: Buffer) => {
        const plaintext = plaintextByCiphertext.get(encrypted.toString('utf8'))

        if (!plaintext) {
          throw new Error('Ciphertext de teste inválido.')
        }

        return plaintext
      }
    },
    encryptCalls: () => encryptionCount,
    protectedPlaintexts: () => plaintexts
  }
}

function isPermissionError(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'EPERM'
}
