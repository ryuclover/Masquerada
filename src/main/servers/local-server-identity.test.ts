import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  unlink,
  writeFile
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  createLocalServerStorage,
  type LocalServerStorageErrorCode
} from './local-server-storage'
import {
  calculateServerId,
  createServerIdentityMaterial,
  MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES,
  MAX_SERVER_IDENTITY_METADATA_BYTES,
  type ServerIdentityErrorCode
} from './server-identity'

const FIRST_ID = '11111111111111111111111111111111'
const SECOND_ID = '22222222222222222222222222222222'
const TEST_DEVICE_IDENTITY = createTestDeviceIdentity()
const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('identidade integrada ao servidor local', () => {
  it('cria a estrutura mínima completa e referencia o serverId', async () => {
    const fixture = await createFixture()
    const serverMetadata = await readJson(fixture.paths.serverMetadata)
    const identityMetadata = await readJson(fixture.paths.identityMetadata)
    const encryptedPrivateKey = await readFile(fixture.paths.privateKey)

    expect((await readdir(fixture.paths.serverDirectory)).sort()).toEqual([
      'authority',
      'identity',
      'server.db',
      'server.json'
    ])
    expect((await readdir(fixture.paths.identityDirectory)).sort()).toEqual([
      'identity.json',
      'private-key.enc'
    ])
    expect(serverMetadata).toEqual({
      version: 1,
      localStorageId: FIRST_ID,
      displayName: 'Servidor',
      serverId: fixture.server.serverId
    })
    expect(identityMetadata).toMatchObject({
      version: 1,
      algorithm: 'Ed25519',
      fingerprint: fixture.server.serverId
    })
    expect(encryptedPrivateKey.length).toBeGreaterThan(0)
  })

  it('faz serverId corresponder exatamente ao SHA-256 da SPKI', async () => {
    const fixture = await createFixture()
    const identityMetadata = await readJson(fixture.paths.identityMetadata)
    const publicKeyDer = Buffer.from(String(identityMetadata.publicKey), 'base64')

    expect(fixture.server.serverId).toBe(calculateServerId(publicKeyDer))
    expect(fixture.server.serverId).not.toBe(fixture.server.localStorageId)
    expect(fixture.server.identity.publicKey).toEqual(publicKeyDer)
  })

  it('preserva serverId e public key em uma nova instância', async () => {
    const fixture = await createFixture()
    const reloaded = await createLocalServerStorage(
      fixture.userData,
      fixture.fake.storage,
      TEST_DEVICE_IDENTITY
    ).loadLocalServer(FIRST_ID)

    expect(reloaded.serverId).toBe(fixture.server.serverId)
    expect(reloaded.identity.publicKey).toEqual(fixture.server.identity.publicKey)
  })

  it('gera identidades distintas para dois servidores do mesmo dispositivo', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const storage = storageWithIds(userData, fake, [FIRST_ID, SECOND_ID])
    const first = await storage.createLocalServer('Primeiro')
    const second = await storage.createLocalServer('Segundo')

    expect(second.serverId).not.toBe(first.serverId)
    expect(second.identity.publicKey).not.toEqual(first.identity.publicKey)
  })

  it('não reutiliza a identidade criptográfica de um dispositivo', async () => {
    const fixture = await createFixture()
    const devicePublicKey = generateKeyPairSync('ed25519').publicKey.export({
      format: 'der',
      type: 'spki'
    })
    const deviceFingerprint = calculateServerId(devicePublicKey)

    expect(fixture.server.serverId).not.toBe(deviceFingerprint)
    expect(fixture.server.identity.publicKey).not.toEqual(devicePublicKey)
  })

  it('não persiste PKCS#8 plaintext em nenhum arquivo do servidor', async () => {
    const fixture = await createFixture()
    const protectedPlaintext = fixture.fake.plaintexts()[0]
    const persistedFiles = await Promise.all([
      readFile(fixture.paths.serverMetadata),
      readFile(fixture.paths.identityMetadata),
      readFile(fixture.paths.privateKey)
    ])

    expect(protectedPlaintext).toBeDefined()

    for (const contents of persistedFiles) {
      expect(contents.toString('utf8')).not.toContain(protectedPlaintext)
    }

    expect(fixture.server).not.toHaveProperty('privateKey')
    expect(fixture.server.identity).not.toHaveProperty('privateKey')
  })

  it('rejeita serverId adulterado em server.json', async () => {
    const fixture = await createFixture()
    const metadata = await readJson(fixture.paths.serverMetadata)
    metadata.serverId = `sha256:${'0'.repeat(64)}`
    await writeJson(fixture.paths.serverMetadata, metadata)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_ID_MISMATCH'
    )
  })

  it('rejeita identidade copiada de outro servidor', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const storage = storageWithIds(userData, fake, [FIRST_ID, SECOND_ID])
    await storage.createLocalServer('Primeiro')
    await storage.createLocalServer('Segundo')
    const firstIdentity = join(userData, 'servers', FIRST_ID, 'identity')
    const secondIdentity = join(userData, 'servers', SECOND_ID, 'identity')
    await rm(firstIdentity, { recursive: true })
    await cp(secondIdentity, firstIdentity, { recursive: true })

    await expectStorageError(storage.loadLocalServer(FIRST_ID), 'SERVER_IDENTITY_ID_MISMATCH')
  })

  it('rejeita public key trocada mesmo com fingerprint correspondente', async () => {
    const pair = await createTwoServerFixture()
    const firstMetadata = await readJson(pair.firstPaths.identityMetadata)
    const secondMetadata = await readJson(pair.secondPaths.identityMetadata)
    firstMetadata.publicKey = secondMetadata.publicKey
    firstMetadata.fingerprint = secondMetadata.fingerprint
    await writeJson(pair.firstPaths.identityMetadata, firstMetadata)

    await expectStorageError(
      pair.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_KEY_MISMATCH'
    )
  })

  it('rejeita private key trocada', async () => {
    const pair = await createTwoServerFixture()
    await copyFile(pair.secondPaths.privateKey, pair.firstPaths.privateKey)

    await expectStorageError(
      pair.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_KEY_MISMATCH'
    )
  })

  it.each([
    ['ausente', async (path: string) => unlink(path)],
    ['vazio', async (path: string) => writeFile(path, Buffer.alloc(0))],
    [
      'acima do limite',
      async (path: string) => writeFile(path, Buffer.alloc(MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES + 1))
    ]
  ])('rejeita private-key.enc %s', async (_caseName, mutate) => {
    const fixture = await createFixture()
    await mutate(fixture.paths.privateKey)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_CORRUPTED'
    )
  })

  it('rejeita identity metadata acima do limite no filesystem', async () => {
    const fixture = await createFixture()
    await writeFile(
      fixture.paths.identityMetadata,
      Buffer.alloc(MAX_SERVER_IDENTITY_METADATA_BYTES + 1)
    )

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_CORRUPTED'
    )
  })

  it('rejeita identity/ como junction quando reproduzível', async () => {
    const fixture = await createFixture()
    const target = join(fixture.userData, 'identity-target')
    await cp(fixture.paths.identityDirectory, target, { recursive: true })
    await rm(fixture.paths.identityDirectory, { recursive: true })

    try {
      await symlink(target, fixture.paths.identityDirectory, 'junction')
    } catch (error) {
      if (isPermissionError(error)) return
      throw error
    }

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_PATH_UNSAFE'
    )
  })

  it.each(['identityMetadata', 'privateKey'] as const)(
    'rejeita %s como symlink quando reproduzível',
    async (fileName) => {
      const fixture = await createFixture()
      const filePath = fixture.paths[fileName]
      const target = join(fixture.userData, `${fileName}-target`)
      await copyFile(filePath, target)
      await unlink(filePath)

      try {
        await symlink(target, filePath, 'file')
      } catch (error) {
        if (isPermissionError(error)) return
        throw error
      }

      await expectStorageError(
        fixture.storage.loadLocalServer(FIRST_ID),
        'SERVER_IDENTITY_PATH_UNSAFE'
      )
    }
  )

  it('rejeita arquivo no lugar de identity/', async () => {
    const fixture = await createFixture()
    await rm(fixture.paths.identityDirectory, { recursive: true })
    await writeFile(fixture.paths.identityDirectory, 'não é diretório')

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_PATH_UNSAFE'
    )
  })

  it.each(['identityMetadata', 'privateKey'] as const)(
    'rejeita diretório no lugar de %s',
    async (fileName) => {
      const fixture = await createFixture()
      await unlink(fixture.paths[fileName])
      await mkdir(fixture.paths[fileName])

      await expectStorageError(
        fixture.storage.loadLocalServer(FIRST_ID),
        'SERVER_IDENTITY_CORRUPTED'
      )
    }
  )

  it('não publica servidor quando a geração de identidade falha', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const storage = createLocalServerStorage(userData, fake.storage, TEST_DEVICE_IDENTITY, {
      generateStorageId: () => FIRST_ID,
      createIdentityMaterial: () => {
        throw new Error('Falha simulada de geração.')
      }
    })

    await expectStorageError(storage.createLocalServer('Falha'), 'SERVER_IDENTITY_CRYPTO_FAILED')
    await expect(readdir(join(userData, 'servers'))).resolves.toEqual([])
  })

  it('não publica servidor quando a proteção da private key falha', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage({ encryptionFails: true })
    const storage = storageWithIds(userData, fake, [FIRST_ID])

    await expectStorageError(
      storage.createLocalServer('Falha'),
      'SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE'
    )
    await expect(readdir(join(userData, 'servers'))).resolves.toEqual([])
  })

  it('remove staging quando a gravação da identidade falha', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const validMaterial = createServerIdentityMaterial(
      fake.storage,
      TEST_DEVICE_IDENTITY,
      'win32'
    )
    const storage = createLocalServerStorage(userData, fake.storage, TEST_DEVICE_IDENTITY, {
      generateStorageId: () => FIRST_ID,
      platform: 'win32',
      createIdentityMaterial: () => ({
        ...validMaterial,
        metadataBytes: Buffer.alloc(MAX_SERVER_IDENTITY_METADATA_BYTES + 1)
      })
    })

    await expectStorageError(storage.createLocalServer('Falha'), 'SERVER_CREATION_FAILED')
    await expect(readdir(join(userData, 'servers'))).resolves.toEqual([])
  })

  it('não reconhece publicação parcial sem server.json', async () => {
    const fixture = await createFixture()
    await unlink(fixture.paths.serverMetadata)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_METADATA_CORRUPTED'
    )
  })

  it('nunca regenera identidade quando private-key.enc está corrompido', async () => {
    const fixture = await createFixture()
    const serverMetadataBefore = await readFile(fixture.paths.serverMetadata)
    const identityMetadataBefore = await readFile(fixture.paths.identityMetadata)
    await writeFile(fixture.paths.privateKey, 'ciphertext adulterado')
    const privateKeyBeforeLoad = await readFile(fixture.paths.privateKey)
    const encryptionCallsBeforeLoad = fixture.fake.encryptCalls()

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_IDENTITY_CORRUPTED'
    )

    expect(fixture.fake.encryptCalls()).toBe(encryptionCallsBeforeLoad)
    expect(await readFile(fixture.paths.serverMetadata)).toEqual(serverMetadataBefore)
    expect(await readFile(fixture.paths.identityMetadata)).toEqual(identityMetadataBefore)
    expect(await readFile(fixture.paths.privateKey)).toEqual(privateKeyBeforeLoad)
  })
})

async function createFixture() {
  const userData = await createUserData()
  const fake = createFakeSecureStorage()
  const storage = storageWithIds(userData, fake, [FIRST_ID])
  const server = await storage.createLocalServer('Servidor')
  return { userData, fake, storage, server, paths: serverPaths(userData, FIRST_ID) }
}

async function createTwoServerFixture() {
  const userData = await createUserData()
  const fake = createFakeSecureStorage()
  const storage = storageWithIds(userData, fake, [FIRST_ID, SECOND_ID])
  await storage.createLocalServer('Primeiro')
  await storage.createLocalServer('Segundo')
  return {
    storage,
    firstPaths: serverPaths(userData, FIRST_ID),
    secondPaths: serverPaths(userData, SECOND_ID)
  }
}

function serverPaths(userData: string, storageId: string) {
  const serverDirectory = join(userData, 'servers', storageId)
  const identityDirectory = join(serverDirectory, 'identity')
  return {
    serverDirectory,
    serverMetadata: join(serverDirectory, 'server.json'),
    identityDirectory,
    identityMetadata: join(identityDirectory, 'identity.json'),
    privateKey: join(identityDirectory, 'private-key.enc')
  }
}

async function createUserData(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-server-identity-'))
  testRoots.push(root)
  return root
}

function storageWithIds(
  userData: string,
  fake: ReturnType<typeof createFakeSecureStorage>,
  ids: string[]
) {
  let index = 0
  return createLocalServerStorage(userData, fake.storage, TEST_DEVICE_IDENTITY, {
    platform: 'win32',
    generateStorageId: () => ids[index++] ?? ids.at(-1) ?? FIRST_ID
  })
}

async function readJson(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
}

async function writeJson(path: string, value: Record<string, unknown>): Promise<void> {
  await writeFile(path, JSON.stringify(value))
}

async function expectStorageError(
  operation: Promise<unknown>,
  code: LocalServerStorageErrorCode | ServerIdentityErrorCode
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code })
}

function isPermissionError(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'EPERM'
}

function createFakeSecureStorage(
  options: { encryptionFails?: boolean } = {}
) {
  const plaintextByCiphertext = new Map<string, string>()
  const protectedPlaintexts: string[] = []
  let encryptionCount = 0

  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (plaintext: string) => {
        if (options.encryptionFails) {
          throw new Error('Falha simulada de proteção.')
        }

        encryptionCount += 1
        protectedPlaintexts.push(plaintext)
        const ciphertext = `server-protected:${encryptionCount}`
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
    plaintexts: () => protectedPlaintexts,
    encryptCalls: () => encryptionCount
  }
}

function createTestDeviceIdentity() {
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({
    format: 'der',
    type: 'spki'
  })

  return {
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey: Buffer.from(publicKey)
  }
}
