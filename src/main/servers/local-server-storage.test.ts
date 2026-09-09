import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  link,
  lstat,
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
  MAX_DISPLAY_NAME_CODE_POINTS,
  MAX_SERVER_METADATA_BYTES,
  MAX_STORAGE_ID_COLLISION_ATTEMPTS,
  type LocalServerStorageErrorCode
} from './local-server-storage'

const FIRST_ID = '0123456789abcdef0123456789abcdef'
const SECOND_ID = 'fedcba9876543210fedcba9876543210'
const VALID_SERVER_ID = `sha256:${'0'.repeat(64)}`
const TEST_DEVICE_IDENTITY = createTestDeviceIdentity()
const testRoots: string[] = []
const secureStorageByUserData = new Map<string, ReturnType<typeof createFakeSecureStorage>>()

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
  secureStorageByUserData.clear()
})

describe('filesystem local de servidores', () => {
  it('cria somente o diretório interno e o server.json mínimo', async () => {
    const userData = await createUserData()
    const storage = storageWithIds(userData, [FIRST_ID])

    const created = await storage.createLocalServer('Meu servidor')
    const serverDirectory = join(userData, 'servers', FIRST_ID)
    const persisted = JSON.parse(
      await readFile(join(serverDirectory, 'server.json'), 'utf8')
    ) as unknown

    expect(created).toMatchObject({
      version: 1,
      localStorageId: FIRST_ID,
      displayName: 'Meu servidor'
    })
    expect((await readdir(serverDirectory)).sort()).toEqual([
      'authority',
      'identity',
      'server.db',
      'server.json'
    ])
    expect((await readdir(join(serverDirectory, 'identity'))).sort()).toEqual([
      'identity.json',
      'private-key.enc'
    ])
    expect(persisted).toEqual({
      version: 1,
      localStorageId: FIRST_ID,
      displayName: 'Meu servidor',
      serverId: created.serverId
    })
  })

  it('carrega o servidor criado pelo storage ID', async () => {
    const userData = await createUserData()
    const storage = storageWithIds(userData, [FIRST_ID])
    const created = await storage.createLocalServer('Comunidade')

    await expect(storage.loadLocalServer(created.localStorageId)).resolves.toEqual(created)
  })

  it('preserva um displayName Unicode em NFC', async () => {
    const userData = await createUserData()
    const storage = storageWithIds(userData, [FIRST_ID])

    const created = await storage.createLocalServer('Projeto 🔥')

    expect(created.displayName).toBe('Projeto 🔥')
    await expect(storage.loadLocalServer(FIRST_ID)).resolves.toEqual(created)
  })

  it('gera IDs diferentes para criações consecutivas', async () => {
    const userData = await createUserData()
    const storage = createTestStorage(userData)

    const first = await storage.createLocalServer('Primeiro')
    const second = await storage.createLocalServer('Segundo')

    expect(first.localStorageId).toMatch(/^[0-9a-f]{32}$/)
    expect(second.localStorageId).toMatch(/^[0-9a-f]{32}$/)
    expect(second.localStorageId).not.toBe(first.localStorageId)
  })

  it('carrega metadata equivalente em uma nova instância', async () => {
    const userData = await createUserData()
    const created = await storageWithIds(userData, [FIRST_ID]).createLocalServer('Persistente')

    const loaded = await createTestStorage(userData).loadLocalServer(FIRST_ID)

    expect(loaded).toEqual(created)
  })

  it.each([
    ['', 'vazio'],
    [' \t ', 'somente whitespace'],
    ['nome\ncom controle', 'caractere de controle'],
    ['e\u0301', 'Unicode fora de NFC']
  ])('rejeita displayName inválido: %s (%s)', async (displayName) => {
    const userData = await createUserData()
    const storage = storageWithIds(userData, [FIRST_ID])

    await expectStorageError(storage.createLocalServer(displayName), 'INVALID_SERVER_NAME')
    await expect(readdir(userData)).resolves.toEqual([])
  })

  it('rejeita displayName acima do limite em pontos de código', async () => {
    const userData = await createUserData()
    const storage = storageWithIds(userData, [FIRST_ID])

    await expectStorageError(
      storage.createLocalServer('🔥'.repeat(MAX_DISPLAY_NAME_CODE_POINTS + 1)),
      'INVALID_SERVER_NAME'
    )
  })

  it('rejeita displayName de tipo diferente em runtime', async () => {
    const userData = await createUserData()
    const storage = storageWithIds(userData, [FIRST_ID])

    await expectStorageError(
      storage.createLocalServer(42 as unknown as string),
      'INVALID_SERVER_NAME'
    )
  })

  it.each(['../foo', '..\\foo', '/foo', 'C:\\foo', '\\\\server\\share', '.', '..', 'foo/bar', 'foo\\bar'])(
    'rejeita storage ID antes de tocar o filesystem: %s',
    async (storageId) => {
      const userData = await createUserData()
      const storage = createTestStorage(userData)

      await expectStorageError(storage.loadLocalServer(storageId), 'INVALID_STORAGE_ID')
      await expect(readdir(userData)).resolves.toEqual([])
    }
  )

  it.each([
    ['JSON inválido', '{'],
    ['JSON truncado', '{"version":'],
    [
      'campo obrigatório ausente',
      JSON.stringify({ version: 1, localStorageId: FIRST_ID })
    ],
    [
      'campo inesperado',
      JSON.stringify({
        version: 1,
        localStorageId: FIRST_ID,
        displayName: 'Servidor',
        serverId: VALID_SERVER_ID,
        owner: 'antecipado'
      })
    ],
    [
      'storage ID divergente',
      JSON.stringify({
        version: 1,
        localStorageId: SECOND_ID,
        displayName: 'Servidor',
        serverId: VALID_SERVER_ID
      })
    ],
    [
      'displayName inválido',
      JSON.stringify({
        version: 1,
        localStorageId: FIRST_ID,
        displayName: '   ',
        serverId: VALID_SERVER_ID
      })
    ]
  ])('rejeita metadata adulterado: %s', async (_caseName, contents) => {
    const fixture = await createServerFixture()
    await writeFile(fixture.metadataPath, contents)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_METADATA_CORRUPTED'
    )
  })

  it('rejeita versão desconhecida', async () => {
    const fixture = await createServerFixture()
    await writeMetadata(fixture.metadataPath, {
      version: 2,
      localStorageId: FIRST_ID,
      displayName: 'Servidor',
      serverId: VALID_SERVER_ID
    })

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_VERSION_UNSUPPORTED'
    )
  })

  it('rejeita metadata acima do limite antes do parse', async () => {
    const fixture = await createServerFixture()
    await writeFile(fixture.metadataPath, Buffer.alloc(MAX_SERVER_METADATA_BYTES + 1, 0x20))

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_METADATA_CORRUPTED'
    )
  })

  it('rejeita server.json como symlink quando a plataforma permite reproduzir', async () => {
    const fixture = await createServerFixture()
    const targetPath = join(fixture.userData, 'metadata-fora.json')
    await writeFile(targetPath, await readFile(fixture.metadataPath))
    await unlink(fixture.metadataPath)

    try {
      await symlink(targetPath, fixture.metadataPath, 'file')
    } catch (error) {
      if (isPermissionError(error)) {
        return
      }

      throw error
    }

    await expectStorageError(fixture.storage.loadLocalServer(FIRST_ID), 'SERVER_PATH_UNSAFE')
  })

  it('rejeita o diretório do servidor como junction quando reproduzível', async () => {
    const fixture = await createServerFixture()
    const targetDirectory = join(fixture.userData, 'target')
    await mkdir(targetDirectory)
    await writeMetadata(join(targetDirectory, 'server.json'), {
      version: 1,
      localStorageId: FIRST_ID,
      displayName: 'Servidor'
    })
    await rm(fixture.serverDirectory, { recursive: true })

    try {
      await symlink(targetDirectory, fixture.serverDirectory, 'junction')
    } catch (error) {
      if (isPermissionError(error)) {
        return
      }

      throw error
    }

    await expectStorageError(fixture.storage.loadLocalServer(FIRST_ID), 'SERVER_PATH_UNSAFE')
  })

  it('rejeita arquivo no lugar do diretório do servidor', async () => {
    const userData = await createUserData()
    const serversRoot = join(userData, 'servers')
    await mkdir(serversRoot)
    await writeFile(join(serversRoot, FIRST_ID), 'não é diretório')

    await expectStorageError(
      createTestStorage(userData).loadLocalServer(FIRST_ID),
      'SERVER_PATH_UNSAFE'
    )
  })

  it('rejeita diretório no lugar de server.json', async () => {
    const fixture = await createServerFixture()
    await unlink(fixture.metadataPath)
    await mkdir(fixture.metadataPath)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_METADATA_CORRUPTED'
    )
  })

  it('retorna erro seguro para servidor inexistente sem criar o root', async () => {
    const userData = await createUserData()

    await expectStorageError(
      createTestStorage(userData).loadLocalServer(FIRST_ID),
      'SERVER_NOT_FOUND'
    )
    await expect(readdir(userData)).resolves.toEqual([])
  })

  it('não reconhece staging parcial nem diretório final sem metadata', async () => {
    const userData = await createUserData()
    const serversRoot = join(userData, 'servers')
    const stagingDirectory = join(serversRoot, `.creating-${FIRST_ID}-deadbeefdeadbeef`)
    await mkdir(stagingDirectory, { recursive: true })
    await writeMetadata(join(stagingDirectory, 'server.json'), {
      version: 1,
      localStorageId: FIRST_ID,
      displayName: 'Parcial'
    })
    const storage = createTestStorage(userData)

    await expectStorageError(storage.loadLocalServer(FIRST_ID), 'SERVER_NOT_FOUND')

    await mkdir(join(serversRoot, FIRST_ID))
    await expectStorageError(storage.loadLocalServer(FIRST_ID), 'SERVER_METADATA_CORRUPTED')
  })

  it('em colisão preserva o servidor existente e tenta outro ID', async () => {
    const userData = await createUserData()
    const originalStorage = storageWithIds(userData, [FIRST_ID])
    const original = await originalStorage.createLocalServer('Original')
    const originalBytes = await readFile(join(userData, 'servers', FIRST_ID, 'server.json'))
    const collidingStorage = storageWithIds(userData, [FIRST_ID, SECOND_ID])

    const created = await collidingStorage.createLocalServer('Novo')

    expect(created.localStorageId).toBe(SECOND_ID)
    expect(await readFile(join(userData, 'servers', FIRST_ID, 'server.json'))).toEqual(originalBytes)
    await expect(originalStorage.loadLocalServer(FIRST_ID)).resolves.toEqual(original)
  })

  it('falha fechada ao atingir o limite de colisões sem overwrite', async () => {
    const userData = await createUserData()
    const originalStorage = storageWithIds(userData, [FIRST_ID])
    const original = await originalStorage.createLocalServer('Original')
    let generationCount = 0
    const collidingStorage = createTestStorage(userData, {
      generateStorageId: () => {
        generationCount += 1
        return FIRST_ID
      }
    })

    await expectStorageError(
      collidingStorage.createLocalServer('Nunca criado'),
      'SERVER_ID_COLLISION_LIMIT'
    )
    expect(generationCount).toBe(MAX_STORAGE_ID_COLLISION_ATTEMPTS)
    await expect(originalStorage.loadLocalServer(FIRST_ID)).resolves.toEqual(original)
  })

  it('rejeita hard link externo apenas pelo conteúdo se ele for adulterado', async () => {
    const fixture = await createServerFixture()
    const externalPath = join(fixture.userData, 'external.json')
    await writeFile(externalPath, '{')
    await unlink(fixture.metadataPath)
    await link(externalPath, fixture.metadataPath)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_METADATA_CORRUPTED'
    )
  })

  it('rejeita um root servers adulterado como junction', async () => {
    const userData = await createUserData()
    const targetDirectory = join(userData, 'target-root')
    await mkdir(targetDirectory)

    try {
      await symlink(targetDirectory, join(userData, 'servers'), 'junction')
    } catch (error) {
      if (isPermissionError(error)) {
        return
      }

      throw error
    }

    await expectStorageError(
      createTestStorage(userData).loadLocalServer(FIRST_ID),
      'SERVER_PATH_UNSAFE'
    )
  })

  it('remove o staging após uma criação concluída', async () => {
    const userData = await createUserData()
    await storageWithIds(userData, [FIRST_ID]).createLocalServer('Sem resíduos')

    expect((await readdir(join(userData, 'servers'))).sort()).toEqual([FIRST_ID])
    expect((await lstat(join(userData, 'servers', FIRST_ID))).isDirectory()).toBe(true)
  })
})

async function createUserData(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-servers-'))
  testRoots.push(root)
  return root
}

function storageWithIds(userData: string, ids: string[]) {
  let index = 0

  return createTestStorage(userData, {
    generateStorageId: () => ids[index++] ?? ids.at(-1) ?? FIRST_ID
  })
}

function createTestStorage(
  userData: string,
  options: Parameters<typeof createLocalServerStorage>[3] = {}
) {
  let fake = secureStorageByUserData.get(userData)

  if (!fake) {
    fake = createFakeSecureStorage()
    secureStorageByUserData.set(userData, fake)
  }

  return createLocalServerStorage(userData, fake.storage, TEST_DEVICE_IDENTITY, options)
}

async function createServerFixture() {
  const userData = await createUserData()
  const storage = storageWithIds(userData, [FIRST_ID])
  await storage.createLocalServer('Servidor')
  const serverDirectory = join(userData, 'servers', FIRST_ID)

  return {
    userData,
    storage,
    serverDirectory,
    metadataPath: join(serverDirectory, 'server.json')
  }
}

async function writeMetadata(path: string, metadata: Record<string, unknown>): Promise<void> {
  await writeFile(path, JSON.stringify(metadata))
}

async function expectStorageError(
  operation: Promise<unknown>,
  code: LocalServerStorageErrorCode
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code })
}

function isPermissionError(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'EPERM'
}

function createFakeSecureStorage() {
  const plaintextByCiphertext = new Map<string, string>()
  let encryptionCount = 0

  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (plaintext: string) => {
        encryptionCount += 1
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
    }
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
