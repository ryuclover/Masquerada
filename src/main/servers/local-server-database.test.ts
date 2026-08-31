import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  copyFile,
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
import { DatabaseSync } from 'node:sqlite'

import { afterEach, describe, expect, it } from 'vitest'

import {
  createLocalServerStorage,
  type LocalServerStorageErrorCode
} from './local-server-storage'
import {
  DATABASE_FILE_NAME,
  DATABASE_SCHEMA_VERSION,
  listMembers,
  MAX_INITIAL_SERVER_DATABASE_BYTES,
  openServerDatabase
} from './server-database'

const FIRST_ID = '11111111111111111111111111111111'
const SECOND_ID = '22222222222222222222222222222222'
const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('persistência SQLite e membership integrada ao servidor local', () => {
  it('cria server.db no diretório do servidor com o initial owner em members', async () => {
    const fixture = await createFixture()
    const entries = await readdir(fixture.paths.serverDirectory)

    expect(entries.sort()).toEqual(['authority', 'identity', 'server.db', 'server.json'])
    const db = openServerDatabase(fixture.paths.database)
    const version = db.prepare('PRAGMA user_version;').get() as { user_version: number }
    const members = listMembers(db)
    db.close()

    expect(version.user_version).toBe(DATABASE_SCHEMA_VERSION)
    expect(members).toHaveLength(1)
    expect(members[0]?.deviceFingerprint).toBe(fixture.device.fingerprint)
    expect(members[0]?.publicKey).toEqual(fixture.device.publicKey)
  })

  it('permite carregar servidor válido e verificar consistência com Initial Owner Binding', async () => {
    const fixture = await createFixture()
    const loaded = await fixture.storage.loadLocalServer(FIRST_ID)

    expect(loaded.localStorageId).toBe(FIRST_ID)
    expect(loaded.serverId).toBe(fixture.server.serverId)
    expect(loaded.initialOwner.deviceFingerprint).toBe(fixture.device.fingerprint)
  })

  it('mantém bancos e memberships independentes para servidores distintos', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const device = createDeviceIdentity()
    const storage = createStorage(userData, fake, device, [FIRST_ID, SECOND_ID])

    const first = await storage.createLocalServer('Primeiro')
    const second = await storage.createLocalServer('Segundo')

    const firstDbPath = join(userData, 'servers', FIRST_ID, DATABASE_FILE_NAME)
    const secondDbPath = join(userData, 'servers', SECOND_ID, DATABASE_FILE_NAME)

    expect(first.localStorageId).toBe(FIRST_ID)
    expect(second.localStorageId).toBe(SECOND_ID)
    expect(firstDbPath).not.toBe(secondDbPath)
  })

  it('rejeita carregamento se server.db estiver ausente', async () => {
    const fixture = await createFixture()
    await unlink(fixture.paths.database)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_NOT_FOUND'
    )
  })

  it('rejeita carregamento se server.db estiver vazio', async () => {
    const fixture = await createFixture()
    await writeFile(fixture.paths.database, Buffer.alloc(0))

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_CORRUPTED'
    )
  })

  it('rejeita carregamento se server.db for um diretório', async () => {
    const fixture = await createFixture()
    await unlink(fixture.paths.database)
    await mkdir(fixture.paths.database)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_PATH_UNSAFE'
    )
  })

  it('rejeita carregamento se server.db for um symlink quando suportado', async () => {
    const fixture = await createFixture()
    const targetPath = join(fixture.userData, 'target-server.db')
    await copyFile(fixture.paths.database, targetPath)
    await unlink(fixture.paths.database)

    try {
      await symlink(targetPath, fixture.paths.database, 'file')
    } catch (error) {
      if (isPermissionError(error)) return
      throw error
    }

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_PATH_UNSAFE'
    )
  })

  it('rejeita carregamento se server.db exceder o limite inicial de tamanho', async () => {
    const fixture = await createFixture()
    await writeFile(fixture.paths.database, Buffer.alloc(MAX_INITIAL_SERVER_DATABASE_BYTES + 1))

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_TOO_LARGE'
    )
  })

  it('rejeita carregamento se server.db contiver bytes corrompidos', async () => {
    const fixture = await createFixture()
    const contents = await readFile(fixture.paths.database)
    contents[100] = 0x00
    contents[101] = 0x00
    contents[102] = 0xff
    contents[103] = 0xff
    await writeFile(fixture.paths.database, contents)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_CORRUPTED'
    )
  })

  it('rejeita carregamento se server.db tiver user_version incompatível', async () => {
    const fixture = await createFixture()
    const db = new DatabaseSync(fixture.paths.database)
    db.exec('PRAGMA user_version = 99;')
    db.close()

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_VERSION_UNSUPPORTED'
    )
  })

  it('rejeita carregamento se server.db tiver schema modificado com tabela inesperada', async () => {
    const fixture = await createFixture()
    const db = new DatabaseSync(fixture.paths.database)
    db.exec('CREATE TABLE backdoor (id INTEGER PRIMARY KEY);')
    db.close()

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_DATABASE_SCHEMA_INVALID'
    )
  })

  it('impede tentativa de escalada de privilégio ao alterar members no SQLite', async () => {
    const fixture = await createFixture()
    const deviceB = createDeviceIdentity()

    // Atacante altera a tabela members: remove Device A (owner) e adiciona Device B
    const db = new DatabaseSync(fixture.paths.database)
    db.prepare('DELETE FROM members;').run()
    db.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
      deviceB.fingerprint,
      deviceB.publicKey
    )
    db.close()

    // Tentativa de carregar o servidor sob autoridade do Device B
    const storageB = createStorage(fixture.userData, fixture.fake, deviceB, [FIRST_ID])
    await expectStorageError(
      storageB.loadLocalServer(FIRST_ID),
      'SERVER_MEMBERSHIP_STATE_INVALID'
    )
  })

  it('não recria nem auto-repara server.db quando o owner é removido de members', async () => {
    const fixture = await createFixture()
    const serverMetadataBefore = await readFile(fixture.paths.serverMetadata)
    const identityMetadataBefore = await readFile(fixture.paths.identityMetadata)
    const ownerMetadataBefore = await readFile(fixture.paths.ownerMetadata)

    // Remove owner de members
    const db = new DatabaseSync(fixture.paths.database)
    db.prepare('DELETE FROM members WHERE device_fingerprint = ?;').run(fixture.device.fingerprint)
    db.close()
    const dbBytesBefore = await readFile(fixture.paths.database)

    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_MEMBERSHIP_STATE_INVALID'
    )

    // Confirma que não houve auto-repair
    expect(await readFile(fixture.paths.database)).toEqual(dbBytesBefore)
    expect(await readFile(fixture.paths.serverMetadata)).toEqual(serverMetadataBefore)
    expect(await readFile(fixture.paths.identityMetadata)).toEqual(identityMetadataBefore)
    expect(await readFile(fixture.paths.ownerMetadata)).toEqual(ownerMetadataBefore)
  })
})

async function createFixture() {
  const userData = await createUserData()
  const fake = createFakeSecureStorage()
  const device = createDeviceIdentity()
  const storage = createStorage(userData, fake, device, [FIRST_ID])
  const server = await storage.createLocalServer('Servidor com DB')
  return { userData, fake, device, storage, server, paths: serverPaths(userData, FIRST_ID) }
}

function createStorage(
  userData: string,
  fake: ReturnType<typeof createFakeSecureStorage>,
  device: ReturnType<typeof createDeviceIdentity>,
  ids: string[]
) {
  let index = 0
  return createLocalServerStorage(userData, fake.storage, device, {
    platform: 'win32',
    generateStorageId: () => ids[index++] ?? ids.at(-1) ?? FIRST_ID
  })
}

function serverPaths(userData: string, storageId: string) {
  const serverDirectory = join(userData, 'servers', storageId)
  const identityDirectory = join(serverDirectory, 'identity')
  const authorityDirectory = join(serverDirectory, 'authority')
  return {
    serverDirectory,
    serverMetadata: join(serverDirectory, 'server.json'),
    identityMetadata: join(identityDirectory, 'identity.json'),
    authorityDirectory,
    ownerMetadata: join(authorityDirectory, 'owner.json'),
    database: join(serverDirectory, DATABASE_FILE_NAME)
  }
}

async function createUserData(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-server-db-integration-'))
  testRoots.push(root)
  return root
}

function createDeviceIdentity() {
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({
    format: 'der',
    type: 'spki'
  })

  return {
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey: Buffer.from(publicKey)
  }
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
    },
    encryptCalls: () => encryptionCount
  }
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
