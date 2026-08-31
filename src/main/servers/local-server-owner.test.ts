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
  loadInitialOwnerBinding,
  MAX_INITIAL_OWNER_METADATA_BYTES,
  type InitialOwnerBindingErrorCode
} from './initial-owner-binding'
import {
  createLocalServerStorage,
  type LocalServerStorageErrorCode
} from './local-server-storage'
import { createServerIdentityMaterial } from './server-identity'

const FIRST_ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const SECOND_ID = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('autoridade inicial integrada ao servidor', () => {
  it('cria exatamente um owner binding para a device identity criadora', async () => {
    const fixture = await createFixture()
    const metadata = await readJson(fixture.paths.ownerMetadata)

    expect(await readdir(fixture.paths.authorityDirectory)).toEqual(['owner.json'])
    expect(metadata).toMatchObject({
      version: 1,
      type: 'initial-owner',
      serverId: fixture.server.serverId,
      ownerDeviceFingerprint: fixture.device.fingerprint,
      ownerDevicePublicKey: fixture.device.publicKey.toString('base64')
    })
    expect(fixture.server.initialOwner.deviceFingerprint).toBe(fixture.device.fingerprint)
    expect(fixture.server.initialOwner.publicKey).toEqual(fixture.device.publicKey)
  })

  it('persiste uma assinatura verificável pela server public key', async () => {
    const fixture = await createFixture()
    const ownerBytes = await readFile(fixture.paths.ownerMetadata)

    const verified = loadInitialOwnerBinding(
      ownerBytes,
      fixture.server.serverId,
      fixture.server.identity.publicKey
    )

    expect(verified.signature).toEqual(fixture.server.initialOwner.signature)
  })

  it('mantém owner, public key e assinatura em novo carregamento', async () => {
    const fixture = await createFixture()
    const signatureBefore = Buffer.from(fixture.server.initialOwner.signature)
    const reloaded = await createStorage(
      fixture.userData,
      fixture.fake,
      fixture.device,
      [FIRST_ID]
    ).loadLocalServer(FIRST_ID)

    expect(reloaded.initialOwner.deviceFingerprint).toBe(fixture.device.fingerprint)
    expect(reloaded.initialOwner.publicKey).toEqual(fixture.device.publicKey)
    expect(reloaded.initialOwner.signature).toEqual(signatureBefore)
  })

  it('usa o mesmo device, mas assinaturas distintas, em servidores diferentes', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const device = createDeviceIdentity()
    const storage = createStorage(userData, fake, device, [FIRST_ID, SECOND_ID])
    const first = await storage.createLocalServer('Primeiro')
    const second = await storage.createLocalServer('Segundo')

    expect(second.initialOwner.deviceFingerprint).toBe(first.initialOwner.deviceFingerprint)
    expect(second.serverId).not.toBe(first.serverId)
    expect(second.initialOwner.signature).not.toEqual(first.initialOwner.signature)
  })

  it('registra devices diferentes como owners de seus respectivos servidores', async () => {
    const fakeA = createFakeSecureStorage()
    const fakeB = createFakeSecureStorage()
    const deviceA = createDeviceIdentity()
    const deviceB = createDeviceIdentity()
    const serverA = await createStorage(
      await createUserData(),
      fakeA,
      deviceA,
      [FIRST_ID]
    ).createLocalServer('A')
    const serverB = await createStorage(
      await createUserData(),
      fakeB,
      deviceB,
      [FIRST_ID]
    ).createLocalServer('B')

    expect(serverA.initialOwner.deviceFingerprint).toBe(deviceA.fingerprint)
    expect(serverB.initialOwner.deviceFingerprint).toBe(deviceB.fingerprint)
    expect(serverB.initialOwner.deviceFingerprint).not.toBe(serverA.initialOwner.deviceFingerprint)
  })

  it.each([
    ['JSON inválido', Buffer.from('{')],
    ['JSON truncado', Buffer.from('{"version":')],
    ['arquivo excessivo', Buffer.alloc(MAX_INITIAL_OWNER_METADATA_BYTES + 1)]
  ])('rejeita owner.json %s pelo carregamento integrado', async (_caseName, contents) => {
    const fixture = await createFixture()
    await writeFile(fixture.paths.ownerMetadata, contents)

    await expectOwnerError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('rejeita owner.json copiado de outro servidor', async () => {
    const pair = await createPairFixture()
    await copyFile(pair.secondPaths.ownerMetadata, pair.firstPaths.ownerMetadata)

    await expectOwnerError(
      pair.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('rejeita assinatura copiada de outro servidor', async () => {
    const pair = await createPairFixture()
    const firstOwner = await readJson(pair.firstPaths.ownerMetadata)
    const secondOwner = await readJson(pair.secondPaths.ownerMetadata)
    firstOwner.signature = secondOwner.signature
    await writeJson(pair.firstPaths.ownerMetadata, firstOwner)

    await expectOwnerError(
      pair.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('impede escalada ao trocar owner A por device B sem assinatura do servidor', async () => {
    const fixture = await createFixture()
    const deviceB = createDeviceIdentity()
    const ownerMetadata = await readJson(fixture.paths.ownerMetadata)
    ownerMetadata.ownerDeviceFingerprint = deviceB.fingerprint
    ownerMetadata.ownerDevicePublicKey = deviceB.publicKey.toString('base64')
    await writeJson(fixture.paths.ownerMetadata, ownerMetadata)
    const tamperedBytes = await readFile(fixture.paths.ownerMetadata)
    const storageAsDeviceB = createStorage(
      fixture.userData,
      fixture.fake,
      deviceB,
      [FIRST_ID]
    )

    await expectOwnerError(
      storageAsDeviceB.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
    expect(await readFile(fixture.paths.ownerMetadata)).toEqual(tamperedBytes)
  })

  it('não recria owner.json ausente nem elege o device atual', async () => {
    const fixture = await createFixture()
    const deviceB = createDeviceIdentity()
    const serverMetadataBefore = await readFile(fixture.paths.serverMetadata)
    const identityMetadataBefore = await readFile(fixture.paths.identityMetadata)
    const encryptionCallsBefore = fixture.fake.encryptCalls()
    await unlink(fixture.paths.ownerMetadata)
    const storageAsDeviceB = createStorage(
      fixture.userData,
      fixture.fake,
      deviceB,
      [FIRST_ID]
    )

    await expectOwnerError(
      storageAsDeviceB.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
    await expect(readFile(fixture.paths.ownerMetadata)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(fixture.fake.encryptCalls()).toBe(encryptionCallsBefore)
    expect(await readFile(fixture.paths.serverMetadata)).toEqual(serverMetadataBefore)
    expect(await readFile(fixture.paths.identityMetadata)).toEqual(identityMetadataBefore)
  })

  it('não repara assinatura corrompida nem altera arquivos', async () => {
    const fixture = await createFixture()
    const owner = await readJson(fixture.paths.ownerMetadata)
    owner.signature = Buffer.alloc(64).toString('base64')
    await writeJson(fixture.paths.ownerMetadata, owner)
    const bytesBefore = await readFile(fixture.paths.ownerMetadata)
    const encryptionCallsBefore = fixture.fake.encryptCalls()

    await expectOwnerError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
    expect(await readFile(fixture.paths.ownerMetadata)).toEqual(bytesBefore)
    expect(fixture.fake.encryptCalls()).toBe(encryptionCallsBefore)
  })

  it('rejeita authority/ como junction quando reproduzível', async () => {
    const fixture = await createFixture()
    const target = join(fixture.userData, 'authority-target')
    await cp(fixture.paths.authorityDirectory, target, { recursive: true })
    await rm(fixture.paths.authorityDirectory, { recursive: true })

    try {
      await symlink(target, fixture.paths.authorityDirectory, 'junction')
    } catch (error) {
      if (isPermissionError(error)) return
      throw error
    }

    await expectOwnerError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_PATH_UNSAFE'
    )
  })

  it('rejeita owner.json como symlink quando reproduzível', async () => {
    const fixture = await createFixture()
    const target = join(fixture.userData, 'owner-target.json')
    await copyFile(fixture.paths.ownerMetadata, target)
    await unlink(fixture.paths.ownerMetadata)

    try {
      await symlink(target, fixture.paths.ownerMetadata, 'file')
    } catch (error) {
      if (isPermissionError(error)) return
      throw error
    }

    await expectOwnerError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_PATH_UNSAFE'
    )
  })

  it('rejeita arquivo no lugar de authority/', async () => {
    const fixture = await createFixture()
    await rm(fixture.paths.authorityDirectory, { recursive: true })
    await writeFile(fixture.paths.authorityDirectory, 'não é diretório')

    await expectOwnerError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_PATH_UNSAFE'
    )
  })

  it('rejeita diretório no lugar de owner.json', async () => {
    const fixture = await createFixture()
    await unlink(fixture.paths.ownerMetadata)
    await mkdir(fixture.paths.ownerMetadata)

    await expectOwnerError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('remove staging quando a gravação do owner binding falha', async () => {
    const userData = await createUserData()
    const fake = createFakeSecureStorage()
    const device = createDeviceIdentity()
    const validMaterial = createServerIdentityMaterial(fake.storage, device, 'win32')
    const storage = createLocalServerStorage(userData, fake.storage, device, {
      platform: 'win32',
      generateStorageId: () => FIRST_ID,
      createIdentityMaterial: () => ({
        ...validMaterial,
        initialOwnerMetadataBytes: Buffer.alloc(MAX_INITIAL_OWNER_METADATA_BYTES + 1)
      })
    })

    await expectOwnerError(storage.createLocalServer('Falha'), 'SERVER_CREATION_FAILED')
    await expect(readdir(join(userData, 'servers'))).resolves.toEqual([])
  })

  it('não expõe mutação de owner nem capability genérica de assinatura', async () => {
    const fixture = await createFixture()

    expect(Object.keys(fixture.server).sort()).toEqual([
      'displayName',
      'identity',
      'initialOwner',
      'localStorageId',
      'serverId',
      'version'
    ])
    expect(fixture.server).not.toHaveProperty('changeOwner')
    expect(fixture.server).not.toHaveProperty('sign')
    expect(fixture.server.identity).not.toHaveProperty('sign')
  })
})

async function createFixture() {
  const userData = await createUserData()
  const fake = createFakeSecureStorage()
  const device = createDeviceIdentity()
  const storage = createStorage(userData, fake, device, [FIRST_ID])
  const server = await storage.createLocalServer('Servidor')
  return { userData, fake, device, storage, server, paths: serverPaths(userData, FIRST_ID) }
}

async function createPairFixture() {
  const userData = await createUserData()
  const fake = createFakeSecureStorage()
  const device = createDeviceIdentity()
  const storage = createStorage(userData, fake, device, [FIRST_ID, SECOND_ID])
  await storage.createLocalServer('Primeiro')
  await storage.createLocalServer('Segundo')
  return {
    storage,
    firstPaths: serverPaths(userData, FIRST_ID),
    secondPaths: serverPaths(userData, SECOND_ID)
  }
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
    serverMetadata: join(serverDirectory, 'server.json'),
    identityMetadata: join(identityDirectory, 'identity.json'),
    authorityDirectory,
    ownerMetadata: join(authorityDirectory, 'owner.json')
  }
}

async function createUserData(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-server-owner-'))
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

async function readJson(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
}

async function writeJson(path: string, value: Record<string, unknown>): Promise<void> {
  await writeFile(path, JSON.stringify(value))
}

async function expectOwnerError(
  operation: Promise<unknown>,
  code:
    | LocalServerStorageErrorCode
    | InitialOwnerBindingErrorCode
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
    },
    encryptCalls: () => encryptionCount
  }
}
