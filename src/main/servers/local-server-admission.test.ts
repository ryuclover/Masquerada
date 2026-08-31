import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import {
  createLocalServerStorage,
  type LocalServerStorageErrorCode
} from './local-server-storage'
import { DATABASE_FILE_NAME } from './server-database'

const FIRST_ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('admissão de novos membros integrada ao storage local de servidores', () => {
  it('admite novo membro atomicamente com convite single-use e persiste o novo estado', async () => {
    const fixture = await createFixture()
    const { encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const candidateB = createDeviceIdentity()

    const member = await fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateB)
    expect(member.deviceFingerprint).toBe(candidateB.fingerprint)
    expect(member.publicKey).toEqual(candidateB.publicKey)

    // Reabre o servidor em uma nova instância de storage e confirma que o novo membro persiste
    const reloadedServer = await fixture.storage.loadLocalServer(FIRST_ID)
    expect(reloadedServer.serverId).toBe(fixture.server.serverId)

    // Replay do mesmo convite por outro device C é rejeitado
    const candidateC = createDeviceIdentity()
    await expectStorageError(
      fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateC),
      'SERVER_INVITE_EXHAUSTED'
    )
  })

  it('impede replay pelo mesmo dispositivo e não consome usos adicionais', async () => {
    const fixture = await createFixture()
    const { invite, encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 3
    })

    const candidateB = createDeviceIdentity()

    // 1ª admissão: sucesso
    await fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateB)
    const storedAfterFirst = await fixture.storage.getStoredInvite(FIRST_ID, invite.inviteId)
    expect(storedAfterFirst?.uses).toBe(1)

    // 2ª tentativa com o mesmo candidato: falha como member já existente
    await expectStorageError(
      fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateB),
      'SERVER_MEMBER_ALREADY_EXISTS'
    )

    // O contador de usos NÃO aumentou
    const storedAfterSecond = await fixture.storage.getStoredInvite(FIRST_ID, invite.inviteId)
    expect(storedAfterSecond?.uses).toBe(1)
  })

  it('garante atomicidade e impede dupla admissão em concorrência de convite single-use', async () => {
    const fixture = await createFixture()
    const { invite, encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const candidateB = createDeviceIdentity()
    const candidateC = createDeviceIdentity()

    // Execução simultânea de duas admissões concorrentes
    const results = await Promise.allSettled([
      fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateB),
      fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateC)
    ])

    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r) => r.status === 'rejected')

    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)

    // Apenas 1 uso consumido
    const stored = await fixture.storage.getStoredInvite(FIRST_ID, invite.inviteId)
    expect(stored?.uses).toBe(1)
    expect(stored?.status).toBe('exhausted')
  })

  it('rejeita carregamento de servidor se a public key de um membro admitido for adulterada', async () => {
    const fixture = await createFixture()
    const { encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const candidateB = createDeviceIdentity()
    const otherDevice = createDeviceIdentity()

    await fixture.storage.admitLocalServerMemberWithInvite(FIRST_ID, encoded, candidateB)

    // Adulteração manual no SQLite: troca a chave de candidateB pela de otherDevice
    const dbPath = join(fixture.userData, 'servers', FIRST_ID, DATABASE_FILE_NAME)
    const db = new DatabaseSync(dbPath)
    db.prepare('UPDATE members SET device_public_key = ? WHERE device_fingerprint = ?;').run(
      otherDevice.publicKey,
      candidateB.fingerprint
    )
    db.close()

    // Carregamento do servidor falha fechado
    await expectStorageError(
      fixture.storage.loadLocalServer(FIRST_ID),
      'SERVER_MEMBERSHIP_STATE_INVALID'
    )
  })
})

async function createFixture() {
  const userData = await createUserData()
  const fake = createFakeSecureStorage()
  const device = createDeviceIdentity()
  const storage = createStorage(userData, fake, device, [FIRST_ID])
  const server = await storage.createLocalServer('Servidor de Teste')
  return { userData, fake, device, storage, server }
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

async function createUserData(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-server-admission-'))
  testRoots.push(root)
  return root
}

function createDeviceIdentity() {
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({
    format: 'der',
    type: 'spki'
  })

  const fingerprint = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
  return createAuthenticatedCandidateDevice(fingerprint, Buffer.from(publicKey))
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
