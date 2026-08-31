import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  createLocalServerStorage,
  type LocalServerStorageErrorCode
} from './local-server-storage'
import { verifyServerInvite } from './server-invite'

const FIRST_ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('emissão, consumo e revogação de convites no storage local', () => {
  it('permite que a autoridade inicial emita convite e persiste o estado no banco', async () => {
    const fixture = await createFixture()
    const expiresAt = Math.floor(Date.now() / 1000) + 3600

    const { invite, encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt,
      maxUses: 1
    })

    expect(invite.serverId).toBe(fixture.server.serverId)
    expect(invite.issuedByDeviceFingerprint).toBe(fixture.device.fingerprint)
    expect(invite.expiresAt).toBe(expiresAt)
    expect(invite.maxUses).toBe(1)
    expect(encoded).toMatch(/^MQR1\.[A-Za-z0-9_-]+$/)

    const stored = await fixture.storage.getStoredInvite(FIRST_ID, invite.inviteId)
    expect(stored).toEqual({
      inviteId: invite.inviteId,
      expiresAt,
      maxUses: 1,
      uses: 0,
      revoked: false,
      status: 'available'
    })

    const verified = verifyServerInvite(encoded, fixture.server.identity.publicKey, {
      expectedServerId: fixture.server.serverId
    })
    expect(verified).toEqual(invite)
  })

  it('consome convite single-use e rejeita replay subsequente', async () => {
    const fixture = await createFixture()
    const { invite, encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    // Primeiro consumo: sucesso
    await expect(
      fixture.storage.consumeLocalServerInvite(FIRST_ID, encoded)
    ).resolves.toBeUndefined()

    const storedAfterFirst = await fixture.storage.getStoredInvite(FIRST_ID, invite.inviteId)
    expect(storedAfterFirst?.uses).toBe(1)
    expect(storedAfterFirst?.status).toBe('exhausted')

    // Segundo consumo (replay): falha fechado
    await expectStorageError(
      fixture.storage.consumeLocalServerInvite(FIRST_ID, encoded),
      'SERVER_INVITE_EXHAUSTED'
    )
  })

  it('permite ao owner revogar um convite e impede qualquer consumo posterior', async () => {
    const fixture = await createFixture()
    const { invite, encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    await expect(
      fixture.storage.revokeLocalServerInvite(FIRST_ID, invite.inviteId)
    ).resolves.toBeUndefined()

    const stored = await fixture.storage.getStoredInvite(FIRST_ID, invite.inviteId)
    expect(stored?.revoked).toBe(true)
    expect(stored?.status).toBe('revoked')

    await expectStorageError(
      fixture.storage.consumeLocalServerInvite(FIRST_ID, encoded),
      'SERVER_INVITE_REVOKED'
    )
  })

  it('impede que dispositivo não-owner revogue convites do servidor', async () => {
    const fixture = await createFixture()
    const { invite } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const attackerDevice = createDeviceIdentity()
    const attackerStorage = createStorage(fixture.userData, fixture.fake, attackerDevice, [FIRST_ID])

    await expectStorageError(
      attackerStorage.revokeLocalServerInvite(FIRST_ID, invite.inviteId),
      'SERVER_INVITE_UNAUTHORIZED'
    )
  })

  it('garante atomicidade e impede duplo consumo em corrida de convite single-use', async () => {
    const fixture = await createFixture()
    const { encoded } = await fixture.storage.createLocalServerInvite(FIRST_ID, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    // Execução sequencial/concorrente das duas tentativas
    const results = await Promise.allSettled([
      fixture.storage.consumeLocalServerInvite(FIRST_ID, encoded),
      fixture.storage.consumeLocalServerInvite(FIRST_ID, encoded)
    ])

    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r) => r.status === 'rejected')

    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
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
  const root = await mkdtemp(join(tmpdir(), 'masquerada-server-invite-'))
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
