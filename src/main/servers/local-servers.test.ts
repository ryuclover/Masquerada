import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  getPath: vi.fn<(name: string) => string>(),
  plaintextByCiphertext: new Map<string, string>()
}))

vi.mock('electron', () => ({
  app: { getPath: electronMock.getPath },
  safeStorage: {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptString: (plaintext: string) => {
      const ciphertext = `protected:${electronMock.plaintextByCiphertext.size + 1}`
      electronMock.plaintextByCiphertext.set(ciphertext, plaintext)
      return Buffer.from(ciphertext)
    },
    decryptString: (encrypted: Buffer) => {
      const plaintext = electronMock.plaintextByCiphertext.get(encrypted.toString('utf8'))

      if (!plaintext) {
        throw new Error('Ciphertext inválido.')
      }

      return plaintext
    }
  }
}))

import { createLocalServer, initializeLocalServers } from './local-servers'

let testRoot: string | undefined

afterAll(async () => {
  if (testRoot) {
    await rm(testRoot, { force: true, recursive: true })
  }
})

it('deriva o root de produção exclusivamente de app.getPath(userData)', async () => {
  testRoot = await mkdtemp(join(tmpdir(), 'masquerada-main-servers-'))
  electronMock.getPath.mockReturnValue(testRoot)
  initializeLocalServers(createTestDeviceIdentity())

  const created = await createLocalServer('Servidor do main')
  const metadataPath = join(testRoot, 'servers', created.localStorageId, 'server.json')

  expect(electronMock.getPath).toHaveBeenCalledOnce()
  expect(electronMock.getPath).toHaveBeenCalledWith('userData')
  await expect(readFile(metadataPath, 'utf8')).resolves.toContain('Servidor do main')
})

function createTestDeviceIdentity() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = keyPair.publicKey.export({ format: 'der', type: 'spki' })

  return {
    algorithm: 'Ed25519' as const,
    fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey: Buffer.from(publicKey),
    signDeviceAuthChallenge: () => Buffer.alloc(64)
  }
}
