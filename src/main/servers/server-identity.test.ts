import { createHash, generateKeyPairSync } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  calculateServerId,
  createServerIdentityMaterial,
  loadServerIdentity,
  MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES,
  MAX_SERVER_IDENTITY_METADATA_BYTES,
  type ServerIdentityErrorCode
} from './server-identity'

const TEST_DEVICE_IDENTITY = createTestDeviceIdentity()

describe('identidade criptográfica do servidor', () => {
  it('gera Ed25519 e deriva o serverId do DER/SPKI canônico', () => {
    const fake = createFakeSecureStorage()
    const material = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32')
    const metadata = readIdentityMetadata(material.metadataBytes)
    const publicKeyDer = Buffer.from(String(metadata.publicKey), 'base64')

    expect(material.identity).toMatchObject({
      version: 1,
      algorithm: 'Ed25519',
      serverId: calculateServerId(publicKeyDer)
    })
    expect(metadata.fingerprint).toBe(material.identity.serverId)
    expect(material.identity.publicKey).toEqual(publicKeyDer)
  })

  it('carrega a mesma identidade pública e verifica o keypair', () => {
    const fake = createFakeSecureStorage()
    const material = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32')

    const loaded = loadServerIdentity(
      material.metadataBytes,
      material.encryptedPrivateKey,
      fake.storage,
      'win32'
    )

    expect(loaded.serverId).toBe(material.identity.serverId)
    expect(loaded.publicKey).toEqual(material.identity.publicKey)
  })

  it('não expõe private key nem PKCS#8 na identidade pública', () => {
    const fake = createFakeSecureStorage()
    const material = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32')

    expect(Object.keys(material.identity).sort()).toEqual([
      'algorithm',
      'publicKey',
      'serverId',
      'version'
    ])
    expect(material.identity).not.toHaveProperty('privateKey')
    expect(material.identity).not.toHaveProperty('privateKeyDer')
    expect(material.metadataBytes.toString('utf8')).not.toContain('privateKey')
    expect(material.encryptedPrivateKey.toString('utf8')).not.toContain(fake.plaintexts()[0])
  })

  it('gera identidades independentes', () => {
    const fake = createFakeSecureStorage()
    const first = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32').identity
    const second = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32').identity

    expect(second.serverId).not.toBe(first.serverId)
    expect(second.publicKey).not.toEqual(first.publicKey)
  })

  it('falha quando a geração de keypair falha', () => {
    const fake = createFakeSecureStorage()

    expectIdentityError(
      () =>
        createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32', () => {
          throw new Error('Falha simulada do CSPRNG.')
        }),
      'SERVER_IDENTITY_CRYPTO_FAILED'
    )
    expect(fake.encryptCalls()).toBe(0)
  })

  it('rejeita keypair gerado com outro algoritmo', () => {
    const fake = createFakeSecureStorage()

    expectIdentityError(
      () =>
        createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32', () =>
          generateKeyPairSync('x25519')
        ),
      'SERVER_IDENTITY_CRYPTO_FAILED'
    )
  })

  it('falha fechada sem secure storage', () => {
    const fake = createFakeSecureStorage({ available: false })

    expectIdentityError(
      () => createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32'),
      'SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE'
    )
  })

  it('rejeita backend Linux inseguro', () => {
    const fake = createFakeSecureStorage({ backend: 'basic_text' })

    expectIdentityError(
      () => createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'linux'),
      'SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE'
    )
  })

  it('falha fechada quando a proteção da private key falha', () => {
    const fake = createFakeSecureStorage({ encryptionFails: true })

    expectIdentityError(
      () => createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32'),
      'SERVER_IDENTITY_SECURE_STORAGE_UNAVAILABLE'
    )
  })

  it.each([
    ['JSON corrompido', Buffer.from('{')],
    ['JSON truncado', Buffer.from('{"version":')],
    ['metadata vazio', Buffer.alloc(0)],
    ['metadata excessivo', Buffer.alloc(MAX_SERVER_IDENTITY_METADATA_BYTES + 1)]
  ])('rejeita %s', (_caseName, metadataBytes) => {
    const fixture = createIdentityFixture()

    expectLoadError(fixture, { metadataBytes }, 'SERVER_IDENTITY_CORRUPTED')
  })

  it.each([
    [
      'campo extra',
      (metadata: Record<string, unknown>) => {
        metadata.owner = 'não permitido'
      },
      'SERVER_IDENTITY_CORRUPTED' as const
    ],
    [
      'campo ausente',
      (metadata: Record<string, unknown>) => {
        delete metadata.publicKey
      },
      'SERVER_IDENTITY_CORRUPTED' as const
    ],
    [
      'versão desconhecida',
      (metadata: Record<string, unknown>) => {
        metadata.version = 2
      },
      'SERVER_IDENTITY_VERSION_UNSUPPORTED' as const
    ],
    [
      'algoritmo diferente',
      (metadata: Record<string, unknown>) => {
        metadata.algorithm = 'X25519'
      },
      'SERVER_IDENTITY_CORRUPTED' as const
    ],
    [
      'Base64 não canônico',
      (metadata: Record<string, unknown>) => {
        metadata.publicKey = `${String(metadata.publicKey)}=`
      },
      'SERVER_IDENTITY_CORRUPTED' as const
    ],
    [
      'SPKI inválida',
      (metadata: Record<string, unknown>) => {
        const invalidSpki = Buffer.from('não é SPKI')
        metadata.publicKey = invalidSpki.toString('base64')
        metadata.fingerprint = calculateServerId(invalidSpki)
      },
      'SERVER_IDENTITY_INVALID_PUBLIC_KEY' as const
    ],
    [
      'fingerprint adulterado',
      (metadata: Record<string, unknown>) => {
        metadata.fingerprint = `sha256:${'0'.repeat(64)}`
      },
      'SERVER_IDENTITY_ID_MISMATCH' as const
    ]
  ])('rejeita metadata com %s', (_caseName, mutate, errorCode) => {
    const fixture = createIdentityFixture()
    const metadata = readIdentityMetadata(fixture.material.metadataBytes)
    mutate(metadata)

    expectLoadError(
      fixture,
      { metadataBytes: Buffer.from(JSON.stringify(metadata)) },
      errorCode
    )
  })

  it('rejeita SPKI de outro algoritmo', () => {
    const fixture = createIdentityFixture()
    const otherKey = generateKeyPairSync('x25519').publicKey.export({
      format: 'der',
      type: 'spki'
    })
    const metadata = readIdentityMetadata(fixture.material.metadataBytes)
    metadata.publicKey = otherKey.toString('base64')
    metadata.fingerprint = calculateServerId(otherKey)

    expectLoadError(
      fixture,
      { metadataBytes: Buffer.from(JSON.stringify(metadata)) },
      'SERVER_IDENTITY_INVALID_PUBLIC_KEY'
    )
  })

  it.each([
    ['ciphertext adulterado', Buffer.from('adulterado')],
    ['ciphertext vazio', Buffer.alloc(0)],
    ['ciphertext excessivo', Buffer.alloc(MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES + 1)]
  ])('rejeita %s', (_caseName, encryptedPrivateKey) => {
    const fixture = createIdentityFixture()

    expectLoadError(fixture, { encryptedPrivateKey }, 'SERVER_IDENTITY_CORRUPTED')
  })

  it('rejeita falha de descriptografia', () => {
    const fixture = createIdentityFixture({ decryptionFails: true })

    expectLoadError(fixture, {}, 'SERVER_IDENTITY_CORRUPTED')
  })

  it('rejeita PKCS#8 malformado', () => {
    const fixture = createIdentityFixture()
    const malformedCiphertext = fixture.fake.protect(Buffer.from('não é PKCS#8').toString('base64'))

    expectLoadError(
      fixture,
      { encryptedPrivateKey: malformedCiphertext },
      'SERVER_IDENTITY_CORRUPTED'
    )
  })

  it('rejeita private key de outro algoritmo', () => {
    const fixture = createIdentityFixture()
    const otherPrivateKey = generateKeyPairSync('x25519').privateKey.export({
      format: 'der',
      type: 'pkcs8'
    })
    const otherCiphertext = fixture.fake.protect(otherPrivateKey.toString('base64'))

    expectLoadError(
      fixture,
      { encryptedPrivateKey: otherCiphertext },
      'SERVER_IDENTITY_CORRUPTED'
    )
  })

  it('rejeita keypair incompatível', () => {
    const fake = createFakeSecureStorage()
    const first = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32')
    const second = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32')

    expectIdentityError(
      () => loadServerIdentity(first.metadataBytes, second.encryptedPrivateKey, fake.storage, 'win32'),
      'SERVER_IDENTITY_KEY_MISMATCH'
    )
  })
})

function createIdentityFixture(
  options: Parameters<typeof createFakeSecureStorage>[0] = {}
) {
  const fake = createFakeSecureStorage(options)
  const material = createServerIdentityMaterial(fake.storage, TEST_DEVICE_IDENTITY, 'win32')
  return { fake, material }
}

function expectLoadError(
  fixture: ReturnType<typeof createIdentityFixture>,
  overrides: {
    metadataBytes?: Buffer
    encryptedPrivateKey?: Buffer
  },
  code: ServerIdentityErrorCode
): void {
  expectIdentityError(
    () =>
      loadServerIdentity(
        overrides.metadataBytes ?? fixture.material.metadataBytes,
        overrides.encryptedPrivateKey ?? fixture.material.encryptedPrivateKey,
        fixture.fake.storage,
        'win32'
      ),
    code
  )
}

function expectIdentityError(operation: () => unknown, code: ServerIdentityErrorCode): void {
  expect(operation).toThrowError(expect.objectContaining({ code }))
}

function readIdentityMetadata(metadataBytes: Buffer): Record<string, unknown> {
  return JSON.parse(metadataBytes.toString('utf8')) as Record<string, unknown>
}

function createFakeSecureStorage(
  options: {
    available?: boolean
    backend?: 'basic_text' | 'gnome_libsecret'
    encryptionFails?: boolean
    decryptionFails?: boolean
  } = {}
) {
  const plaintextByCiphertext = new Map<string, string>()
  const protectedPlaintexts: string[] = []
  let encryptionCount = 0

  const storage = {
    isEncryptionAvailable: () => options.available ?? true,
    getSelectedStorageBackend: () => options.backend ?? ('gnome_libsecret' as const),
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
      if (options.decryptionFails) {
        throw new Error('Falha simulada de descriptografia.')
      }

      const plaintext = plaintextByCiphertext.get(encrypted.toString('utf8'))

      if (!plaintext) {
        throw new Error('Ciphertext de teste inválido.')
      }

      return plaintext
    }
  }

  return {
    storage,
    encryptCalls: () => encryptionCount,
    plaintexts: () => protectedPlaintexts,
    protect: (plaintext: string) => storage.encryptString(plaintext)
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
