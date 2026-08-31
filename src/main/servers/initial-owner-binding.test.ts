import {
  createHash,
  generateKeyPairSync,
  sign
} from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  createInitialOwnerBinding,
  INITIAL_OWNER_BINDING_DOMAIN,
  loadInitialOwnerBinding,
  MAX_INITIAL_OWNER_METADATA_BYTES,
  type InitialOwnerBindingErrorCode
} from './initial-owner-binding'

describe('vínculo criptográfico do owner inicial', () => {
  it('cria declaração pública estrita para a device identity', () => {
    const fixture = createBindingFixture()
    const metadata = readMetadata(fixture.metadataBytes)

    expect(metadata).toEqual({
      version: 1,
      type: 'initial-owner',
      serverId: fixture.serverId,
      ownerDeviceFingerprint: fixture.device.fingerprint,
      ownerDevicePublicKey: fixture.device.publicKey.toString('base64'),
      signature: fixture.binding.signature.toString('base64')
    })
    expect(fixture.binding).toMatchObject({
      version: 1,
      type: 'initial-owner',
      serverId: fixture.serverId,
      deviceFingerprint: fixture.device.fingerprint
    })
  })

  it('verifica a assinatura com a server public key', () => {
    const fixture = createBindingFixture()

    const loaded = loadInitialOwnerBinding(
      fixture.metadataBytes,
      fixture.serverId,
      fixture.serverPublicKey
    )

    expect(loaded.deviceFingerprint).toBe(fixture.device.fingerprint)
    expect(loaded.publicKey).toEqual(fixture.device.publicKey)
    expect(loaded.signature).toEqual(fixture.binding.signature)
  })

  it('produz assinaturas diferentes para servidores diferentes com o mesmo device', () => {
    const device = createDeviceIdentity()
    const first = createBindingFixture(device)
    const second = createBindingFixture(device)

    expect(second.serverId).not.toBe(first.serverId)
    expect(second.binding.signature).not.toEqual(first.binding.signature)
    expect(second.binding.deviceFingerprint).toBe(first.binding.deviceFingerprint)
  })

  it('vincula devices diferentes quando identidades diferentes são fornecidas', () => {
    const first = createBindingFixture(createDeviceIdentity())
    const second = createBindingFixture(createDeviceIdentity())

    expect(second.binding.deviceFingerprint).not.toBe(first.binding.deviceFingerprint)
    expect(second.binding.publicKey).not.toEqual(first.binding.publicKey)
  })

  it('rejeita device fingerprint que não corresponde à public key na criação', () => {
    const device = createDeviceIdentity()
    device.fingerprint = `sha256:${'0'.repeat(64)}`

    expectBindingError(
      () => createBindingFixture(device),
      'SERVER_OWNER_BINDING_CREATION_FAILED'
    )
  })

  it.each([
    ['JSON inválido', Buffer.from('{')],
    ['JSON truncado', Buffer.from('{"version":')],
    ['arquivo vazio', Buffer.alloc(0)],
    ['arquivo excessivo', Buffer.alloc(MAX_INITIAL_OWNER_METADATA_BYTES + 1)]
  ])('rejeita %s', (_caseName, metadataBytes) => {
    const fixture = createBindingFixture()

    expectLoadError(fixture, metadataBytes, 'SERVER_OWNER_BINDING_INVALID')
  })

  it.each([
    [
      'campo ausente',
      (metadata: Record<string, unknown>) => delete metadata.signature,
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'campo extra',
      (metadata: Record<string, unknown>) => {
        metadata.role = 'admin'
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'versão desconhecida',
      (metadata: Record<string, unknown>) => {
        metadata.version = 2
      },
      'SERVER_OWNER_BINDING_VERSION_UNSUPPORTED' as const
    ],
    [
      'tipo incorreto',
      (metadata: Record<string, unknown>) => {
        metadata.type = 'membership'
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'serverId inválido',
      (metadata: Record<string, unknown>) => {
        metadata.serverId = '../server'
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'fingerprint inválido',
      (metadata: Record<string, unknown>) => {
        metadata.ownerDeviceFingerprint = 'device-A'
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'Base64 não canônico',
      (metadata: Record<string, unknown>) => {
        metadata.ownerDevicePublicKey = `${String(metadata.ownerDevicePublicKey)}=`
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'public key inválida',
      (metadata: Record<string, unknown>) => {
        const invalidKey = Buffer.from('não é SPKI')
        metadata.ownerDevicePublicKey = invalidKey.toString('base64')
        metadata.ownerDeviceFingerprint = fingerprint(invalidKey)
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'assinatura inválida',
      (metadata: Record<string, unknown>) => {
        const signature = Buffer.from(String(metadata.signature), 'base64')
        signature[0] = (signature[0] ?? 0) ^ 0xff
        metadata.signature = signature.toString('base64')
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'assinatura truncada',
      (metadata: Record<string, unknown>) => {
        metadata.signature = Buffer.alloc(63).toString('base64')
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ],
    [
      'assinatura excessiva',
      (metadata: Record<string, unknown>) => {
        metadata.signature = Buffer.alloc(65).toString('base64')
      },
      'SERVER_OWNER_BINDING_INVALID' as const
    ]
  ])('rejeita owner metadata com %s', (_caseName, mutate, errorCode) => {
    const fixture = createBindingFixture()
    const metadata = readMetadata(fixture.metadataBytes)
    mutate(metadata)

    expectLoadError(fixture, Buffer.from(JSON.stringify(metadata)), errorCode)
  })

  it('rejeita owner public key de outro algoritmo', () => {
    const fixture = createBindingFixture()
    const x25519PublicKey = generateKeyPairSync('x25519').publicKey.export({
      format: 'der',
      type: 'spki'
    })
    const metadata = readMetadata(fixture.metadataBytes)
    metadata.ownerDevicePublicKey = x25519PublicKey.toString('base64')
    metadata.ownerDeviceFingerprint = fingerprint(x25519PublicKey)

    expectLoadError(
      fixture,
      Buffer.from(JSON.stringify(metadata)),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('rejeita troca conjunta do fingerprint e public key do owner', () => {
    const fixture = createBindingFixture()
    const attacker = createDeviceIdentity()
    const metadata = readMetadata(fixture.metadataBytes)
    metadata.ownerDeviceFingerprint = attacker.fingerprint
    metadata.ownerDevicePublicKey = attacker.publicKey.toString('base64')

    expectLoadError(
      fixture,
      Buffer.from(JSON.stringify(metadata)),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('rejeita owner.json copiado de outro servidor', () => {
    const first = createBindingFixture()
    const second = createBindingFixture()

    expectBindingError(
      () => loadInitialOwnerBinding(second.metadataBytes, first.serverId, first.serverPublicKey),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('rejeita assinatura copiada de outro servidor', () => {
    const device = createDeviceIdentity()
    const first = createBindingFixture(device)
    const second = createBindingFixture(device)
    const metadata = readMetadata(first.metadataBytes)
    metadata.signature = second.binding.signature.toString('base64')

    expectLoadError(
      first,
      Buffer.from(JSON.stringify(metadata)),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('não aceita assinatura sobre payload sem domain separation', () => {
    const fixture = createBindingFixture()
    const metadata = readMetadata(fixture.metadataBytes)
    const payloadWithoutDomain = frame([
      Buffer.from('1', 'ascii'),
      Buffer.from('initial-owner'),
      Buffer.from(fixture.serverId, 'ascii'),
      Buffer.from(fixture.device.fingerprint, 'ascii'),
      fixture.device.publicKey
    ])
    metadata.signature = sign(null, payloadWithoutDomain, fixture.serverPrivateKey).toString('base64')

    expectLoadError(
      fixture,
      Buffer.from(JSON.stringify(metadata)),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })

  it('não aceita assinatura produzida com domínio diferente', () => {
    const fixture = createBindingFixture()
    const metadata = readMetadata(fixture.metadataBytes)
    const wrongDomainPayload = frame([
      Buffer.from('Masquerada/server-membership/v1'),
      Buffer.from('1', 'ascii'),
      Buffer.from('initial-owner'),
      Buffer.from(fixture.serverId, 'ascii'),
      Buffer.from(fixture.device.fingerprint, 'ascii'),
      fixture.device.publicKey
    ])
    metadata.signature = sign(null, wrongDomainPayload, fixture.serverPrivateKey).toString('base64')

    expect(INITIAL_OWNER_BINDING_DOMAIN).toBe('Masquerada/server-initial-owner/v1')
    expectLoadError(
      fixture,
      Buffer.from(JSON.stringify(metadata)),
      'SERVER_OWNER_BINDING_INVALID'
    )
  })
})

function createBindingFixture(device = createDeviceIdentity()) {
  const serverKeyPair = generateKeyPairSync('ed25519')
  const serverPublicKey = serverKeyPair.publicKey.export({ format: 'der', type: 'spki' })
  const serverId = fingerprint(serverPublicKey)
  const material = createInitialOwnerBinding(serverId, device, serverKeyPair.privateKey)

  return {
    ...material,
    device,
    serverId,
    serverPublicKey: Buffer.from(serverPublicKey),
    serverPrivateKey: serverKeyPair.privateKey
  }
}

function createDeviceIdentity() {
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({
    format: 'der',
    type: 'spki'
  })

  return {
    fingerprint: fingerprint(publicKey),
    publicKey: Buffer.from(publicKey)
  }
}

function fingerprint(publicKey: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
}

function readMetadata(metadataBytes: Buffer): Record<string, unknown> {
  return JSON.parse(metadataBytes.toString('utf8')) as Record<string, unknown>
}

function expectLoadError(
  fixture: ReturnType<typeof createBindingFixture>,
  metadataBytes: Buffer,
  code: InitialOwnerBindingErrorCode
): void {
  expectBindingError(
    () =>
      loadInitialOwnerBinding(
        metadataBytes,
        fixture.serverId,
        fixture.serverPublicKey
      ),
    code
  )
}

function expectBindingError(operation: () => unknown, code: InitialOwnerBindingErrorCode): void {
  expect(operation).toThrowError(expect.objectContaining({ code }))
}

function frame(fields: Buffer[]): Buffer {
  return Buffer.concat(
    fields.flatMap((field) => {
      const length = Buffer.alloc(4)
      length.writeUInt32BE(field.length)
      return [length, field]
    })
  )
}
