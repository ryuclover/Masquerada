import { createHash, generateKeyPairSync, sign } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  createServerInvite,
  decodeServerInvite,
  encodeInviteSigningPayload,
  encodeServerInvite,
  INVITE_PREFIX,
  MAX_SERVER_INVITE_STRING_LENGTH,
  SERVER_INVITE_DOMAIN,
  type ServerInviteErrorCode,
  verifyServerInvite
} from './server-invite'

describe('convites criptográficos de servidor (Server Invite)', () => {
  it('cria, codifica e verifica convite autossuficiente assinado pela Server Key', () => {
    const fixture = createServerFixture()
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt,
      maxUses: 1
    })

    expect(invite).toMatchObject({
      version: 1,
      type: 'server-invite',
      serverId: fixture.serverId,
      issuedByDeviceFingerprint: fixture.ownerDevice.fingerprint,
      expiresAt,
      maxUses: 1
    })
    expect(invite.inviteId).toMatch(/^[0-9a-f]{32}$/)
    expect(invite.inviteSecret).toMatch(/^[0-9a-f]{64}$/)
    expect(invite.signature).toHaveLength(64)

    const encoded = encodeServerInvite(invite)
    expect(encoded).toMatch(/^MQR1\.[A-Za-z0-9_-]+$/)

    const decoded = decodeServerInvite(encoded)
    expect(decoded).toEqual(invite)

    const verified = verifyServerInvite(encoded, fixture.serverPublicKey, {
      expectedServerId: fixture.serverId,
      nowSeconds: expiresAt - 100
    })
    expect(verified).toEqual(invite)
  })

  it('gera inviteId e inviteSecret únicos e com alta entropia para emissões sucessivas', () => {
    const fixture = createServerFixture()
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    const first = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt
    })
    const second = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt
    })

    expect(first.inviteId).not.toBe(second.inviteId)
    expect(first.inviteSecret).not.toBe(second.inviteSecret)
    expect(first.signature).not.toEqual(second.signature)
  })

  it('rejeita convite com prefixo de protocolo desconhecido', () => {
    const fixture = createServerFixture()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000
    })
    const encoded = encodeServerInvite(invite)
    const invalidPrefix = encoded.replace(INVITE_PREFIX, 'MQR2.')

    expectInviteError(() => decodeServerInvite(invalidPrefix), 'SERVER_INVITE_INVALID')
  })

  it('rejeita convite com espaços em branco, quebras de linha ou caracteres estranhos', () => {
    const fixture = createServerFixture()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000
    })
    const encoded = encodeServerInvite(invite)

    expectInviteError(() => decodeServerInvite(` ${encoded}`), 'SERVER_INVITE_INVALID')
    expectInviteError(() => decodeServerInvite(`${encoded}\n`), 'SERVER_INVITE_INVALID')
    expectInviteError(() => decodeServerInvite(`${encoded}=`), 'SERVER_INVITE_INVALID')
  })

  it('rejeita convite cujo tamanho excede o limite máximo permitido', () => {
    const excessiveString = `${INVITE_PREFIX}${'A'.repeat(MAX_SERVER_INVITE_STRING_LENGTH)}`

    expectInviteError(() => decodeServerInvite(excessiveString), 'SERVER_INVITE_INVALID')
  })

  it('rejeita convite expirado durante verificação temporal', () => {
    const fixture = createServerFixture()
    const expiresAt = 1700000000
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt
    })

    expectInviteError(
      () =>
        verifyServerInvite(invite, fixture.serverPublicKey, {
          nowSeconds: expiresAt + 1
        }),
      'SERVER_INVITE_EXPIRED'
    )
  })

  it('rejeita convite com serverId divergente do expectedServerId', () => {
    const fixture = createServerFixture()
    const otherServer = createServerFixture()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000
    })

    expectInviteError(
      () =>
        verifyServerInvite(invite, fixture.serverPublicKey, {
          expectedServerId: otherServer.serverId
        }),
      'SERVER_INVITE_SERVER_MISMATCH'
    )
  })

  it('rejeita convite se a server public key não corresponder ao serverId do convite', () => {
    const fixture = createServerFixture()
    const otherServer = createServerFixture()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000
    })

    expectInviteError(
      () => verifyServerInvite(invite, otherServer.serverPublicKey),
      'SERVER_INVITE_INVALID'
    )
  })

  it('rejeita convite adulterado em qualquer um de seus campos (assinatura inválida)', () => {
    const fixture = createServerFixture()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    // Adulteração de maxUses
    const tampered = { ...invite, maxUses: 5 }
    expectInviteError(() => verifyServerInvite(tampered, fixture.serverPublicKey), 'SERVER_INVITE_INVALID')

    // Adulteração de inviteSecret
    const tamperedSecret = { ...invite, inviteSecret: '0'.repeat(64) }
    expectInviteError(() => verifyServerInvite(tamperedSecret, fixture.serverPublicKey), 'SERVER_INVITE_INVALID')

    // Adulteração de expiresAt
    const tamperedExpiry = { ...invite, expiresAt: 2000000001 }
    expectInviteError(() => verifyServerInvite(tamperedExpiry, fixture.serverPublicKey), 'SERVER_INVITE_INVALID')
  })

  it('rejeita convite assinado com domain separation incorreto', () => {
    const fixture = createServerFixture()
    const inviteId = 'a'.repeat(32)
    const inviteSecret = 'b'.repeat(64)
    const expiresAt = 2000000000
    const maxUses = 1
    const wrongDomainPayload = encodeInviteSigningPayload(
      fixture.serverId,
      inviteId,
      inviteSecret,
      fixture.ownerDevice.fingerprint,
      expiresAt,
      maxUses,
      'Masquerada/server-initial-owner/v1'
    )
    const wrongDomainSignature = sign(null, wrongDomainPayload, fixture.serverPrivateKey)

    const invite = {
      version: 1 as const,
      type: 'server-invite' as const,
      serverId: fixture.serverId,
      inviteId,
      inviteSecret,
      issuedByDeviceFingerprint: fixture.ownerDevice.fingerprint,
      expiresAt,
      maxUses,
      signature: Buffer.from(wrongDomainSignature)
    }

    expect(SERVER_INVITE_DOMAIN).toBe('Masquerada/server-invite/v1')
    expectInviteError(() => verifyServerInvite(invite, fixture.serverPublicKey), 'SERVER_INVITE_INVALID')
  })

  it.each([
    ['versão desconhecida', (m: Record<string, unknown>) => { m.version = 2 }, 'SERVER_INVITE_VERSION_UNSUPPORTED' as const],
    ['tipo inválido', (m: Record<string, unknown>) => { m.type = 'membership' }, 'SERVER_INVITE_INVALID' as const],
    ['campo ausente', (m: Record<string, unknown>) => { delete m.inviteSecret }, 'SERVER_INVITE_INVALID' as const],
    ['campo extra', (m: Record<string, unknown>) => { m.role = 'admin' }, 'SERVER_INVITE_INVALID' as const],
    ['expiresAt negativo', (m: Record<string, unknown>) => { m.expiresAt = -1 }, 'SERVER_INVITE_INVALID' as const],
    ['maxUses zero', (m: Record<string, unknown>) => { m.maxUses = 0 }, 'SERVER_INVITE_INVALID' as const],
    ['inviteId malformado', (m: Record<string, unknown>) => { m.inviteId = '123' }, 'SERVER_INVITE_INVALID' as const],
    ['inviteSecret malformado', (m: Record<string, unknown>) => { m.inviteSecret = 'xyz' }, 'SERVER_INVITE_INVALID' as const]
  ])('rejeita metadata com %s', (_name, mutate, expectedCode) => {
    const fixture = createServerFixture()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000
    })
    const metadata: Record<string, unknown> = {
      version: invite.version,
      type: invite.type,
      serverId: invite.serverId,
      inviteId: invite.inviteId,
      inviteSecret: invite.inviteSecret,
      issuedByDeviceFingerprint: invite.issuedByDeviceFingerprint,
      expiresAt: invite.expiresAt,
      maxUses: invite.maxUses,
      signature: invite.signature.toString('base64url')
    }

    mutate(metadata)
    const jsonBytes = Buffer.from(JSON.stringify(metadata), 'utf8')
    const encoded = `${INVITE_PREFIX}${jsonBytes.toString('base64url')}`

    expectInviteError(() => decodeServerInvite(encoded), expectedCode)
  })
})

function createServerFixture() {
  const serverKeyPair = generateKeyPairSync('ed25519')
  const serverPublicKey = Buffer.from(serverKeyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const serverId = `sha256:${createHash('sha256').update(serverPublicKey).digest('hex')}`

  const ownerKeyPair = generateKeyPairSync('ed25519')
  const ownerPublicKey = Buffer.from(ownerKeyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const ownerFingerprint = `sha256:${createHash('sha256').update(ownerPublicKey).digest('hex')}`

  return {
    serverId,
    serverPublicKey,
    serverPrivateKey: serverKeyPair.privateKey,
    ownerDevice: {
      fingerprint: ownerFingerprint,
      publicKey: ownerPublicKey
    }
  }
}

function expectInviteError(operation: () => unknown, code: ServerInviteErrorCode): void {
  expect(operation).toThrowError(expect.objectContaining({ code }))
}
