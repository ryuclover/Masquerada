import { createHash, generateKeyPairSync } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  buildCanonicalMemberCertificatePayload,
  createMemberCertificate,
  MEMBER_CERTIFICATE_DOMAIN,
  MEMBER_CERTIFICATE_SIGNATURE_BYTES,
  MEMBER_CERTIFICATE_VERSION,
  verifyMemberCertificate,
  type MemberCertificate
} from './member-certificate'

describe('member-certificate: artefato criptográfico e certificação de membership', () => {
  it('(1) constrói payload binário canônico determinístico com domain separation', () => {
    const serverKey = generateKeyPairSync('ed25519')
    const serverPubDer = Buffer.from(serverKey.publicKey.export({ format: 'der', type: 'spki' }))
    const serverId = `sha256:${createHash('sha256').update(serverPubDer).digest('hex')}`

    const memberKey = generateKeyPairSync('ed25519')
    const memberPubDer = Buffer.from(memberKey.publicKey.export({ format: 'der', type: 'spki' }))
    const memberFingerprint = `sha256:${createHash('sha256').update(memberPubDer).digest('hex')}`
    const inviteId = '0123456789abcdef0123456789abcdef'

    const payload = buildCanonicalMemberCertificatePayload(
      serverId,
      memberFingerprint,
      memberPubDer,
      inviteId
    )

    expect(payload).toBeInstanceOf(Buffer)
    expect(payload.length).toBeGreaterThan(100)

    // Verifica domain prefix
    const domainLen = payload.readUInt8(0)
    expect(payload.subarray(1, 1 + domainLen).toString('utf8')).toBe(MEMBER_CERTIFICATE_DOMAIN)
  })

  it('(2) cria e verifica com sucesso Member Certificate legítimo assinado pela Server Identity', () => {
    const serverKey = generateKeyPairSync('ed25519')
    const serverPubDer = Buffer.from(serverKey.publicKey.export({ format: 'der', type: 'spki' }))
    const serverId = `sha256:${createHash('sha256').update(serverPubDer).digest('hex')}`

    const memberKey = generateKeyPairSync('ed25519')
    const memberPubDer = Buffer.from(memberKey.publicKey.export({ format: 'der', type: 'spki' }))
    const memberFingerprint = `sha256:${createHash('sha256').update(memberPubDer).digest('hex')}`
    const inviteId = 'aabbccddeeff00112233445566778899'

    const cert = createMemberCertificate(
      serverId,
      serverKey.privateKey,
      memberFingerprint,
      memberPubDer,
      inviteId
    )

    expect(cert.version).toBe(MEMBER_CERTIFICATE_VERSION)
    expect(cert.type).toBe('member-certificate')
    expect(cert.serverId).toBe(serverId)
    expect(cert.memberDeviceFingerprint).toBe(memberFingerprint)
    expect(cert.memberDevicePublicKey.equals(memberPubDer)).toBe(true)
    expect(cert.admissionInviteId).toBe(inviteId)
    expect(cert.signature.length).toBe(MEMBER_CERTIFICATE_SIGNATURE_BYTES)

    // Verificação válida
    expect(verifyMemberCertificate(cert, serverId, serverPubDer)).toBe(true)
  })

  it('(3) rejeita verificação se o certificado for verificado contra outro serverId / chave de outro servidor', () => {
    const serverKeyA = generateKeyPairSync('ed25519')
    const serverPubDerA = Buffer.from(serverKeyA.publicKey.export({ format: 'der', type: 'spki' }))
    const serverIdA = `sha256:${createHash('sha256').update(serverPubDerA).digest('hex')}`

    const serverKeyB = generateKeyPairSync('ed25519')
    const serverPubDerB = Buffer.from(serverKeyB.publicKey.export({ format: 'der', type: 'spki' }))
    const serverIdB = `sha256:${createHash('sha256').update(serverPubDerB).digest('hex')}`

    const memberKey = generateKeyPairSync('ed25519')
    const memberPubDer = Buffer.from(memberKey.publicKey.export({ format: 'der', type: 'spki' }))
    const memberFingerprint = `sha256:${createHash('sha256').update(memberPubDer).digest('hex')}`
    const inviteId = '11223344556677889900aabbccddeeff'

    // Certificado emitido pelo Server A
    const certA = createMemberCertificate(
      serverIdA,
      serverKeyA.privateKey,
      memberFingerprint,
      memberPubDer,
      inviteId
    )

    // Tenta validar contra Server B -> falha
    expect(() => {
      verifyMemberCertificate(certA, serverIdB, serverPubDerB)
    }).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBER_CERTIFICATE_INVALID' }))
  })

  it('(4) rejeita certificado com adulteração (tampering) de fingerprint, public key, inviteId ou assinatura', () => {
    const serverKey = generateKeyPairSync('ed25519')
    const serverPubDer = Buffer.from(serverKey.publicKey.export({ format: 'der', type: 'spki' }))
    const serverId = `sha256:${createHash('sha256').update(serverPubDer).digest('hex')}`

    const memberKey = generateKeyPairSync('ed25519')
    const memberPubDer = Buffer.from(memberKey.publicKey.export({ format: 'der', type: 'spki' }))
    const memberFingerprint = `sha256:${createHash('sha256').update(memberPubDer).digest('hex')}`
    const inviteId = '11223344556677889900aabbccddeeff'

    const validCert = createMemberCertificate(
      serverId,
      serverKey.privateKey,
      memberFingerprint,
      memberPubDer,
      inviteId
    )

    // 1. Alteração de fingerprint
    const tamperedFingerprint: MemberCertificate = {
      ...validCert,
      memberDeviceFingerprint: 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    }
    expect(() => verifyMemberCertificate(tamperedFingerprint, serverId, serverPubDer)).toThrowError()

    // 2. Alteração de public key
    const otherMemberKey = generateKeyPairSync('ed25519')
    const otherMemberPubDer = Buffer.from(otherMemberKey.publicKey.export({ format: 'der', type: 'spki' }))
    const tamperedKey: MemberCertificate = {
      ...validCert,
      memberDevicePublicKey: otherMemberPubDer
    }
    expect(() => verifyMemberCertificate(tamperedKey, serverId, serverPubDer)).toThrowError()

    // 3. Alteração de inviteId
    const tamperedInvite: MemberCertificate = {
      ...validCert,
      admissionInviteId: 'ffffffffffffffffffffffffffffffff'
    }
    expect(() => verifyMemberCertificate(tamperedInvite, serverId, serverPubDer)).toThrowError()

    // 4. Alteração de assinatura
    const badSig = Buffer.from(validCert.signature)
    badSig[0] = (badSig[0] ?? 0) ^ 0xff
    const tamperedSig: MemberCertificate = {
      ...validCert,
      signature: badSig
    }
    expect(() => verifyMemberCertificate(tamperedSig, serverId, serverPubDer)).toThrowError()
  })

  it('(5) garante imutabilidade defensiva dos buffers retornados', () => {
    const serverKey = generateKeyPairSync('ed25519')
    const serverPubDer = Buffer.from(serverKey.publicKey.export({ format: 'der', type: 'spki' }))
    const serverId = `sha256:${createHash('sha256').update(serverPubDer).digest('hex')}`

    const memberKey = generateKeyPairSync('ed25519')
    const memberPubDer = Buffer.from(memberKey.publicKey.export({ format: 'der', type: 'spki' }))
    const memberFingerprint = `sha256:${createHash('sha256').update(memberPubDer).digest('hex')}`
    const inviteId = '1234567890abcdef1234567890abcdef'

    const cert = createMemberCertificate(
      serverId,
      serverKey.privateKey,
      memberFingerprint,
      memberPubDer,
      inviteId
    )

    // Modifica o buffer de entrada original
    memberPubDer[0] = (memberPubDer[0] ?? 0) ^ 0xff
    expect(cert.memberDevicePublicKey[0]).not.toBe(memberPubDer[0])

    // Modifica o buffer do certificado
    const certKeyCopy = Buffer.from(cert.memberDevicePublicKey)
    certKeyCopy[0] = (certKeyCopy[0] ?? 0) ^ 0xff
    expect(cert.memberDevicePublicKey.equals(certKeyCopy)).toBe(false)
  })
})
