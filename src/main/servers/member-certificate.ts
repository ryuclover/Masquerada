import {
  createHash,
  createPublicKey,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

export const MEMBER_CERTIFICATE_DOMAIN = 'Masquerada/server-member-certificate/v1'
export const MEMBER_CERTIFICATE_VERSION = 1
export const MEMBER_CERTIFICATE_SIGNATURE_BYTES = 64
const MAX_PUBLIC_KEY_BYTES = 256
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/
const HEX_32_PATTERN = /^[0-9a-f]{32}$/

export type MemberCertificateErrorCode =
  | 'SERVER_MEMBER_CERTIFICATE_INVALID'
  | 'SERVER_MEMBER_CERTIFICATE_MISSING'
  | 'SERVER_MEMBER_CERTIFICATE_UNEXPECTED'
  | 'SERVER_MEMBERSHIP_STATE_INVALID'
  | 'SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION'

const ERROR_MESSAGES: Record<MemberCertificateErrorCode, string> = {
  SERVER_MEMBER_CERTIFICATE_INVALID: 'O certificado de membro é inválido, corrompido ou a assinatura não confere.',
  SERVER_MEMBER_CERTIFICATE_MISSING: 'Membro não-owner persistido sem o correspondente certificado criptográfico da Server Identity.',
  SERVER_MEMBER_CERTIFICATE_UNEXPECTED: 'Certificado de membro inesperado para a autoridade do Initial Owner.',
  SERVER_MEMBERSHIP_STATE_INVALID: 'O estado de membros do servidor é inválido ou inconsistente com a autoridade.',
  SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION: 'Migração de banco com membros não-owner legados exige nova admissão para certificação criptográfica.'
}

export class MemberCertificateError extends Error {
  readonly code: MemberCertificateErrorCode

  constructor(code: MemberCertificateErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'MemberCertificateError'
    this.code = code
  }
}

export interface MemberCertificate {
  readonly version: 1
  readonly type: 'member-certificate'
  readonly serverId: string
  readonly memberDeviceFingerprint: string
  readonly memberDevicePublicKey: Buffer
  readonly admissionInviteId: string
  readonly signature: Buffer
}

/**
 * Constrói o payload binário canônico para assinatura e verificação do Member Certificate.
 */
export function buildCanonicalMemberCertificatePayload(
  serverId: string,
  memberDeviceFingerprint: string,
  memberDevicePublicKey: Buffer,
  admissionInviteId: string
): Buffer {
  const domainBuf = Buffer.from(MEMBER_CERTIFICATE_DOMAIN, 'utf8')
  const serverIdBuf = Buffer.from(serverId, 'utf8')
  const fingerprintBuf = Buffer.from(memberDeviceFingerprint, 'utf8')
  const inviteIdBuf = Buffer.from(admissionInviteId, 'utf8')

  const chunks: Buffer[] = []

  // 1. Domain (1 byte length + UTF-8)
  const dHeader = Buffer.alloc(1 + domainBuf.length)
  dHeader.writeUInt8(domainBuf.length, 0)
  domainBuf.copy(dHeader, 1)
  chunks.push(dHeader)

  // 2. Version (1 byte: 1) + Type (1 byte: 1)
  const verType = Buffer.alloc(2)
  verType.writeUInt8(MEMBER_CERTIFICATE_VERSION, 0)
  verType.writeUInt8(1, 1) // 1 = member-certificate
  chunks.push(verType)

  // 3. ServerId (1 byte length + UTF-8)
  const sHeader = Buffer.alloc(1 + serverIdBuf.length)
  sHeader.writeUInt8(serverIdBuf.length, 0)
  serverIdBuf.copy(sHeader, 1)
  chunks.push(sHeader)

  // 4. MemberDeviceFingerprint (1 byte length + UTF-8)
  const fHeader = Buffer.alloc(1 + fingerprintBuf.length)
  fHeader.writeUInt8(fingerprintBuf.length, 0)
  fingerprintBuf.copy(fHeader, 1)
  chunks.push(fHeader)

  // 5. MemberDevicePublicKey (2 bytes uint16BE length + raw DER bytes)
  const pHeader = Buffer.alloc(2 + memberDevicePublicKey.length)
  pHeader.writeUInt16BE(memberDevicePublicKey.length, 0)
  memberDevicePublicKey.copy(pHeader, 2)
  chunks.push(pHeader)

  // 6. AdmissionInviteId (1 byte length + UTF-8)
  const iHeader = Buffer.alloc(1 + inviteIdBuf.length)
  iHeader.writeUInt8(inviteIdBuf.length, 0)
  inviteIdBuf.copy(iHeader, 1)
  chunks.push(iHeader)

  return Buffer.concat(chunks)
}

/**
 * Cria e assina criptograficamente um Member Certificate para um novo membro admitido.
 */
export function createMemberCertificate(
  serverId: string,
  serverPrivateKey: KeyObject,
  memberDeviceFingerprint: string,
  memberDevicePublicKey: Buffer,
  admissionInviteId: string
): MemberCertificate {
  if (typeof serverId !== 'string' || !FINGERPRINT_PATTERN.test(serverId)) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (typeof memberDeviceFingerprint !== 'string' || !FINGERPRINT_PATTERN.test(memberDeviceFingerprint)) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (typeof admissionInviteId !== 'string' || !HEX_32_PATTERN.test(admissionInviteId)) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (
    !Buffer.isBuffer(memberDevicePublicKey) ||
    memberDevicePublicKey.length === 0 ||
    memberDevicePublicKey.length > MAX_PUBLIC_KEY_BYTES
  ) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  // Valida integridade entre memberDevicePublicKey e memberDeviceFingerprint
  const expectedFingerprint = `sha256:${createHash('sha256').update(memberDevicePublicKey).digest('hex')}`
  if (memberDeviceFingerprint !== expectedFingerprint) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  const canonicalPayload = buildCanonicalMemberCertificatePayload(
    serverId,
    memberDeviceFingerprint,
    memberDevicePublicKey,
    admissionInviteId
  )

  const signature = sign(null, canonicalPayload, serverPrivateKey)
  if (signature.length !== MEMBER_CERTIFICATE_SIGNATURE_BYTES) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  return Object.freeze({
    version: 1,
    type: 'member-certificate',
    serverId,
    memberDeviceFingerprint,
    memberDevicePublicKey: Buffer.from(memberDevicePublicKey),
    admissionInviteId,
    signature: Buffer.from(signature)
  })
}

/**
 * Valida e verifica a autenticidade criptográfica de um Member Certificate usando a Server Public Key.
 */
export function verifyMemberCertificate(
  certificate: MemberCertificate,
  expectedServerId: string,
  serverPublicKeyDer: Buffer
): boolean {
  if (!certificate || typeof certificate !== 'object') {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (certificate.version !== MEMBER_CERTIFICATE_VERSION || certificate.type !== 'member-certificate') {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (certificate.serverId !== expectedServerId) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (!FINGERPRINT_PATTERN.test(certificate.memberDeviceFingerprint)) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (!HEX_32_PATTERN.test(certificate.admissionInviteId)) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (
    !Buffer.isBuffer(certificate.signature) ||
    certificate.signature.length !== MEMBER_CERTIFICATE_SIGNATURE_BYTES
  ) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }
  if (
    !Buffer.isBuffer(certificate.memberDevicePublicKey) ||
    certificate.memberDevicePublicKey.length === 0 ||
    certificate.memberDevicePublicKey.length > MAX_PUBLIC_KEY_BYTES
  ) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  // Verifica que o fingerprint confere com a chave do membro
  const expectedFingerprint = `sha256:${createHash('sha256').update(certificate.memberDevicePublicKey).digest('hex')}`
  if (certificate.memberDeviceFingerprint !== expectedFingerprint) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  // Verifica que a chave do servidor confere com o expectedServerId
  const expectedDerivedServerId = `sha256:${createHash('sha256').update(serverPublicKeyDer).digest('hex')}`
  if (expectedServerId !== expectedDerivedServerId) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  const canonicalPayload = buildCanonicalMemberCertificatePayload(
    certificate.serverId,
    certificate.memberDeviceFingerprint,
    certificate.memberDevicePublicKey,
    certificate.admissionInviteId
  )

  let serverKeyObject: KeyObject
  try {
    serverKeyObject = createPublicKey({ key: serverPublicKeyDer, format: 'der', type: 'spki' })
  } catch {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  const isValid = verify(null, canonicalPayload, serverKeyObject, certificate.signature)
  if (!isValid) {
    throw new MemberCertificateError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  return true
}
