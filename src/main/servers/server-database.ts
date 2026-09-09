import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  type KeyObject
} from 'node:crypto'
import { open, stat } from 'node:fs/promises'
import { DatabaseSync } from 'node:sqlite'

import type { InitialOwnerDeviceIdentity } from './initial-owner-binding'
import {
  createMemberCertificate,
  verifyMemberCertificate,
  type MemberCertificate
} from './member-certificate'
import {
  decodeServerInvite,
  verifyServerInvite,
  type ServerInvite
} from './server-invite'

export const DATABASE_FILE_NAME = 'server.db'
export const DATABASE_SCHEMA_VERSION = 4
export const MAX_INITIAL_SERVER_DATABASE_BYTES = 1024 * 1024 // 1 MB
export const MIN_SERVER_DATABASE_BYTES = 512
export const MAX_MEMBERS_LIST_LIMIT = 1000
export const SECRET_HASH_BYTES = 32
const MAX_PUBLIC_KEY_BYTES = 256
const SQLITE_HEADER = Buffer.from('SQLite format 3\0', 'utf8')
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/
const HEX_32_PATTERN = /^[0-9a-f]{32}$/
const HEX_64_PATTERN = /^[0-9a-f]{64}$/

export type ServerDatabaseErrorCode =
  | 'SERVER_DATABASE_NOT_FOUND'
  | 'SERVER_DATABASE_PATH_UNSAFE'
  | 'SERVER_DATABASE_CORRUPTED'
  | 'SERVER_DATABASE_SCHEMA_INVALID'
  | 'SERVER_DATABASE_VERSION_UNSUPPORTED'
  | 'SERVER_DATABASE_TOO_LARGE'
  | 'SERVER_DATABASE_INITIALIZATION_FAILED'
  | 'SERVER_MEMBERSHIP_STATE_INVALID'
  | 'SERVER_MEMBER_CERTIFICATE_INVALID'
  | 'SERVER_MEMBER_CERTIFICATE_MISSING'
  | 'SERVER_MEMBER_CERTIFICATE_UNEXPECTED'
  | 'SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION'
  | 'SERVER_INVITE_NOT_FOUND'
  | 'SERVER_INVITE_STATE_INVALID'
  | 'SERVER_INVITE_EXHAUSTED'
  | 'SERVER_INVITE_REVOKED'
  | 'SERVER_INVITE_EXPIRED'
  | 'SERVER_INVITE_INVALID'
  | 'SERVER_MEMBER_ALREADY_EXISTS'
  | 'SERVER_ADMISSION_INVALID_CANDIDATE'
  | 'SERVER_ADMISSION_FAILED'

const ERROR_MESSAGES: Record<ServerDatabaseErrorCode, string> = {
  SERVER_DATABASE_NOT_FOUND: 'O banco de dados do servidor não foi encontrado.',
  SERVER_DATABASE_PATH_UNSAFE: 'O caminho do banco de dados do servidor não é seguro.',
  SERVER_DATABASE_CORRUPTED: 'O banco de dados do servidor está corrompido ou é inválido.',
  SERVER_DATABASE_SCHEMA_INVALID: 'O esquema do banco de dados do servidor é inválido ou contém objetos inesperados.',
  SERVER_DATABASE_VERSION_UNSUPPORTED: 'A versão do esquema do banco de dados do servidor não é suportada.',
  SERVER_DATABASE_TOO_LARGE: 'O arquivo de banco de dados do servidor excede o tamanho máximo permitido.',
  SERVER_DATABASE_INITIALIZATION_FAILED: 'Não foi possível inicializar o banco de dados do servidor com segurança.',
  SERVER_MEMBERSHIP_STATE_INVALID: 'O estado de membros do servidor é inválido ou inconsistente com a autoridade.',
  SERVER_MEMBER_CERTIFICATE_INVALID: 'O certificado de membro é inválido ou forjado.',
  SERVER_MEMBER_CERTIFICATE_MISSING: 'Membro não-owner persistido sem certificado criptográfico da Server Identity.',
  SERVER_MEMBER_CERTIFICATE_UNEXPECTED: 'Certificado de membro inesperado para o Initial Owner.',
  SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION: 'Migração de banco legado v3 com membros não-owner exige nova admissão criptográfica.',
  SERVER_INVITE_NOT_FOUND: 'O convite do servidor não foi encontrado.',
  SERVER_INVITE_STATE_INVALID: 'O estado persistido do convite é inválido ou inconsistente.',
  SERVER_INVITE_EXHAUSTED: 'O convite do servidor já atingiu o limite máximo de utilizações.',
  SERVER_INVITE_REVOKED: 'O convite do servidor foi revogado.',
  SERVER_INVITE_EXPIRED: 'O convite do servidor expirou.',
  SERVER_INVITE_INVALID: 'O convite do servidor é inválido.',
  SERVER_MEMBER_ALREADY_EXISTS: 'A identidade do dispositivo candidato já é membro do servidor.',
  SERVER_ADMISSION_INVALID_CANDIDATE: 'A identidade do dispositivo candidato é inválida.',
  SERVER_ADMISSION_FAILED: 'Não foi possível admitir o novo membro no servidor com segurança.'
}

export class ServerDatabaseError extends Error {
  readonly code: ServerDatabaseErrorCode

  constructor(code: ServerDatabaseErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'ServerDatabaseError'
    this.code = code
  }
}

export interface Member {
  readonly deviceFingerprint: string
  readonly publicKey: Buffer
}

export interface ExpectedOwner {
  readonly deviceFingerprint: string
  readonly publicKey: Buffer
}

export interface ExpectedServerContext {
  readonly serverId: string
  readonly serverPublicKey: Buffer
}

import {
  type AuthenticatedCandidateDevice,
  isAuthenticatedCandidateDevice
} from '../security/authenticated-candidate'
export type { AuthenticatedCandidateDevice }

export interface StoredInvite {
  readonly inviteId: string
  readonly expiresAt: number
  readonly maxUses: number
  readonly uses: number
  readonly revoked: boolean
  readonly status: 'available' | 'exhausted' | 'revoked' | 'expired'
}

export function initializeServerDatabase(
  databasePath: string,
  initialOwner: InitialOwnerDeviceIdentity
): void {
  let db: DatabaseSync | undefined

  try {
    const validatedOwnerKey = validatePublicKeyDer(
      initialOwner.publicKey,
      initialOwner.fingerprint,
      'SERVER_DATABASE_INITIALIZATION_FAILED'
    )

    db = new DatabaseSync(databasePath, { readOnly: false })
    configurePragmas(db)
    db.exec(`
      CREATE TABLE members (
        device_fingerprint TEXT PRIMARY KEY,
        device_public_key BLOB NOT NULL
      );

      CREATE TABLE member_certificates (
        device_fingerprint TEXT PRIMARY KEY
          REFERENCES members(device_fingerprint)
          ON DELETE RESTRICT,
        certificate_version INTEGER NOT NULL
          CHECK (certificate_version = 1),
        admission_invite_id TEXT NOT NULL,
        signature BLOB NOT NULL
      );

      CREATE TABLE invites (
        invite_id TEXT PRIMARY KEY,
        invite_secret_hash BLOB NOT NULL,
        expires_at INTEGER NOT NULL,
        max_uses INTEGER NOT NULL,
        uses INTEGER NOT NULL,
        revoked INTEGER NOT NULL,
        CHECK (max_uses >= 1),
        CHECK (uses >= 0),
        CHECK (uses <= max_uses),
        CHECK (revoked IN (0, 1))
      );
    `)

    db.prepare(`
      INSERT INTO members (device_fingerprint, device_public_key)
      VALUES (?, ?);
    `).run(initialOwner.fingerprint, validatedOwnerKey)

    db.exec(`PRAGMA user_version = ${DATABASE_SCHEMA_VERSION};`)
    validateDatabaseIntegrityAndSchema(db, {
      deviceFingerprint: initialOwner.fingerprint,
      publicKey: validatedOwnerKey
    })
  } catch (error) {
    throw databaseWriteError(error, 'SERVER_DATABASE_INITIALIZATION_FAILED')
  } finally {
    if (db) {
      try {
        db.close()
      } catch {
        // Ignora erro ao fechar em cleanup
      }
    }
  }
}

export async function validateServerDatabaseFile(
  databasePath: string,
  expectedOwner?: ExpectedOwner,
  serverContext?: ExpectedServerContext
): Promise<void> {
  let fileHandle
  try {
    const stats = await stat(databasePath)

    if (stats.size > MAX_INITIAL_SERVER_DATABASE_BYTES) {
      throw new ServerDatabaseError('SERVER_DATABASE_TOO_LARGE')
    }

    if (stats.size < MIN_SERVER_DATABASE_BYTES) {
      throw new ServerDatabaseError('SERVER_DATABASE_CORRUPTED')
    }

    fileHandle = await open(databasePath, 'r')
    const headerBuffer = Buffer.alloc(16)
    const { bytesRead } = await fileHandle.read(headerBuffer, 0, 16, 0)

    if (bytesRead < 16 || !headerBuffer.equals(SQLITE_HEADER)) {
      throw new ServerDatabaseError('SERVER_DATABASE_CORRUPTED')
    }
  } catch (error) {
    if (error instanceof ServerDatabaseError) {
      throw error
    }

    throw new ServerDatabaseError('SERVER_DATABASE_CORRUPTED')
  } finally {
    if (fileHandle) {
      await fileHandle.close().catch(() => undefined)
    }
  }

  validateDatabaseContent(databasePath, expectedOwner, serverContext)
}

export function openServerDatabase(
  databasePath: string,
  expectedOwner?: ExpectedOwner,
  serverContext?: ExpectedServerContext
): DatabaseSync {
  let db: DatabaseSync | undefined

  try {
    db = new DatabaseSync(databasePath, { readOnly: false })
    configurePragmas(db)
    validateDatabaseIntegrityAndSchema(db, expectedOwner, serverContext)
    return db
  } catch (error) {
    if (db) {
      try {
        db.close()
      } catch {
        // Ignora erro ao fechar em cleanup
      }
    }

    throw databaseWriteError(error, 'SERVER_DATABASE_CORRUPTED')
  }
}

function validateDatabaseContent(
  databasePath: string,
  expectedOwner?: ExpectedOwner,
  serverContext?: ExpectedServerContext
): void {
  const db = openServerDatabase(databasePath, expectedOwner, serverContext)
  db.close()
}

export function configurePragmas(db: DatabaseSync): void {
  const { page_size: pageSize } = db.prepare('PRAGMA page_size;').get() as { page_size: number }
  const maxPages = Math.floor(MAX_INITIAL_SERVER_DATABASE_BYTES / pageSize)
  const { max_page_count: configuredMaxPages } = db
    .prepare(`PRAGMA max_page_count = ${maxPages};`)
    .get() as { max_page_count: number }

  // SQLite cannot lower the limit below the existing page count.
  if (configuredMaxPages > maxPages) {
    throw new ServerDatabaseError('SERVER_DATABASE_TOO_LARGE')
  }

  db.exec('PRAGMA foreign_keys = ON;')
  db.exec('PRAGMA trusted_schema = OFF;')
  db.exec('PRAGMA busy_timeout = 5000;')
  db.exec('PRAGMA journal_mode = DELETE;')
  db.exec('PRAGMA synchronous = FULL;')
}

function validateDatabaseIntegrityAndSchema(
  db: DatabaseSync,
  expectedOwner?: ExpectedOwner,
  serverContext?: ExpectedServerContext
): void {
  let quickCheckRows: unknown[]

  try {
    quickCheckRows = db.prepare('PRAGMA quick_check;').all()
  } catch {
    throw new ServerDatabaseError('SERVER_DATABASE_CORRUPTED')
  }

  if (
    !Array.isArray(quickCheckRows) ||
    quickCheckRows.length !== 1 ||
    (quickCheckRows[0] as { quick_check?: string }).quick_check !== 'ok'
  ) {
    throw new ServerDatabaseError('SERVER_DATABASE_CORRUPTED')
  }

  const userVersionResult = db.prepare('PRAGMA user_version;').get() as
    | { user_version?: number }
    | undefined

  if (
    !userVersionResult ||
    typeof userVersionResult.user_version !== 'number' ||
    !Number.isInteger(userVersionResult.user_version)
  ) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  const version = userVersionResult.user_version

  if (version > DATABASE_SCHEMA_VERSION) {
    throw new ServerDatabaseError('SERVER_DATABASE_VERSION_UNSUPPORTED')
  }

  // Migração segura de v3 -> v4 se elegível (apenas Initial Owner)
  if (version === 3) {
    if (!expectedOwner) {
      throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
    }

    // Executa migração atômica para v4
    db.exec('BEGIN IMMEDIATE;')
    try {
      const v3Members = db.prepare('SELECT device_fingerprint, device_public_key FROM members;').all()
      if (v3Members.length !== 1) {
        throw new ServerDatabaseError('SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION')
      }

      const ownerMember = parseAndValidateMemberRow(v3Members[0])
      if (
        ownerMember.deviceFingerprint !== expectedOwner.deviceFingerprint ||
        !ownerMember.publicKey.equals(expectedOwner.publicKey)
      ) {
        throw new ServerDatabaseError('SERVER_MEMBERSHIP_STATE_INVALID')
      }

      db.exec(`
        CREATE TABLE member_certificates (
          device_fingerprint TEXT PRIMARY KEY
            REFERENCES members(device_fingerprint)
            ON DELETE RESTRICT,
          certificate_version INTEGER NOT NULL
            CHECK (certificate_version = 1),
          admission_invite_id TEXT NOT NULL,
          signature BLOB NOT NULL
        );
      `)
      db.exec('PRAGMA user_version = 4;')
      // Validate the complete v4 schema and data before making the migration durable.
      validateDatabaseIntegrityAndSchema(db, expectedOwner, serverContext)
      db.exec('COMMIT;')
      return
    } catch (error) {
      try {
        db.exec('ROLLBACK;')
      } catch {
        // Ignora
      }
      throw databaseWriteError(error, 'SERVER_DATABASE_SCHEMA_INVALID')
    }
  } else if (version !== DATABASE_SCHEMA_VERSION) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  // Allowlist estrita de schema v4: exatamente 3 tabelas (invites, member_certificates, members)
  const schemaObjects = db
    .prepare("SELECT type, name, tbl_name FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name ASC;")
    .all() as Array<{ type?: unknown; name?: unknown; tbl_name?: unknown }>

  if (
    schemaObjects.length !== 3 ||
    schemaObjects[0]?.type !== 'table' ||
    schemaObjects[0]?.name !== 'invites' ||
    schemaObjects[0]?.tbl_name !== 'invites' ||
    schemaObjects[1]?.type !== 'table' ||
    schemaObjects[1]?.name !== 'member_certificates' ||
    schemaObjects[1]?.tbl_name !== 'member_certificates' ||
    schemaObjects[2]?.type !== 'table' ||
    schemaObjects[2]?.name !== 'members' ||
    schemaObjects[2]?.tbl_name !== 'members'
  ) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  // Valida todos os registros presentes na tabela members
  const allMembers = db
    .prepare('SELECT device_fingerprint, device_public_key FROM members;')
    .all()

  const memberMap = new Map<string, Member>()
  for (const row of allMembers) {
    const member = parseAndValidateMemberRow(row)
    memberMap.set(member.deviceFingerprint, member)
  }

  // Valida todos os registros presentes na tabela member_certificates
  const allCerts = db
    .prepare('SELECT device_fingerprint, certificate_version, admission_invite_id, signature FROM member_certificates;')
    .all()

  const certMap = new Map<string, RawStoredMemberCertificateRow>()
  for (const row of allCerts) {
    const cert = parseAndValidateStoredMemberCertificateRow(row)
    certMap.set(cert.device_fingerprint, cert)
  }

  // Valida todos os registros presentes na tabela invites
  const allInvites = db
    .prepare('SELECT invite_id, invite_secret_hash, expires_at, max_uses, uses, revoked FROM invites;')
    .all()

  for (const row of allInvites) {
    parseAndValidateStoredInviteRow(row)
  }

  // Se um expectedOwner foi especificado, valida a consistência de ownership e cardinalidade exata de certificados
  if (expectedOwner) {
    const ownerMember = memberMap.get(expectedOwner.deviceFingerprint)
    if (!ownerMember || !ownerMember.publicKey.equals(expectedOwner.publicKey)) {
      throw new ServerDatabaseError('SERVER_MEMBERSHIP_STATE_INVALID')
    }

    // Regra SEC-084: Initial Owner possui ZERO rows em member_certificates
    if (certMap.has(expectedOwner.deviceFingerprint)) {
      throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_UNEXPECTED')
    }

    // Regra SEC-083: Cardinalidade exata (N members -> exatamente N - 1 certificados)
    if (certMap.size !== memberMap.size - 1) {
      throw new ServerDatabaseError('SERVER_MEMBERSHIP_STATE_INVALID')
    }

    // Valida que cada membro não-owner possui exatamente 1 certificado correspondente e válido
    for (const [fingerprint, member] of memberMap) {
      if (fingerprint === expectedOwner.deviceFingerprint) continue

      const certRow = certMap.get(fingerprint)
      if (!certRow) {
        throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_MISSING')
      }

      // Se contexto criptográfico do servidor estiver disponível, valida a assinatura Ed25519
      if (serverContext) {
        const certObj: MemberCertificate = {
          version: 1,
          type: 'member-certificate',
          serverId: serverContext.serverId,
          memberDeviceFingerprint: fingerprint,
          memberDevicePublicKey: member.publicKey,
          admissionInviteId: certRow.admission_invite_id,
          signature: Buffer.from(certRow.signature)
        }

        try {
          verifyMemberCertificate(certObj, serverContext.serverId, serverContext.serverPublicKey)
        } catch {
          throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_INVALID')
        }
      }
    }
  }
}

export function parseAndValidateMemberRow(row: unknown): Member {
  if (!isRecord(row)) {
    throw new ServerDatabaseError('SERVER_MEMBERSHIP_STATE_INVALID')
  }

  const { device_fingerprint, device_public_key } = row

  if (typeof device_fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(device_fingerprint)) {
    throw new ServerDatabaseError('SERVER_MEMBERSHIP_STATE_INVALID')
  }

  if (
    !(device_public_key instanceof Uint8Array) ||
    device_public_key.length === 0 ||
    device_public_key.length > MAX_PUBLIC_KEY_BYTES
  ) {
    throw new ServerDatabaseError('SERVER_MEMBERSHIP_STATE_INVALID')
  }

  const validatedKey = validatePublicKeyDer(
    Buffer.from(device_public_key),
    device_fingerprint,
    'SERVER_MEMBERSHIP_STATE_INVALID'
  )

  return Object.freeze({
    deviceFingerprint: device_fingerprint,
    get publicKey(): Buffer {
      return Buffer.from(validatedKey)
    }
  })
}

interface RawStoredMemberCertificateRow {
  readonly device_fingerprint: string
  readonly certificate_version: number
  readonly admission_invite_id: string
  readonly signature: Uint8Array
}

function parseAndValidateStoredMemberCertificateRow(row: unknown): RawStoredMemberCertificateRow {
  if (!isRecord(row)) {
    throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  const {
    device_fingerprint,
    certificate_version,
    admission_invite_id,
    signature
  } = row

  if (typeof device_fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(device_fingerprint)) {
    throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  if (certificate_version !== 1) {
    throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  if (typeof admission_invite_id !== 'string' || !HEX_32_PATTERN.test(admission_invite_id)) {
    throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  if (
    !(signature instanceof Uint8Array) ||
    signature.length !== 64
  ) {
    throw new ServerDatabaseError('SERVER_MEMBER_CERTIFICATE_INVALID')
  }

  return {
    device_fingerprint,
    certificate_version,
    admission_invite_id,
    signature
  }
}

interface RawStoredInviteRow {
  readonly invite_id: string
  readonly invite_secret_hash: Uint8Array
  readonly expires_at: number
  readonly max_uses: number
  readonly uses: number
  readonly revoked: number
}

function parseAndValidateStoredInviteRow(row: unknown): RawStoredInviteRow {
  if (!isRecord(row)) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  const {
    invite_id,
    invite_secret_hash,
    expires_at,
    max_uses,
    uses,
    revoked
  } = row

  if (typeof invite_id !== 'string' || !HEX_32_PATTERN.test(invite_id)) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  if (
    !(invite_secret_hash instanceof Uint8Array) ||
    invite_secret_hash.length !== SECRET_HASH_BYTES
  ) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  if (typeof expires_at !== 'number' || !Number.isInteger(expires_at) || expires_at <= 0) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  if (typeof max_uses !== 'number' || !Number.isInteger(max_uses) || max_uses < 1) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  if (typeof uses !== 'number' || !Number.isInteger(uses) || uses < 0 || uses > max_uses) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  if (typeof revoked !== 'number' || (revoked !== 0 && revoked !== 1)) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  return {
    invite_id,
    invite_secret_hash,
    expires_at,
    max_uses,
    uses,
    revoked
  }
}

export function registerIssuedInvite(db: DatabaseSync, invite: ServerInvite): void {
  if (!HEX_32_PATTERN.test(invite.inviteId) || !HEX_64_PATTERN.test(invite.inviteSecret)) {
    throw new ServerDatabaseError('SERVER_INVITE_INVALID')
  }

  const secretHash = hashInviteSecret(invite.inviteSecret)

  try {
    db.prepare(`
      INSERT INTO invites (invite_id, invite_secret_hash, expires_at, max_uses, uses, revoked)
      VALUES (?, ?, ?, ?, 0, 0);
    `).run(invite.inviteId, secretHash, invite.expiresAt, invite.maxUses)
  } catch (error) {
    throw databaseWriteError(error, 'SERVER_INVITE_STATE_INVALID')
  }
}

export function consumeServerInvite(
  db: DatabaseSync,
  inviteOrEncoded: ServerInvite | string,
  serverPublicKeyDer: Buffer,
  options: { nowSeconds?: number } = {}
): void {
  const verifiedInvite =
    typeof inviteOrEncoded === 'string'
      ? decodeServerInvite(inviteOrEncoded)
      : inviteOrEncoded

  verifyServerInvite(verifiedInvite, serverPublicKeyDer, options)

  const inviteRow = db
    .prepare('SELECT invite_id, invite_secret_hash, expires_at, max_uses, uses, revoked FROM invites WHERE invite_id = ?;')
    .get(verifiedInvite.inviteId)

  if (!inviteRow) {
    throw new ServerDatabaseError('SERVER_INVITE_NOT_FOUND')
  }

  const stored = parseAndValidateStoredInviteRow(inviteRow)

  if (
    stored.expires_at !== verifiedInvite.expiresAt ||
    stored.max_uses !== verifiedInvite.maxUses
  ) {
    throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
  }

  const computedHash = hashInviteSecret(verifiedInvite.inviteSecret)
  const storedHashBuffer = Buffer.from(stored.invite_secret_hash)

  if (!timingSafeEqual(computedHash, storedHashBuffer)) {
    throw new ServerDatabaseError('SERVER_INVITE_INVALID')
  }

  if (stored.revoked === 1) {
    throw new ServerDatabaseError('SERVER_INVITE_REVOKED')
  }

  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000)
  if (nowSeconds > stored.expires_at) {
    throw new ServerDatabaseError('SERVER_INVITE_EXPIRED')
  }

  if (stored.uses >= stored.max_uses) {
    throw new ServerDatabaseError('SERVER_INVITE_EXHAUSTED')
  }

  let updateResult: { changes?: number | bigint }
  try {
    updateResult = db.prepare(`
      UPDATE invites
      SET uses = uses + 1
      WHERE invite_id = ? AND revoked = 0 AND uses < max_uses;
    `).run(verifiedInvite.inviteId)
  } catch (error) {
    throw databaseWriteError(error, 'SERVER_INVITE_STATE_INVALID')
  }

  if (updateResult.changes !== 1) {
    const refreshed = db
      .prepare('SELECT revoked, uses, max_uses FROM invites WHERE invite_id = ?;')
      .get(verifiedInvite.inviteId) as { revoked?: number; uses?: number; max_uses?: number } | undefined

    if (refreshed?.revoked === 1) {
      throw new ServerDatabaseError('SERVER_INVITE_REVOKED')
    }

    throw new ServerDatabaseError('SERVER_INVITE_EXHAUSTED')
  }
}

export function admitMemberWithInvite(
  db: DatabaseSync,
  inviteOrEncoded: ServerInvite | string,
  candidateDevice: AuthenticatedCandidateDevice,
  serverId: string,
  serverPublicKeyDer: Buffer,
  serverPrivateKey: KeyObject,
  options: { nowSeconds?: number } = {}
): Member {
  const validatedCandidateKey = validateCandidateDevice(candidateDevice)

  const verifiedInvite =
    typeof inviteOrEncoded === 'string'
      ? decodeServerInvite(inviteOrEncoded)
      : inviteOrEncoded

  verifyServerInvite(verifiedInvite, serverPublicKeyDer, options)

  // Cria o Member Certificate assinado antes ou dentro da transação atômica
  const memberCert = createMemberCertificate(
    serverId,
    serverPrivateKey,
    candidateDevice.fingerprint,
    validatedCandidateKey,
    verifiedInvite.inviteId
  )

  db.exec('BEGIN IMMEDIATE;')

  try {
    const existingMemberRow = db
      .prepare('SELECT device_fingerprint, device_public_key FROM members WHERE device_fingerprint = ?;')
      .get(candidateDevice.fingerprint)

    if (existingMemberRow) {
      throw new ServerDatabaseError('SERVER_MEMBER_ALREADY_EXISTS')
    }

    const inviteRow = db
      .prepare('SELECT invite_id, invite_secret_hash, expires_at, max_uses, uses, revoked FROM invites WHERE invite_id = ?;')
      .get(verifiedInvite.inviteId)

    if (!inviteRow) {
      throw new ServerDatabaseError('SERVER_INVITE_NOT_FOUND')
    }

    const stored = parseAndValidateStoredInviteRow(inviteRow)

    if (
      stored.expires_at !== verifiedInvite.expiresAt ||
      stored.max_uses !== verifiedInvite.maxUses
    ) {
      throw new ServerDatabaseError('SERVER_INVITE_STATE_INVALID')
    }

    const computedHash = hashInviteSecret(verifiedInvite.inviteSecret)
    const storedHashBuffer = Buffer.from(stored.invite_secret_hash)

    if (!timingSafeEqual(computedHash, storedHashBuffer)) {
      throw new ServerDatabaseError('SERVER_INVITE_INVALID')
    }

    if (stored.revoked === 1) {
      throw new ServerDatabaseError('SERVER_INVITE_REVOKED')
    }

    const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000)
    if (nowSeconds > stored.expires_at) {
      throw new ServerDatabaseError('SERVER_INVITE_EXPIRED')
    }

    if (stored.uses >= stored.max_uses) {
      throw new ServerDatabaseError('SERVER_INVITE_EXHAUSTED')
    }

    const updateResult = db.prepare(`
      UPDATE invites
      SET uses = uses + 1
      WHERE invite_id = ? AND revoked = 0 AND uses < max_uses;
    `).run(verifiedInvite.inviteId) as { changes?: number }

    if (updateResult.changes !== 1) {
      const refreshed = db
        .prepare('SELECT revoked, uses, max_uses FROM invites WHERE invite_id = ?;')
        .get(verifiedInvite.inviteId) as { revoked?: number; uses?: number; max_uses?: number } | undefined

      if (refreshed?.revoked === 1) {
        throw new ServerDatabaseError('SERVER_INVITE_REVOKED')
      }

      throw new ServerDatabaseError('SERVER_INVITE_EXHAUSTED')
    }

    db.prepare(`
      INSERT INTO members (device_fingerprint, device_public_key)
      VALUES (?, ?);
    `).run(candidateDevice.fingerprint, validatedCandidateKey)

    db.prepare(`
      INSERT INTO member_certificates (device_fingerprint, certificate_version, admission_invite_id, signature)
      VALUES (?, ?, ?, ?);
    `).run(
      candidateDevice.fingerprint,
      memberCert.version,
      memberCert.admissionInviteId,
      memberCert.signature
    )

    db.exec('COMMIT;')

    return Object.freeze({
      deviceFingerprint: candidateDevice.fingerprint,
      get publicKey(): Buffer {
        return Buffer.from(validatedCandidateKey)
      }
    })
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora erro no rollback
    }

    throw databaseWriteError(error, 'SERVER_ADMISSION_FAILED')
  }
}

export function revokeServerInvite(db: DatabaseSync, inviteId: string): void {
  if (typeof inviteId !== 'string' || !HEX_32_PATTERN.test(inviteId)) {
    throw new ServerDatabaseError('SERVER_INVITE_INVALID')
  }

  let result: { changes?: number | bigint }
  try {
    result = db.prepare(`
      UPDATE invites
      SET revoked = 1
      WHERE invite_id = ?;
    `).run(inviteId)
  } catch (error) {
    throw databaseWriteError(error, 'SERVER_INVITE_STATE_INVALID')
  }

  if (result.changes !== 1) {
    throw new ServerDatabaseError('SERVER_INVITE_NOT_FOUND')
  }
}

export function getStoredInvite(
  db: DatabaseSync,
  inviteId: string,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): StoredInvite | undefined {
  if (typeof inviteId !== 'string' || !HEX_32_PATTERN.test(inviteId)) {
    return undefined
  }

  const row = db
    .prepare('SELECT invite_id, invite_secret_hash, expires_at, max_uses, uses, revoked FROM invites WHERE invite_id = ?;')
    .get(inviteId)

  if (!row) {
    return undefined
  }

  const stored = parseAndValidateStoredInviteRow(row)
  let status: StoredInvite['status'] = 'available'

  if (stored.revoked === 1) {
    status = 'revoked'
  } else if (nowSeconds > stored.expires_at) {
    status = 'expired'
  } else if (stored.uses >= stored.max_uses) {
    status = 'exhausted'
  }

  return Object.freeze({
    inviteId: stored.invite_id,
    expiresAt: stored.expires_at,
    maxUses: stored.max_uses,
    uses: stored.uses,
    revoked: stored.revoked === 1,
    status
  })
}

export function hashInviteSecret(secret: string): Buffer {
  return createHash('sha256').update(secret, 'utf8').digest()
}

export function getMemberByFingerprint(
  db: DatabaseSync,
  fingerprint: string
): Member | undefined {
  if (typeof fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(fingerprint)) {
    return undefined
  }

  const row = db
    .prepare('SELECT device_fingerprint, device_public_key FROM members WHERE device_fingerprint = ?;')
    .get(fingerprint)

  if (!row) {
    return undefined
  }

  return parseAndValidateMemberRow(row)
}

export interface VerifiedMemberAuthorization {
  readonly isAuthorized: boolean
  readonly isOwner: boolean
  readonly member?: Member
  readonly certificate?: MemberCertificate
}

/**
 * Primitiva central de autorização de membro persistido.
 * Valida a cadeia criptográfica completa antes de conceder autoridade:
 * - Owner: validado pela correspondência exata com o Initial Owner Binding (owner.json).
 * - Non-owner: validado pela assinatura Ed25519 do Member Certificate correspondente.
 */
export function verifyPersistedMemberAuthorization(
  db: DatabaseSync,
  serverId: string,
  serverPublicKeyDer: Buffer,
  expectedOwner: ExpectedOwner,
  targetFingerprint: string
): VerifiedMemberAuthorization {
  if (typeof targetFingerprint !== 'string' || !FINGERPRINT_PATTERN.test(targetFingerprint)) {
    return { isAuthorized: false, isOwner: false }
  }

  const memberRow = db
    .prepare('SELECT device_fingerprint, device_public_key FROM members WHERE device_fingerprint = ?;')
    .get(targetFingerprint)

  if (!memberRow) {
    return { isAuthorized: false, isOwner: false }
  }

  const member = parseAndValidateMemberRow(memberRow)

  // 1. Caso Owner
  if (targetFingerprint === expectedOwner.deviceFingerprint) {
    if (!member.publicKey.equals(expectedOwner.publicKey)) {
      return { isAuthorized: false, isOwner: true }
    }

    // Owner não pode ter linha em member_certificates
    const certRow = db
      .prepare('SELECT device_fingerprint FROM member_certificates WHERE device_fingerprint = ?;')
      .get(targetFingerprint)

    if (certRow) {
      return { isAuthorized: false, isOwner: true }
    }

    return { isAuthorized: true, isOwner: true, member }
  }

  // 2. Caso Non-Owner
  const certRow = db
    .prepare('SELECT device_fingerprint, certificate_version, admission_invite_id, signature FROM member_certificates WHERE device_fingerprint = ?;')
    .get(targetFingerprint)

  if (!certRow) {
    return { isAuthorized: false, isOwner: false }
  }

  const parsedCertRow = parseAndValidateStoredMemberCertificateRow(certRow)
  const cert: MemberCertificate = {
    version: 1,
    type: 'member-certificate',
    serverId,
    memberDeviceFingerprint: targetFingerprint,
    memberDevicePublicKey: member.publicKey,
    admissionInviteId: parsedCertRow.admission_invite_id,
    signature: Buffer.from(parsedCertRow.signature)
  }

  try {
    verifyMemberCertificate(cert, serverId, serverPublicKeyDer)
    return { isAuthorized: true, isOwner: false, member, certificate: cert }
  } catch {
    return { isAuthorized: false, isOwner: false }
  }
}

export function listMembers(
  db: DatabaseSync,
  limit: number = 100
): Member[] {
  const boundedLimit = Math.min(Math.max(1, limit), MAX_MEMBERS_LIST_LIMIT)
  const rows = db
    .prepare('SELECT device_fingerprint, device_public_key FROM members ORDER BY device_fingerprint ASC LIMIT ?;')
    .all(boundedLimit)

  return rows.map((row) => parseAndValidateMemberRow(row))
}

function validateCandidateDevice(candidate: AuthenticatedCandidateDevice): Buffer {
  if (!isAuthenticatedCandidateDevice(candidate)) {
    throw new ServerDatabaseError('SERVER_ADMISSION_INVALID_CANDIDATE')
  }

  if (
    typeof candidate.fingerprint !== 'string' ||
    !FINGERPRINT_PATTERN.test(candidate.fingerprint)
  ) {
    throw new ServerDatabaseError('SERVER_ADMISSION_INVALID_CANDIDATE')
  }

  if (
    !(candidate.publicKey instanceof Uint8Array) ||
    candidate.publicKey.length === 0 ||
    candidate.publicKey.length > MAX_PUBLIC_KEY_BYTES
  ) {
    throw new ServerDatabaseError('SERVER_ADMISSION_INVALID_CANDIDATE')
  }

  return validatePublicKeyDer(
    Buffer.from(candidate.publicKey),
    candidate.fingerprint,
    'SERVER_ADMISSION_INVALID_CANDIDATE'
  )
}

function validatePublicKeyDer(
  publicKeyBytes: Buffer,
  expectedFingerprint: string,
  errorCode: ServerDatabaseErrorCode
): Buffer {
  let keyObject: KeyObject

  try {
    keyObject = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' })
  } catch {
    throw new ServerDatabaseError(errorCode)
  }

  if (keyObject.type !== 'public' || keyObject.asymmetricKeyType !== 'ed25519') {
    throw new ServerDatabaseError(errorCode)
  }

  const canonicalDer = Buffer.from(keyObject.export({ format: 'der', type: 'spki' }))

  if (!canonicalDer.equals(publicKeyBytes)) {
    throw new ServerDatabaseError(errorCode)
  }

  const calculatedFingerprint = `sha256:${createHash('sha256').update(canonicalDer).digest('hex')}`

  if (calculatedFingerprint !== expectedFingerprint) {
    throw new ServerDatabaseError(errorCode)
  }

  return canonicalDer
}

function databaseWriteError(error: unknown, fallback: ServerDatabaseErrorCode): ServerDatabaseError {
  if (error instanceof ServerDatabaseError) return error
  // node:sqlite reports SQLITE_FULL with numeric errcode 13.
  if (isRecord(error) && error.errcode === 13) {
    return new ServerDatabaseError('SERVER_DATABASE_TOO_LARGE')
  }
  return new ServerDatabaseError(fallback)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
