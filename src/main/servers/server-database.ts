import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  type KeyObject
} from 'node:crypto'
import { open, stat } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
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
export const DATABASE_SCHEMA_VERSION = 6
export const MAX_INITIAL_SERVER_DATABASE_BYTES = 1024 * 1024 // 1 MB
export const MIN_SERVER_DATABASE_BYTES = 512
export const MAX_MEMBERS_LIST_LIMIT = 1000
export const MAX_CHANNELS_PER_SERVER = 128
export const MAX_CHANNEL_NAME_CODE_POINTS = 100
export const MAX_MESSAGES_PER_CHANNEL = 2000
export const MAX_MESSAGE_CONTENT_CODE_POINTS = 4096
export const MAX_MESSAGE_LIST_LIMIT = 500
export const DEFAULT_MESSAGE_LIST_LIMIT = 100
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
  | 'SERVER_CHANNEL_INVALID'
  | 'SERVER_CHANNEL_NOT_FOUND'
  | 'SERVER_CHANNEL_ALREADY_EXISTS'
  | 'SERVER_CHANNEL_LIMIT_REACHED'
  | 'SERVER_CHANNEL_UNAUTHORIZED'
  | 'SERVER_CHANNEL_ARCHIVED'
  | 'SERVER_MESSAGE_INVALID'
  | 'SERVER_MESSAGE_NOT_FOUND'
  | 'SERVER_MESSAGE_FORBIDDEN'
  | 'SERVER_MESSAGE_CAPACITY_REACHED'
  | 'SERVER_MESSAGE_DUPLICATE'
  | 'SERVER_MESSAGE_DUPLICATE'

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
  SERVER_ADMISSION_FAILED: 'Não foi possível admitir o novo membro no servidor com segurança.',
  SERVER_CHANNEL_INVALID: 'O canal solicitado é inválido.',
  SERVER_CHANNEL_NOT_FOUND: 'O canal do servidor não foi encontrado.',
  SERVER_CHANNEL_ALREADY_EXISTS: 'Já existe um canal com esse nome no servidor.',
  SERVER_CHANNEL_LIMIT_REACHED: 'O servidor atingiu o número máximo de canais.',
  SERVER_CHANNEL_UNAUTHORIZED: 'Apenas o owner pode gerenciar canais do servidor.',
  SERVER_CHANNEL_ARCHIVED: 'O canal está arquivado e não aceita novas mensagens.',
  SERVER_MESSAGE_INVALID: 'A mensagem solicitada é inválida.',
  SERVER_MESSAGE_NOT_FOUND: 'A mensagem do servidor não foi encontrada.',
  SERVER_MESSAGE_FORBIDDEN: 'A operação de mensagem não é permitida para este membro.',
  SERVER_MESSAGE_CAPACITY_REACHED: 'O canal atingiu o número máximo de mensagens vivas.',
  SERVER_MESSAGE_DUPLICATE: 'A mensagem duplicada já foi registrada para este canal.'
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

      CREATE TABLE channels (
        channel_id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        created_by TEXT NOT NULL
          REFERENCES members(device_fingerprint)
          ON DELETE RESTRICT,
        archived INTEGER NOT NULL CHECK (archived IN (0, 1))
      );

      CREATE TABLE messages (
        channel_id TEXT NOT NULL
          REFERENCES channels(channel_id)
          ON DELETE RESTRICT,
        sequence INTEGER NOT NULL,
        message_id TEXT PRIMARY KEY,
        client_message_id TEXT NOT NULL UNIQUE,
        author_fingerprint TEXT NOT NULL
          REFERENCES members(device_fingerprint)
          ON DELETE RESTRICT,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        edited_at INTEGER,
        deleted_at INTEGER,
        CHECK (sequence >= 1),
        CHECK (created_at >= 0),
        CHECK (deleted_at IS NULL OR deleted_at >= created_at),
        CHECK (edited_at IS NULL OR edited_at >= created_at),
        UNIQUE (channel_id, sequence)
      );

      CREATE INDEX messages_channel_sequence ON messages(channel_id, sequence);
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

  // Migração atômica de versões legadas (v3/v4/v5) até v6. Commit somente após a
  // validação completa do banco final; qualquer falha preserva os bytes originais.
  if (version === 3 || version === 4 || version === 5) {
    if (version === 3 && !expectedOwner) {
      throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
    }

    db.exec('BEGIN IMMEDIATE;')
    try {
      if (version === 3) {
        const v3Members = db.prepare('SELECT device_fingerprint, device_public_key FROM members;').all()
        if (v3Members.length !== 1) {
          throw new ServerDatabaseError('SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION')
        }

        const ownerMember = parseAndValidateMemberRow(v3Members[0])
        if (
          ownerMember.deviceFingerprint !== expectedOwner!.deviceFingerprint ||
          !ownerMember.publicKey.equals(expectedOwner!.publicKey)
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
      }

      if (version === 3 || version === 4) {
        db.exec(`
          CREATE TABLE channels (
            channel_id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            created_by TEXT NOT NULL
              REFERENCES members(device_fingerprint)
              ON DELETE RESTRICT,
            archived INTEGER NOT NULL CHECK (archived IN (0, 1))
          );
        `)
      }

      db.exec(`
        CREATE TABLE messages (
          channel_id TEXT NOT NULL
            REFERENCES channels(channel_id)
            ON DELETE RESTRICT,
          sequence INTEGER NOT NULL,
          message_id TEXT PRIMARY KEY,
          client_message_id TEXT NOT NULL UNIQUE,
          author_fingerprint TEXT NOT NULL
            REFERENCES members(device_fingerprint)
            ON DELETE RESTRICT,
          content TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          edited_at INTEGER,
          deleted_at INTEGER,
          CHECK (sequence >= 1),
          CHECK (created_at >= 0),
          CHECK (deleted_at IS NULL OR deleted_at >= created_at),
          CHECK (edited_at IS NULL OR edited_at >= created_at),
          UNIQUE (channel_id, sequence)
        );

        CREATE INDEX messages_channel_sequence ON messages(channel_id, sequence);
      `)
      db.exec(`PRAGMA user_version = ${DATABASE_SCHEMA_VERSION};`)
      // Validate the complete final schema and data before making the migration durable.
      validateDatabaseIntegrityAndSchema(db, expectedOwner, serverContext)
      db.exec('COMMIT;')
      return
    } catch (error) {
      try {
        db.exec('ROLLBACK;')
      } catch {
        // Ignora
      }
      // Preserve the original semantic code (e.g. invite validation) so callers and
      // tests can distinguish failure causes; the database keeps its original bytes.
      if (error instanceof ServerDatabaseError) throw error
      throw databaseWriteError(error, 'SERVER_DATABASE_SCHEMA_INVALID')
    }
  } else if (version !== DATABASE_SCHEMA_VERSION) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  // Allowlist estrita de schema v6: exatamente 5 tabelas (channels, invites, member_certificates, members, messages)
  // e exatamente 1 índice (messages_channel_sequence). Objetos sqlite_* continuam excluídos.
  const schemaObjects = db
    .prepare("SELECT type, name, tbl_name FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name ASC;")
    .all() as Array<{ type?: unknown; name?: unknown; tbl_name?: unknown }>

  const tables = schemaObjects.filter((object) => object.type === 'table')
  const indexes = schemaObjects.filter((object) => object.type === 'index')

  const isTable = (object: { type?: unknown; name?: unknown; tbl_name?: unknown } | undefined, name: string): boolean =>
    object?.name === name && object?.tbl_name === name

  if (
    tables.length !== 5 ||
    !isTable(tables[0], 'channels') ||
    !isTable(tables[1], 'invites') ||
    !isTable(tables[2], 'member_certificates') ||
    !isTable(tables[3], 'members') ||
    !isTable(tables[4], 'messages') ||
    indexes.length !== 1 ||
    indexes[0]?.name !== 'messages_channel_sequence' ||
    indexes[0]?.tbl_name !== 'messages' ||
    schemaObjects.length !== tables.length + indexes.length ||
    schemaObjects.some((object) => object.type !== 'table' && object.type !== 'index')
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

  // Valida todos os registros presentes na tabela channels
  const allChannels = db
    .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels ORDER BY name ASC;')
    .all()

  for (const row of allChannels) {
    parseAndValidateChannelRow(row, memberMap)
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

// ---------------------------------------------------------------------------
// Channels (ETAPA 8.2)
// ---------------------------------------------------------------------------

export interface ServerChannel {
  readonly channelId: string
  readonly name: string
  readonly createdAt: number
  readonly createdBy: string
  readonly archived: boolean
}

interface RawStoredChannelRow {
  readonly channel_id: string
  readonly name: string
  readonly created_at: number
  readonly created_by: string
  readonly archived: number
}

function parseAndValidateChannelRow(row: unknown, memberMap?: Map<string, Member>): ServerChannel {
  if (!isRecord(row)) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  const { channel_id, name, created_at, created_by, archived } = row as Record<string, unknown>

  if (
    typeof channel_id !== 'string' || !HEX_32_PATTERN.test(channel_id) ||
    typeof name !== 'string' ||
    typeof created_at !== 'number' || !Number.isInteger(created_at) ||
    created_at < 0 || created_at > 4_102_444_800 ||
    typeof created_by !== 'string' || !FINGERPRINT_PATTERN.test(created_by) ||
    typeof archived !== 'number' || (archived !== 0 && archived !== 1)
  ) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  assertValidChannelName(name)

  if (memberMap && !memberMap.has(created_by)) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  return Object.freeze({
    channelId: channel_id,
    name,
    createdAt: created_at,
    createdBy: created_by,
    archived: archived === 1
  })
}

export function assertValidChannelName(name: string): void {
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    name.trim().length === 0 ||
    [...name].length > MAX_CHANNEL_NAME_CODE_POINTS ||
    name.normalize('NFC') !== name
  ) {
    throw new ServerDatabaseError('SERVER_CHANNEL_INVALID')
  }

  for (let index = 0; index < name.length; index++) {
    const unit = name.charCodeAt(index)
    if (unit <= 0x1f || (unit >= 0x7f && unit <= 0x9f)) {
      throw new ServerDatabaseError('SERVER_CHANNEL_INVALID')
    }
  }
}

export function listChannels(db: DatabaseSync, limit: number = MAX_CHANNELS_PER_SERVER): ServerChannel[] {
  const boundedLimit = Math.min(Math.max(1, limit), MAX_CHANNELS_PER_SERVER)
  const rows = db
    .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels ORDER BY name COLLATE BINARY ASC, channel_id ASC LIMIT ?;')
    .all(boundedLimit) as unknown as RawStoredChannelRow[]

  return rows.map((row) => parseAndValidateChannelRow(row))
}

export function getChannelByName(db: DatabaseSync, name: string): ServerChannel | undefined {
  assertValidChannelName(name)
  const row = db
    .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels WHERE name = ?;')
    .get(name)

  return row === undefined ? undefined : parseAndValidateChannelRow(row)
}

export function createChannel(
  db: DatabaseSync,
  options: {
    readonly name: string
    readonly actorFingerprint: string
    readonly isOwner: boolean
    readonly channelId?: string
    readonly nowSeconds?: number
  }
): ServerChannel {
  assertValidChannelName(options.name)
  if (!FINGERPRINT_PATTERN.test(options.actorFingerprint) || !options.isOwner) {
    throw new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED')
  }

  const channelId = options.channelId ?? randomUUID().replaceAll('-', '')
  if (!HEX_32_PATTERN.test(channelId)) {
    throw new ServerDatabaseError('SERVER_CHANNEL_INVALID')
  }
  const createdAt = options.nowSeconds ?? Math.floor(Date.now() / 1000)

  db.exec('BEGIN IMMEDIATE;')
  try {
    const total = db.prepare('SELECT COUNT(*) AS count FROM channels;').get() as { count: number }
    if (total.count >= MAX_CHANNELS_PER_SERVER) {
      throw new ServerDatabaseError('SERVER_CHANNEL_LIMIT_REACHED')
    }

    if (getChannelByName(db, options.name)) {
      throw new ServerDatabaseError('SERVER_CHANNEL_ALREADY_EXISTS')
    }

    db.prepare(`
      INSERT INTO channels (channel_id, name, created_at, created_by, archived)
      VALUES (?, ?, ?, ?, 0);
    `).run(channelId, options.name, createdAt, options.actorFingerprint)

    const row = db
      .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels WHERE channel_id = ?;')
      .get(channelId)
    if (!row) {
      throw new ServerDatabaseError('SERVER_CHANNEL_INVALID')
    }
    const channel = parseAndValidateChannelRow(row)
    db.exec('COMMIT;')
    return channel
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    if (error instanceof ServerDatabaseError) throw error
    // UNIQUE constraint backstop for concurrent same-name inserts.
    if (isSqliteConstraintError(error)) {
      throw new ServerDatabaseError('SERVER_CHANNEL_ALREADY_EXISTS')
    }
    throw databaseWriteError(error, 'SERVER_CHANNEL_INVALID')
  }
}

export function renameChannel(
  db: DatabaseSync,
  options: {
    readonly channelId: string
    readonly name: string
    readonly actorFingerprint: string
    readonly isOwner: boolean
  }
): ServerChannel {
  assertValidChannelName(options.name)
  if (!HEX_32_PATTERN.test(options.channelId) || !options.isOwner) {
    throw new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED')
  }

  db.exec('BEGIN IMMEDIATE;')
  try {
    const result = db
      .prepare('UPDATE channels SET name = ? WHERE channel_id = ?;')
      .run(options.name, options.channelId) as { changes?: number | bigint }
    if (result.changes !== 1) {
      throw new ServerDatabaseError('SERVER_CHANNEL_NOT_FOUND')
    }
    const row = db
      .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels WHERE channel_id = ?;')
      .get(options.channelId)
    if (!row) {
      throw new ServerDatabaseError('SERVER_CHANNEL_NOT_FOUND')
    }
    const channel = parseAndValidateChannelRow(row)
    db.exec('COMMIT;')
    return channel
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    throw databaseWriteError(error, 'SERVER_CHANNEL_INVALID')
  }
}

export function setChannelArchived(
  db: DatabaseSync,
  options: {
    readonly channelId: string
    readonly archived: boolean
    readonly actorFingerprint: string
    readonly isOwner: boolean
  }
): ServerChannel {
  if (!HEX_32_PATTERN.test(options.channelId) || !options.isOwner) {
    throw new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED')
  }

  db.exec('BEGIN IMMEDIATE;')
  try {
    const result = db
      .prepare('UPDATE channels SET archived = ? WHERE channel_id = ?;')
      .run(options.archived ? 1 : 0, options.channelId) as { changes?: number | bigint }
    if (result.changes !== 1) {
      throw new ServerDatabaseError('SERVER_CHANNEL_NOT_FOUND')
    }
    const row = db
      .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels WHERE channel_id = ?;')
      .get(options.channelId)
    if (!row) {
      throw new ServerDatabaseError('SERVER_CHANNEL_NOT_FOUND')
    }
    const channel = parseAndValidateChannelRow(row)
    db.exec('COMMIT;')
    return channel
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    throw databaseWriteError(error, 'SERVER_CHANNEL_INVALID')
  }
}

export function deleteChannel(
  db: DatabaseSync,
  options: {
    readonly channelId: string
    readonly actorFingerprint: string
    readonly isOwner: boolean
  }
): void {
  if (!HEX_32_PATTERN.test(options.channelId) || !options.isOwner) {
    throw new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED')
  }

  db.exec('BEGIN IMMEDIATE;')
  try {
    const result = db
      .prepare('DELETE FROM channels WHERE channel_id = ?;')
      .run(options.channelId) as { changes?: number | bigint }
    if (result.changes !== 1) {
      throw new ServerDatabaseError('SERVER_CHANNEL_NOT_FOUND')
    }
    db.exec('COMMIT;')
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    if (error instanceof ServerDatabaseError) throw error
    if (isRecord(error) && error.errcode === 19) {
      // Messages reference the channel with ON DELETE RESTRICT.
      throw new ServerDatabaseError('SERVER_DATABASE_INITIALIZATION_FAILED')
    }
    throw databaseWriteError(error, 'SERVER_CHANNEL_INVALID')
  }
}

// ---------------------------------------------------------------------------
// Messages (ETAPA 8.3)
// ---------------------------------------------------------------------------

export interface ServerMessage {
  readonly channelId: string
  readonly sequence: number
  readonly messageId: string
  readonly clientMessageId: string
  readonly authorFingerprint: string
  readonly content: string
  readonly createdAt: number
  readonly editedAt: number | null
  readonly deletedAt: number | null
}

export interface MessageOperationAuthorization {
  readonly actorFingerprint: string
  readonly isOwner: boolean
}

export function createMessageOperationAuthorization(options: {
  readonly actorFingerprint: string
  readonly isAuthorized: boolean
  readonly isOwner: boolean
}): MessageOperationAuthorization {
  if (
    typeof options.actorFingerprint !== 'string' ||
    !FINGERPRINT_PATTERN.test(options.actorFingerprint) ||
    !options.isAuthorized
  ) {
    throw new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN')
  }

  return Object.freeze({
    actorFingerprint: options.actorFingerprint,
    isOwner: options.isOwner === true
  })
}

interface RawStoredMessageRow {
  readonly channel_id: string
  readonly sequence: number
  readonly message_id: string
  readonly client_message_id: string
  readonly author_fingerprint: string
  readonly content: string
  readonly created_at: number
  readonly edited_at: number | null
  readonly deleted_at: number | null
}

const MESSAGE_COLUMNS = 'channel_id, sequence, message_id, client_message_id, author_fingerprint, content, created_at, edited_at, deleted_at'

function listMemberMap(db: DatabaseSync): Map<string, Member> {
  const memberMap = new Map<string, Member>()
  for (const row of db.prepare('SELECT device_fingerprint, device_public_key FROM members;').all()) {
    const member = parseAndValidateMemberRow(row)
    memberMap.set(member.deviceFingerprint, member)
  }
  return memberMap
}

function parseAndValidateMessageRow(row: unknown, memberMap: Map<string, Member>): ServerMessage {
  if (!isRecord(row)) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  const {
    channel_id, sequence, message_id, client_message_id, author_fingerprint,
    content, created_at, edited_at, deleted_at
  } = row as Record<string, unknown>

  if (
    typeof channel_id !== 'string' || !HEX_32_PATTERN.test(channel_id) ||
    typeof sequence !== 'number' || !Number.isSafeInteger(sequence) || sequence < 1 ||
    typeof message_id !== 'string' || !HEX_32_PATTERN.test(message_id) ||
    typeof client_message_id !== 'string' || !HEX_32_PATTERN.test(client_message_id) ||
    typeof author_fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(author_fingerprint) ||
    typeof content !== 'string' ||
    typeof created_at !== 'number' || !Number.isInteger(created_at) || created_at < 0 ||
    (edited_at !== null && (typeof edited_at !== 'number' || !Number.isInteger(edited_at) || edited_at < created_at)) ||
    (deleted_at !== null && (typeof deleted_at !== 'number' || !Number.isInteger(deleted_at) || deleted_at < created_at))
  ) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  if (content.length > MAX_MESSAGE_CONTENT_CODE_POINTS || !memberMap.has(author_fingerprint)) {
    throw new ServerDatabaseError('SERVER_DATABASE_SCHEMA_INVALID')
  }

  return Object.freeze({
    channelId: channel_id,
    sequence,
    messageId: message_id,
    clientMessageId: client_message_id,
    authorFingerprint: author_fingerprint,
    content,
    createdAt: created_at,
    editedAt: typeof edited_at === 'number' ? edited_at : null,
    deletedAt: typeof deleted_at === 'number' ? deleted_at : null
  })
}

function getChannelForMessageOperation(db: DatabaseSync, channelId: string, options: { readonly requireActive: boolean } = { requireActive: false }): void {
  if (!HEX_32_PATTERN.test(channelId)) {
    throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
  }

  const row = db
    .prepare('SELECT channel_id, name, created_at, created_by, archived FROM channels WHERE channel_id = ?;')
    .get(channelId)

  if (!row) {
    throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
  }

  const channel = parseAndValidateChannelRow(row)
  if (options.requireActive && channel.archived) {
    throw new ServerDatabaseError('SERVER_CHANNEL_ARCHIVED')
  }
}

function assertValidMessageContent(content: string): void {
  if (
    typeof content !== 'string' ||
    content.length === 0 ||
    [...content].length > MAX_MESSAGE_CONTENT_CODE_POINTS ||
    content.normalize('NFC') !== content
  ) {
    throw new ServerDatabaseError('SERVER_MESSAGE_INVALID')
  }
  for (let index = 0; index < content.length; index++) {
    const unit = content.charCodeAt(index)
    if (unit <= 0x1f || (unit >= 0x7f && unit <= 0x9f)) {
      throw new ServerDatabaseError('SERVER_MESSAGE_INVALID')
    }
  }
}

export function createMessage(
  db: DatabaseSync,
  options: {
    readonly channelId: string
    readonly content: string
    readonly clientMessageId: string
    readonly authorization: MessageOperationAuthorization
    readonly messageId?: string
    readonly nowSeconds?: number
  }
): ServerMessage {
  getChannelForMessageOperation(db, options.channelId, { requireActive: true })
  assertValidMessageContent(options.content)
  if (!HEX_32_PATTERN.test(options.clientMessageId)) {
    throw new ServerDatabaseError('SERVER_MESSAGE_INVALID')
  }

  const messageId = options.messageId ?? randomUUID().replaceAll('-', '')
  if (!HEX_32_PATTERN.test(messageId)) {
    throw new ServerDatabaseError('SERVER_MESSAGE_INVALID')
  }
  const createdAt = options.nowSeconds ?? Math.floor(Date.now() / 1000)

  db.exec('BEGIN IMMEDIATE;')
  try {
    const duplicate = db
      .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE channel_id = ? AND client_message_id = ?;`)
      .get(options.channelId, options.clientMessageId)

    if (duplicate) {
      throw new ServerDatabaseError('SERVER_MESSAGE_DUPLICATE')
    }

    const capacityRow = db
      .prepare('SELECT COUNT(*) AS count FROM messages WHERE channel_id = ? AND deleted_at IS NULL;')
      .get(options.channelId) as { count: number }
    if (capacityRow.count >= MAX_MESSAGES_PER_CHANNEL) {
      throw new ServerDatabaseError('SERVER_MESSAGE_CAPACITY_REACHED')
    }

    const nextSequenceRow = db
      .prepare('SELECT COALESCE(MAX(sequence), 0) + 1 AS next FROM messages WHERE channel_id = ?;')
      .get(options.channelId) as { next: number }
    const sequence = nextSequenceRow.next

    db.prepare(`
      INSERT INTO messages (channel_id, sequence, message_id, client_message_id, author_fingerprint, content, created_at, edited_at, deleted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL);
    `).run(
      options.channelId, sequence, messageId, options.clientMessageId,
      options.authorization.actorFingerprint, options.content, createdAt
    )

    const row = db
      .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE message_id = ?;`)
      .get(messageId)
    if (!row) {
      throw new ServerDatabaseError('SERVER_MESSAGE_INVALID')
    }
    const message = parseAndValidateMessageRow(row, listMemberMap(db))
    db.exec('COMMIT;')
    return message
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    if (error instanceof ServerDatabaseError) throw error
    if (isSqliteConstraintError(error)) {
      // Distinguish the two constraint violations that can reach this insert.
      if (typeof error.message === 'string' && error.message.includes('FOREIGN KEY')) {
        throw new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN')
      }
      throw new ServerDatabaseError('SERVER_MESSAGE_DUPLICATE')
    }
    throw databaseWriteError(error, 'SERVER_MESSAGE_INVALID')
  }
}

export function getMessageById(db: DatabaseSync, messageId: string): ServerMessage | undefined {
  if (!HEX_32_PATTERN.test(messageId)) {
    return undefined
  }

  const row = db
    .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE message_id = ?;`)
    .get(messageId)

  return row === undefined ? undefined : parseAndValidateMessageRow(row, listMemberMap(db))
}

export function editMessage(
  db: DatabaseSync,
  options: {
    readonly messageId: string
    readonly content: string
    readonly authorization: MessageOperationAuthorization
    readonly nowSeconds?: number
  }
): ServerMessage {
  assertValidMessageContent(options.content)
  const editedAt = options.nowSeconds ?? Math.floor(Date.now() / 1000)

  db.exec('BEGIN IMMEDIATE;')
  try {
    const existingRow = db
      .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE message_id = ?;`)
      .get(options.messageId)

    if (!existingRow) {
      throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
    }
    const existing = parseAndValidateMessageRow(existingRow, listMemberMap(db))
    if (existing.deletedAt !== null) {
      throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
    }
    if (existing.authorFingerprint !== options.authorization.actorFingerprint) {
      throw new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN')
    }

    db.prepare('UPDATE messages SET content = ?, edited_at = ? WHERE message_id = ?;')
      .run(options.content, editedAt, options.messageId)

    const row = db
      .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE message_id = ?;`)
      .get(options.messageId)
    if (!row) {
      throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
    }
    const message = parseAndValidateMessageRow(row, listMemberMap(db))
    db.exec('COMMIT;')
    return message
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    if (error instanceof ServerDatabaseError) throw error
    throw databaseWriteError(error, 'SERVER_MESSAGE_INVALID')
  }
}

export function deleteMessage(
  db: DatabaseSync,
  options: {
    readonly messageId: string
    readonly authorization: MessageOperationAuthorization
    readonly nowSeconds?: number
  }
): ServerMessage {
  const deletedAt = options.nowSeconds ?? Math.floor(Date.now() / 1000)

  db.exec('BEGIN IMMEDIATE;')
  try {
    const existingRow = db
      .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE message_id = ?;`)
      .get(options.messageId)

    if (!existingRow) {
      throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
    }
    const existing = parseAndValidateMessageRow(existingRow, listMemberMap(db))
    if (existing.deletedAt !== null) {
      throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
    }
    if (existing.authorFingerprint !== options.authorization.actorFingerprint && !options.authorization.isOwner) {
      throw new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN')
    }

    db.prepare('UPDATE messages SET content = \'\', deleted_at = ? WHERE message_id = ?;')
      .run(deletedAt, options.messageId)

    const row = db
      .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE message_id = ?;`)
      .get(options.messageId)
    if (!row) {
      throw new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND')
    }
    const message = parseAndValidateMessageRow(row, listMemberMap(db))
    db.exec('COMMIT;')
    return message
  } catch (error) {
    try {
      db.exec('ROLLBACK;')
    } catch {
      // Ignora
    }
    if (error instanceof ServerDatabaseError) throw error
    throw databaseWriteError(error, 'SERVER_MESSAGE_INVALID')
  }
}

export function listMessages(
  db: DatabaseSync,
  options: {
    readonly channelId: string
    readonly afterSequence?: number
    readonly limit?: number
  }
): ServerMessage[] {
  getChannelForMessageOperation(db, options.channelId)

  const boundedLimit = Math.min(
    Math.max(1, options.limit ?? DEFAULT_MESSAGE_LIST_LIMIT),
    MAX_MESSAGE_LIST_LIMIT
  )
  const after = options.afterSequence ?? 0
  if (!Number.isSafeInteger(after) || after < 0) {
    throw new ServerDatabaseError('SERVER_MESSAGE_INVALID')
  }

  const rows = db
    .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE channel_id = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?;`)
    .all(options.channelId, after, boundedLimit) as unknown as RawStoredMessageRow[]
  const memberMap = listMemberMap(db)

  return rows.map((row) => parseAndValidateMessageRow(row, memberMap))
}

function isSqliteConstraintError(error: unknown): error is Record<string, unknown> {
  // node:sqlite exposes extended result codes (e.g. 787 FK, 2067 UNIQUE) whose
  // primary code is always 19 (SQLITE_CONSTRAINT).
  return isRecord(error) && typeof error.errcode === 'number' && (error.errcode & 0xff) === 19
}

function databaseWriteError(error: unknown, fallback: ServerDatabaseErrorCode): ServerDatabaseError {
  if (error instanceof ServerDatabaseError) return error
  // node:sqlite reports SQLITE_FULL (13) possibly as an extended result code.
  if (isRecord(error) && typeof error.errcode === 'number' && (error.errcode & 0xff) === 13) {
    return new ServerDatabaseError('SERVER_DATABASE_TOO_LARGE')
  }
  return new ServerDatabaseError(fallback)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
