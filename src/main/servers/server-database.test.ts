import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync } from 'node:fs'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { afterEach, describe, expect, it } from 'vitest'

import {
  createAuthenticatedCandidateDevice,
  type AuthenticatedCandidateDevice
} from '../security/authenticated-candidate'
import {
  admitMemberWithInvite,
  createChannel,
  createMessage,
  createMessageOperationAuthorization,
  DATABASE_FILE_NAME,
  DATABASE_SCHEMA_VERSION,
  deleteChannel,
  deleteMessage,
  editMessage,
  getChannelByName,
  getMemberByFingerprint,
  getStoredInvite,
  initializeServerDatabase,
  listChannels,
  listMembers,
  listMessages,
  MAX_CHANNEL_NAME_CODE_POINTS,
  MAX_CHANNELS_PER_SERVER,
  MAX_INITIAL_SERVER_DATABASE_BYTES,
  MAX_MESSAGE_CONTENT_CODE_POINTS,
  MAX_MESSAGES_PER_CHANNEL,
  openServerDatabase,
  registerIssuedInvite,
  renameChannel,
  revokeServerInvite,
  ServerDatabaseError,
  setChannelArchived,
  validateServerDatabaseFile,
  verifyPersistedMemberAuthorization
} from './server-database'
import { createServerInvite } from './server-invite'

const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('fundação segura de SQLite, membership, invites, certificates e admissão', () => {
  it('inicializa novo banco SQLite com schema version 5, channels, invites, member_certificates e members', async () => {
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    const owner = createTestDeviceIdentity()

    initializeServerDatabase(dbPath, owner)
    await expect(
      validateServerDatabaseFile(dbPath, {
        deviceFingerprint: owner.fingerprint,
        publicKey: owner.publicKey
      })
    ).resolves.toBeUndefined()

    const db = openServerDatabase(dbPath, {
      deviceFingerprint: owner.fingerprint,
      publicKey: owner.publicKey
    })
    const version = db.prepare('PRAGMA user_version;').get() as { user_version: number }
    const foreignKeys = db.prepare('PRAGMA foreign_keys;').get() as { foreign_keys: number }
    const trustedSchema = db.prepare('PRAGMA trusted_schema;').get() as { trusted_schema: number }
    const schemaObjects = db
      .prepare("SELECT type, name, tbl_name FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name ASC;")
      .all()
    const members = listMembers(db)
    const certs = db.prepare('SELECT COUNT(*) as count FROM member_certificates;').get() as { count: number }
    db.close()

    expect(version.user_version).toBe(DATABASE_SCHEMA_VERSION)
    expect(foreignKeys.foreign_keys).toBe(1)
    expect(trustedSchema.trusted_schema).toBe(0)
    expect(schemaObjects).toEqual([
      { type: 'table', name: 'channels', tbl_name: 'channels' },
      { type: 'table', name: 'invites', tbl_name: 'invites' },
      { type: 'table', name: 'member_certificates', tbl_name: 'member_certificates' },
      { type: 'table', name: 'members', tbl_name: 'members' },
      { type: 'table', name: 'messages', tbl_name: 'messages' },
      { type: 'index', name: 'messages_channel_sequence', tbl_name: 'messages' }
    ])
    expect(members).toHaveLength(1)
    expect(members[0]?.deviceFingerprint).toBe(owner.fingerprint)
    expect(certs.count).toBe(0) // Owner tem zero certificados
  })

  it('admite novo membro com convite single-use atomicamente (admissão + certificate + consumo)', async () => {
    const fixture = createServerFixture()
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)

    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const candidateB = createTestDeviceIdentity()

    const db = openServerDatabase(dbPath)
    registerIssuedInvite(db, invite)

    const admittedMember = admitMemberWithInvite(
      db,
      invite,
      candidateB,
      fixture.serverId,
      fixture.serverPublicKey,
      fixture.serverPrivateKey
    )
    expect(admittedMember.deviceFingerprint).toBe(candidateB.fingerprint)
    expect(admittedMember.publicKey).toEqual(candidateB.publicKey)

    // Verifica que o membro está em members
    const lookedUp = getMemberByFingerprint(db, candidateB.fingerprint)
    expect(lookedUp?.deviceFingerprint).toBe(candidateB.fingerprint)
    expect(lookedUp?.publicKey).toEqual(candidateB.publicKey)

    // Verifica que o certificado correspondente foi inserido
    const certRow = db
      .prepare('SELECT device_fingerprint, certificate_version, admission_invite_id, signature FROM member_certificates WHERE device_fingerprint = ?;')
      .get(candidateB.fingerprint) as { device_fingerprint: string; certificate_version: number; admission_invite_id: string; signature: Uint8Array }

    expect(certRow).toBeDefined()
    expect(certRow.device_fingerprint).toBe(candidateB.fingerprint)
    expect(certRow.certificate_version).toBe(1)
    expect(certRow.admission_invite_id).toBe(invite.inviteId)
    expect(certRow.signature.length).toBe(64)

    // Verifica que o convite foi consumido
    const stored = getStoredInvite(db, invite.inviteId)
    expect(stored?.uses).toBe(1)
    expect(stored?.status).toBe('exhausted')

    // Valida autorização persistida
    const auth = verifyPersistedMemberAuthorization(
      db,
      fixture.serverId,
      fixture.serverPublicKey,
      {
        deviceFingerprint: fixture.ownerDevice.fingerprint,
        publicKey: fixture.ownerDevice.publicKey
      },
      candidateB.fingerprint
    )
    expect(auth.isAuthorized).toBe(true)
    expect(auth.isOwner).toBe(false)

    db.close()
  })

  it('rejeita tentativa de admissão com candidate device sem capability runtime autenticada', async () => {
    const fixture = createServerFixture()
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)

    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const keyPair = generateKeyPairSync('ed25519')
    const rawPublicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
    const fingerprint = `sha256:${createHash('sha256').update(rawPublicKey).digest('hex')}`

    const unauthenticatedLiteral = {
      fingerprint,
      publicKey: rawPublicKey
    } as unknown as AuthenticatedCandidateDevice

    const db = openServerDatabase(dbPath)
    registerIssuedInvite(db, invite)

    expect(() =>
      admitMemberWithInvite(
        db,
        invite,
        unauthenticatedLiteral,
        fixture.serverId,
        fixture.serverPublicKey,
        fixture.serverPrivateKey
      )
    ).toThrowError(expect.objectContaining({ code: 'SERVER_ADMISSION_INVALID_CANDIDATE' }))

    db.close()
  })

  it('admite múltiplos membros até maxUses em convite limited-use e bloqueia novos usos', async () => {
    const fixture = createServerFixture()
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)

    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 3
    })

    const candidateB = createTestDeviceIdentity()
    const candidateC = createTestDeviceIdentity()
    const candidateD = createTestDeviceIdentity()
    const candidateE = createTestDeviceIdentity()

    const db = openServerDatabase(dbPath)
    registerIssuedInvite(db, invite)

    expect(
      admitMemberWithInvite(db, invite, candidateB, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey).deviceFingerprint
    ).toBe(candidateB.fingerprint)
    expect(
      admitMemberWithInvite(db, invite, candidateC, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey).deviceFingerprint
    ).toBe(candidateC.fingerprint)
    expect(
      admitMemberWithInvite(db, invite, candidateD, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey).deviceFingerprint
    ).toBe(candidateD.fingerprint)

    // 4º membro deve falhar por convite esgotado
    expect(() =>
      admitMemberWithInvite(db, invite, candidateE, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)
    ).toThrowError(expect.objectContaining({ code: 'SERVER_INVITE_EXHAUSTED' }))

    // Verifica cardinalidade total: 4 members (owner + 3 admitidos) e 3 member_certificates
    const members = listMembers(db)
    expect(members).toHaveLength(4)
    const certCount = db.prepare('SELECT COUNT(*) as count FROM member_certificates;').get() as { count: number }
    expect(certCount.count).toBe(3)

    db.close()
  })

  it('impede duplicate admission: segundo uso do mesmo convite pelo mesmo membro falha com SERVER_MEMBER_ALREADY_EXISTS sem consumir uso', async () => {
    const fixture = createServerFixture()
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)

    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 2
    })

    const candidateB = createTestDeviceIdentity()

    const db = openServerDatabase(dbPath)
    registerIssuedInvite(db, invite)

    admitMemberWithInvite(db, invite, candidateB, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)

    expect(() =>
      admitMemberWithInvite(db, invite, candidateB, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)
    ).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBER_ALREADY_EXISTS' }))

    const stored = getStoredInvite(db, invite.inviteId)
    expect(stored?.uses).toBe(1)

    // O owner também é impedido de se auto-admitir com convite
    expect(() =>
      admitMemberWithInvite(db, invite, fixture.ownerDevice, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)
    ).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBER_ALREADY_EXISTS' }))

    db.close()
  })

  it('rejeita admissão quando o convite foi revogado antes do consumo', async () => {
    const fixture = createServerFixture()
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)

    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const candidateB = createTestDeviceIdentity()

    const db = openServerDatabase(dbPath)
    registerIssuedInvite(db, invite)
    revokeServerInvite(db, invite.inviteId)

    expect(() =>
      admitMemberWithInvite(db, invite, candidateB, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)
    ).toThrowError(expect.objectContaining({ code: 'SERVER_INVITE_REVOKED' }))

    expect(listMembers(db)).toHaveLength(1)
    db.close()
  })

  it('rejeita admissão quando o convite expirou antes do consumo', async () => {
    const fixture = createServerFixture()
    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)

    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 1000,
      maxUses: 1
    })

    const candidateB = createTestDeviceIdentity()

    const db = openServerDatabase(dbPath)
    registerIssuedInvite(db, invite)

    expect(() =>
      admitMemberWithInvite(db, invite, candidateB, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey, {
        nowSeconds: 2000
      })
    ).toThrowError(expect.objectContaining({ code: 'SERVER_INVITE_EXPIRED' }))

    expect(listMembers(db)).toHaveLength(1)
    db.close()
  })

  it('rejeita admissão com convite assinado por outro servidor', async () => {
    const serverA = createServerFixture()
    const serverB = createServerFixture()

    const root = await createTempDir()
    const dbPath = join(root, DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, serverA.ownerDevice)

    const inviteB = createServerInvite(serverB.serverId, serverB.serverPrivateKey, serverB.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 1
    })

    const candidate = createTestDeviceIdentity()

    const db = openServerDatabase(dbPath)

    expect(() =>
      admitMemberWithInvite(db, inviteB, candidate, serverA.serverId, serverA.serverPublicKey, serverA.serverPrivateKey)
    ).toThrowError(expect.objectContaining({ code: 'SERVER_INVITE_INVALID' }))

    db.close()
  })

  describe('testes de segurança, DB tampering e migração (v3 -> v4)', () => {
    it.each(['backdoor', 'sqlitex_hidden', 'SQLITEX_hidden'])('rejeita trigger inesperado %s sem alterar o banco', async (triggerName) => {
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)
      const owner = createTestDeviceIdentity()
      initializeServerDatabase(dbPath, owner)
      const raw = new DatabaseSync(dbPath)
      raw.exec(`CREATE TRIGGER ${triggerName} AFTER UPDATE ON invites BEGIN DELETE FROM members; END;`)
      raw.close()
      const before = await readFile(dbPath)

      await expect(validateServerDatabaseFile(dbPath)).rejects.toMatchObject({
        code: 'SERVER_DATABASE_SCHEMA_INVALID'
      })
      expect(await readFile(dbPath)).toEqual(before)
    })

    it.each(['schema', 'invite', 'column'])('preserva schema v3 e todos os bytes quando a validacao de %s falha', async (failure) => {
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)
      const owner = createTestDeviceIdentity()
      initializeServerDatabase(dbPath, owner)
      const raw = new DatabaseSync(dbPath)
      raw.exec('DROP TABLE messages; DROP INDEX IF EXISTS messages_channel_sequence; DROP TABLE channels; DROP TABLE member_certificates; PRAGMA user_version = 3;')
      raw.prepare(`INSERT INTO invites VALUES (?, ?, 2000000000, 3, 1, 0);`).run(
        'a'.repeat(32), Buffer.alloc(32, 1)
      )
      if (failure === 'schema') {
        raw.exec('CREATE TRIGGER sqlitex_hidden AFTER UPDATE ON invites BEGIN DELETE FROM members; END;')
      } else if (failure === 'column') {
        raw.exec('ALTER TABLE invites RENAME COLUMN invite_secret_hash TO unexpected_hash;')
      } else {
        raw.exec("UPDATE invites SET invite_secret_hash = X'01';")
      }
      raw.close()
      const before = await readFile(dbPath)

      for (let attempt = 0; attempt < 2; attempt++) {
        await expect(validateServerDatabaseFile(dbPath, {
          deviceFingerprint: owner.fingerprint,
          publicKey: owner.publicKey
        })).rejects.toMatchObject({
          code: failure === 'invite' ? 'SERVER_INVITE_STATE_INVALID' : 'SERVER_DATABASE_SCHEMA_INVALID'
        })
        expect(await readFile(dbPath)).toEqual(before)
      }

      const unchanged = new DatabaseSync(dbPath)
      try {
        expect(unchanged.prepare('PRAGMA user_version;').get()).toMatchObject({ user_version: 3 })
        expect(unchanged.prepare("SELECT name FROM sqlite_schema WHERE name = 'member_certificates';").get()).toBeUndefined()
        expect(unchanged.prepare('SELECT COUNT(*) AS count FROM invites;').get()).toMatchObject({ count: 1 })
      } finally {
        unchanged.close()
      }
    })

    it('(36) DB Tampering: atacante injeta linha em members sem certificado -> validação e autorização falham fechadas', async () => {
      const fixture = createServerFixture()
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)
      initializeServerDatabase(dbPath, fixture.ownerDevice)

      const attackerDevice = createTestDeviceIdentity()

      const dbRaw = new DatabaseSync(dbPath)
      dbRaw.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        attackerDevice.fingerprint,
        attackerDevice.publicKey
      )
      dbRaw.close()

      // Validação do banco falha
      expect(() =>
        openServerDatabase(dbPath, {
          deviceFingerprint: fixture.ownerDevice.fingerprint,
          publicKey: fixture.ownerDevice.publicKey
        })
      ).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBERSHIP_STATE_INVALID' }))
    })

    it('(37) DB Tampering: atacante injeta certificado com 64 bytes forjados/aleatórios -> falha fechada', async () => {
      const fixture = createServerFixture()
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)
      initializeServerDatabase(dbPath, fixture.ownerDevice)

      const attackerDevice = createTestDeviceIdentity()
      const fakeSig = Buffer.alloc(64, 0x99)

      const dbRaw = new DatabaseSync(dbPath)
      dbRaw.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        attackerDevice.fingerprint,
        attackerDevice.publicKey
      )
      dbRaw.prepare('INSERT INTO member_certificates (device_fingerprint, certificate_version, admission_invite_id, signature) VALUES (?, 1, ?, ?);').run(
        attackerDevice.fingerprint,
        '00000000000000000000000000000000',
        fakeSig
      )
      dbRaw.close()

      // Ao abrir o banco passando o contexto criptográfico do servidor, a assinatura forjada é detectada
      expect(() =>
        openServerDatabase(
          dbPath,
          {
            deviceFingerprint: fixture.ownerDevice.fingerprint,
            publicKey: fixture.ownerDevice.publicKey
          },
          {
            serverId: fixture.serverId,
            serverPublicKey: fixture.serverPublicKey
          }
        )
      ).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBER_CERTIFICATE_INVALID' }))
    })

    it('(43 e 64) DB Tampering: atacante injeta certificado para o Initial Owner -> falha com SERVER_MEMBER_CERTIFICATE_UNEXPECTED', async () => {
      const fixture = createServerFixture()
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)
      initializeServerDatabase(dbPath, fixture.ownerDevice)

      const fakeSig = Buffer.alloc(64, 0x11)
      const dbRaw = new DatabaseSync(dbPath)
      dbRaw.prepare('INSERT INTO member_certificates (device_fingerprint, certificate_version, admission_invite_id, signature) VALUES (?, 1, ?, ?);').run(
        fixture.ownerDevice.fingerprint,
        '00000000000000000000000000000000',
        fakeSig
      )
      dbRaw.close()

      expect(() =>
        openServerDatabase(dbPath, {
          deviceFingerprint: fixture.ownerDevice.fingerprint,
          publicKey: fixture.ownerDevice.publicKey
        })
      ).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBER_CERTIFICATE_UNEXPECTED' }))
    })

    it('(65) migração segura de schema v3 (owner-only) para schema v4', async () => {
      const fixture = createServerFixture()
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)

      // Cria manualmente um banco válido no schema v3
      const dbV3 = new DatabaseSync(dbPath)
      dbV3.exec(`
        CREATE TABLE members (
          device_fingerprint TEXT PRIMARY KEY,
          device_public_key BLOB NOT NULL
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
      dbV3.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        fixture.ownerDevice.fingerprint,
        fixture.ownerDevice.publicKey
      )
      dbV3.exec('PRAGMA user_version = 3;')
      dbV3.prepare('INSERT INTO invites VALUES (?, ?, 2000000000, 3, 1, 1);').run(
        'a'.repeat(32), Buffer.alloc(32, 1)
      )
      const originalMembers = dbV3.prepare('SELECT * FROM members;').all()
      const originalInvites = dbV3.prepare('SELECT * FROM invites;').all()
      dbV3.close()

      // Abrir o banco com expectedOwner migra de forma segura para v4
      const dbMigrated = openServerDatabase(dbPath, {
        deviceFingerprint: fixture.ownerDevice.fingerprint,
        publicKey: fixture.ownerDevice.publicKey
      })

      const version = dbMigrated.prepare('PRAGMA user_version;').get() as { user_version: number }
      expect(version.user_version).toBe(DATABASE_SCHEMA_VERSION)

      const certCount = dbMigrated.prepare('SELECT COUNT(*) as count FROM member_certificates;').get() as { count: number }
      expect(certCount.count).toBe(0)
      expect(dbMigrated.prepare('SELECT * FROM members;').all()).toEqual(originalMembers)
      expect(dbMigrated.prepare('SELECT * FROM invites;').all()).toEqual(originalInvites)
      dbMigrated.close()
    })

    it('(66) migração de schema v3 com membros não-owner falha fechada com SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION', async () => {
      const fixture = createServerFixture()
      const nonOwner = createTestDeviceIdentity()
      const root = await createTempDir()
      const dbPath = join(root, DATABASE_FILE_NAME)

      // Cria banco v3 com owner + não-owner
      const dbV3 = new DatabaseSync(dbPath)
      dbV3.exec(`
        CREATE TABLE members (
          device_fingerprint TEXT PRIMARY KEY,
          device_public_key BLOB NOT NULL
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
      dbV3.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        fixture.ownerDevice.fingerprint,
        fixture.ownerDevice.publicKey
      )
      dbV3.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        nonOwner.fingerprint,
        nonOwner.publicKey
      )
      dbV3.exec('PRAGMA user_version = 3;')
      dbV3.close()

      // Tentativa de abertura/migração deve falhar fechada sem auto-certificar
      expect(() =>
        openServerDatabase(dbPath, {
          deviceFingerprint: fixture.ownerDevice.fingerprint,
          publicKey: fixture.ownerDevice.publicKey
        })
      ).toThrowError(expect.objectContaining({ code: 'SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION' }))
    })
  })

  it('rejeita SQLite valido ja acima da capacidade sem truncar dados', async () => {
    const owner = createTestDeviceIdentity()
    const dbPath = join(await createTempDir(), DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, owner)
    // An external connection is not subject to the application connection's page limit.
    const raw = new DatabaseSync(dbPath)
    try {
      raw.exec(`
        WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < 14000)
        INSERT INTO invites
        SELECT printf('%032x', n), zeroblob(32), 2000000000, 3, 0, 0 FROM ids;
      `)
      expect(raw.prepare('PRAGMA quick_check;').get()).toMatchObject({ quick_check: 'ok' })
    } finally {
      raw.close()
    }
    const before = await readFile(dbPath)
    expect(before.length).toBeGreaterThan(MAX_INITIAL_SERVER_DATABASE_BYTES)
    expect(() => openServerDatabase(dbPath)).toThrowError(expect.objectContaining({ code: 'SERVER_DATABASE_TOO_LARGE' }))
    await expect(validateServerDatabaseFile(dbPath)).rejects.toMatchObject({ code: 'SERVER_DATABASE_TOO_LARGE' })
    expect(await readFile(dbPath)).toEqual(before)
  }, 30000)

  it.each([512, 4096, 65536])('limita crescimento SQLite com paginas de %i bytes e reverte admissao sem perder dados', async (pageSize) => {
    const fixture = createServerFixture()
    const dbPath = join(await createTempDir(), DATABASE_FILE_NAME)
    initializeServerDatabase(dbPath, fixture.ownerDevice)
    const raw = new DatabaseSync(dbPath)
    raw.exec(`PRAGMA page_size = ${pageSize}; VACUUM;`)
    raw.close()
    const initialSize = (await stat(dbPath)).size
    const expectedOwner = {
      deviceFingerprint: fixture.ownerDevice.fingerprint,
      publicKey: fixture.ownerDevice.publicKey
    }
    const serverContext = { serverId: fixture.serverId, serverPublicKey: fixture.serverPublicKey }
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.ownerDevice, {
      expiresAt: 2000000000,
      maxUses: 10000
    })
    const db = openServerDatabase(dbPath, expectedOwner, serverContext)
    let persistedInvites = 1
    try {
      expect(db.prepare('PRAGMA page_size;').get()).toMatchObject({ page_size: pageSize })
      expect(db.prepare('PRAGMA max_page_count;').get()).toMatchObject({
        max_page_count: Math.floor(MAX_INITIAL_SERVER_DATABASE_BYTES / pageSize)
      })
      registerIssuedInvite(db, invite)

      // Commit bounded batches, then fill the remaining space with individual writes.
      let full = false
      for (const batchSize of [100, 1]) {
        full = false
        while (!full && persistedInvites < 20000) {
          db.exec('BEGIN IMMEDIATE;')
          try {
            for (let offset = 0; offset < batchSize; offset++) {
              registerIssuedInvite(db, {
                ...invite,
                inviteId: (persistedInvites + offset).toString(16).padStart(32, '0')
              })
            }
            db.exec('COMMIT;')
            persistedInvites += batchSize
          } catch (error) {
            // SQLITE_FULL may already have rolled back the entire transaction.
            try { db.exec('ROLLBACK;') } catch { /* Already rolled back. */ }
            expect(error).toBeInstanceOf(ServerDatabaseError)
            expect(error).toMatchObject({ code: 'SERVER_DATABASE_TOO_LARGE' })
            full = true
          }
        }
        expect(full).toBe(true)
        expect(db.prepare('SELECT COUNT(*) AS count FROM invites;').get()).toMatchObject({ count: persistedInvites })
      }

      let admissionRejected = false
      for (let attempt = 0; attempt < 1000; attempt++) {
        const candidate = createTestDeviceIdentity()
        const before = {
          members: db.prepare('SELECT * FROM members ORDER BY device_fingerprint;').all(),
          certificates: db.prepare('SELECT * FROM member_certificates ORDER BY device_fingerprint;').all(),
          invite: getStoredInvite(db, invite.inviteId)
        }
        try {
          admitMemberWithInvite(db, invite, candidate, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)
        } catch (error) {
          expect(error).toMatchObject({ code: 'SERVER_DATABASE_TOO_LARGE' })
          expect(getMemberByFingerprint(db, candidate.fingerprint)).toBeUndefined()
          expect(db.prepare('SELECT * FROM members ORDER BY device_fingerprint;').all()).toEqual(before.members)
          expect(db.prepare('SELECT * FROM member_certificates ORDER BY device_fingerprint;').all()).toEqual(before.certificates)
          expect(getStoredInvite(db, invite.inviteId)).toEqual(before.invite)
          admissionRejected = true
          break
        }
      }
      expect(admissionRejected).toBe(true)
      expect(db.prepare('PRAGMA quick_check;').get()).toMatchObject({ quick_check: 'ok' })
      // No transaction is left open after the failed admission.
      db.exec('BEGIN IMMEDIATE; ROLLBACK;')
    } finally {
      db.close()
    }

    expect((await stat(dbPath)).size).toBeGreaterThanOrEqual(initialSize)
    expect((await stat(dbPath)).size).toBeLessThanOrEqual(MAX_INITIAL_SERVER_DATABASE_BYTES)
    await expect(validateServerDatabaseFile(dbPath, expectedOwner, serverContext)).resolves.toBeUndefined()
    const reopened = openServerDatabase(dbPath, expectedOwner, serverContext)
    try {
      expect(reopened.prepare('PRAGMA max_page_count;').get()).toMatchObject({
        max_page_count: Math.floor(MAX_INITIAL_SERVER_DATABASE_BYTES / pageSize)
      })
      expect(reopened.prepare('SELECT COUNT(*) AS count FROM invites;').get()).toMatchObject({ count: persistedInvites })
    } finally {
      reopened.close()
    }
  }, 30000)
})

describe('canais do servidor (ETAPA 8.2)', () => {
  function createChannelFixture() {
    const root = createTempDirSync()
    const dbPath = join(root, DATABASE_FILE_NAME)
    const owner = createTestDeviceIdentity()
    initializeServerDatabase(dbPath, owner)
    const db = openServerDatabase(dbPath, {
      deviceFingerprint: owner.fingerprint,
      publicKey: owner.publicKey
    })
    testRoots.push(root)
    return { db, dbPath, owner }
  }

  it('cria, lista, renomeia, arquiva e remove canal como owner', () => {
    const { db, owner } = createChannelFixture()
    try {
      const created = createChannel(db, {
        name: 'Geral', actorFingerprint: owner.fingerprint, isOwner: true, nowSeconds: 100
      })
      expect(created.name).toBe('Geral')
      expect(created.archived).toBe(false)
      expect(created.createdAt).toBe(100)
      expect(created.channelId).toMatch(/^[0-9a-f]{32}$/)

      expect(listChannels(db)).toEqual([created])
      expect(getChannelByName(db, 'Geral')).toEqual(created)

      const renamed = renameChannel(db, {
        channelId: created.channelId, name: 'Retaguarda', actorFingerprint: created.createdBy, isOwner: true
      })
      expect(renamed.name).toBe('Retaguarda')

      const archived = setChannelArchived(db, {
        channelId: created.channelId, archived: true, actorFingerprint: created.createdBy, isOwner: true
      })
      expect(archived.archived).toBe(true)

      deleteChannel(db, { channelId: created.channelId, actorFingerprint: created.createdBy, isOwner: true })
      expect(listChannels(db)).toEqual([])
    } finally {
      db.close()
    }
  })

  it('rejeita não-owner, nomes inválidos, duplicados, IDs malformados e canal inexistente', () => {
    const { db, owner } = createChannelFixture()
    try {
      expect(() => createChannel(db, {
        name: 'X', actorFingerprint: owner.fingerprint, isOwner: false
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED'))
      expect(() => createChannel(db, {
        name: '', actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_INVALID'))
      expect(() => createChannel(db, {
        name: 'a'.repeat(MAX_CHANNEL_NAME_CODE_POINTS + 1), actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_INVALID'))
      expect(() => createChannel(db, {
        name: 'linha\nquebrada', actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_INVALID'))

      const created = createChannel(db, { name: 'Geral', actorFingerprint: owner.fingerprint, isOwner: true })
      expect(() => createChannel(db, { name: 'Geral', actorFingerprint: owner.fingerprint, isOwner: true }))
        .toThrow()
      expect(() => createChannel(db, { name: 'Outro', actorFingerprint: owner.fingerprint, isOwner: true, channelId: created.channelId }))
        .toThrow()

      expect(() => renameChannel(db, {
        channelId: created.channelId, name: 'Novo', actorFingerprint: owner.fingerprint, isOwner: false
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED'))
      expect(() => renameChannel(db, {
        channelId: 'z'.repeat(32), name: 'Novo', actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED'))
      expect(() => renameChannel(db, {
        channelId: 'zz', name: 'Novo', actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED'))
      expect(() => deleteChannel(db, {
        channelId: 'f'.repeat(32), actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_NOT_FOUND'))

      const failClosed = (operation: () => unknown): void => {
        try {
          operation()
        } catch (error) {
          expect(error).toBeInstanceOf(ServerDatabaseError)
          return
        }
        expect.unreachable()
      }
      // Duplicate name rename fails closed and the transaction preserves state.
      createChannel(db, { name: 'Outro', actorFingerprint: owner.fingerprint, isOwner: true })
      failClosed(() => renameChannel(db, {
        channelId: created.channelId, name: 'Outro', actorFingerprint: owner.fingerprint, isOwner: true
      }))
      expect(listChannels(db).some((channel) => channel.name === 'Geral')).toBe(true)
    } finally {
      db.close()
    }
  })

  it('impõe limite de 128 canais e preserva estado em falha transacional', () => {
    const { db, owner } = createChannelFixture()
    try {
      for (let index = 0; index < MAX_CHANNELS_PER_SERVER; index++) {
        createChannel(db, {
          name: `Canal ${index}`, actorFingerprint: owner.fingerprint, isOwner: true
        })
      }
      expect(listChannels(db)).toHaveLength(MAX_CHANNELS_PER_SERVER)
      expect(() => createChannel(db, {
        name: 'Canal 129', actorFingerprint: owner.fingerprint, isOwner: true
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_LIMIT_REACHED'))
      expect(listChannels(db)).toHaveLength(MAX_CHANNELS_PER_SERVER)

      expect(() => createChannel(db, {
        name: 'Canal 129', actorFingerprint: owner.fingerprint, isOwner: false
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_UNAUTHORIZED'))
      expect(listChannels(db)).toHaveLength(MAX_CHANNELS_PER_SERVER)
    } finally {
      db.close()
    }
  })

  it('migração v4 -> v6 adiciona channels e messages e preserva dados', () => {
    const root = createTempDirSync()
    testRoots.push(root)
    const dbPath = join(root, DATABASE_FILE_NAME)
    const owner = createTestDeviceIdentity()
    initializeServerDatabase(dbPath, owner)

    const raw = new DatabaseSync(dbPath)
    raw.exec('DROP TABLE channels; DROP TABLE messages; DROP INDEX IF EXISTS messages_channel_sequence; PRAGMA user_version = 4;')
    raw.close()
    const before = readFileSync(dbPath)

    const migrated = openServerDatabase(dbPath, {
      deviceFingerprint: owner.fingerprint,
      publicKey: owner.publicKey
    })
    try {
      expect(migrated.prepare('PRAGMA user_version;').get()).toMatchObject({ user_version: 6 })
      expect(migrated.prepare('SELECT COUNT(*) AS count FROM channels;').get()).toMatchObject({ count: 0 })
      expect(migrated.prepare('SELECT COUNT(*) AS count FROM messages;').get()).toMatchObject({ count: 0 })
      expect(migrated.prepare('SELECT COUNT(*) AS count FROM members;').get()).toMatchObject({ count: 1 })
    } finally {
      migrated.close()
    }
    expect(readFileSync(dbPath)).not.toEqual(before)
  })

  it('canal criado referencia membro; remoção de membro referenciado falha fechada', () => {
    const { db, owner } = createChannelFixture()
    try {
      createChannel(db, { name: 'Geral', actorFingerprint: owner.fingerprint, isOwner: true })
      expect(() => db.exec(`DELETE FROM members WHERE device_fingerprint = '${owner.fingerprint}';`))
        .toThrow()
      expect(listChannels(db)).toHaveLength(1)
    } finally {
      db.close()
    }
  })
})

function createTempDirSync(): string {
  return mkdtempSync(join(tmpdir(), 'masquerada-db-test-'))
}

describe('mensagens do servidor (ETAPA 8.3)', () => {
  function createMessageFixture() {
    const root = createTempDirSync()
    const dbPath = join(root, DATABASE_FILE_NAME)
    const owner = createTestDeviceIdentity()
    const serverKey = generateKeyPairSync('ed25519')
    const serverPublicKey = Buffer.from(serverKey.publicKey.export({ format: 'der', type: 'spki' }))
    const serverId = `sha256:${createHash('sha256').update(serverPublicKey).digest('hex')}`
    initializeServerDatabase(dbPath, owner)
    const db = openServerDatabase(dbPath, {
      deviceFingerprint: owner.fingerprint,
      publicKey: owner.publicKey
    }, { serverId, serverPublicKey })
    testRoots.push(root)
    const ownerAuthorization = createMessageOperationAuthorization({
      actorFingerprint: owner.fingerprint, isAuthorized: true, isOwner: true
    })
    const channel = createChannel(db, {
      name: 'Geral', actorFingerprint: owner.fingerprint, isOwner: true
    })
    return { db, dbPath, owner, ownerAuthorization, channel, serverId, serverPublicKey, serverPrivateKey: serverKey.privateKey }
  }

  function admitMember(db: DatabaseSync, fixture: ReturnType<typeof createMessageFixture>): AuthenticatedCandidateDevice {
    const memberDevice = createTestDeviceIdentity()
    const invite = createServerInvite(fixture.serverId, fixture.serverPrivateKey, fixture.owner, {
      expiresAt: 2000000000, maxUses: 5
    })
    registerIssuedInvite(db, invite)
    admitMemberWithInvite(db, invite, memberDevice, fixture.serverId, fixture.serverPublicKey, fixture.serverPrivateKey)
    return memberDevice
  }

  it('cria mensagem com sequence do host, dedup, edição e soft delete', () => {
    const fixture = createMessageFixture()
    try {
      const first = createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'Primeira',
        clientMessageId: 'a'.repeat(32),
        authorization: fixture.ownerAuthorization,
        nowSeconds: 500
      })
      expect(first.sequence).toBe(1)
      expect(first.content).toBe('Primeira')
      expect(first.deletedAt).toBeNull()

      // Dedup: mesmo clientMessageId rejeitado; outro ID cria sequence 2.
      expect(() => createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'Primeira',
        clientMessageId: 'a'.repeat(32),
        authorization: fixture.ownerAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_DUPLICATE'))

      const second = createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'Segunda',
        clientMessageId: 'b'.repeat(32),
        authorization: fixture.ownerAuthorization,
        nowSeconds: 600
      })
      expect(second.sequence).toBe(2)

      const edited = editMessage(fixture.db, {
        messageId: second.messageId,
        content: 'Segunda editada',
        authorization: fixture.ownerAuthorization,
        nowSeconds: 700
      })
      expect(edited.content).toBe('Segunda editada')
      expect(edited.editedAt).toBe(700)

      const deleted = deleteMessage(fixture.db, {
        messageId: second.messageId,
        authorization: fixture.ownerAuthorization,
        nowSeconds: 800
      })
      expect(deleted.deletedAt).toBe(800)
      expect(deleted.content).toBe('')

      expect(listMessages(fixture.db, { channelId: fixture.channel.channelId })).toHaveLength(2)
      expect(listMessages(fixture.db, { channelId: fixture.channel.channelId })[1]!.content).toBe('')
    } finally {
      fixture.db.close()
    }
  })

  it('não-membro não publica; membro edita apenas o próprio conteúdo; owner remove de membro', () => {
    const fixture = createMessageFixture()
    try {
      const memberDevice = admitMember(fixture.db, fixture)
      const memberAuthorization = createMessageOperationAuthorization({
        actorFingerprint: memberDevice.fingerprint, isAuthorized: true, isOwner: false
      })
      const outsiderAuthorization = createMessageOperationAuthorization({
        actorFingerprint: 'sha256:' + 'e'.repeat(64), isAuthorized: true, isOwner: true
      })

      const memberMessage = createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'Do membro',
        clientMessageId: 'c'.repeat(32),
        authorization: memberAuthorization
      })

      expect(() => createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'De fora',
        clientMessageId: 'd'.repeat(32),
        authorization: outsiderAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN'))

      expect(() => editMessage(fixture.db, {
        messageId: memberMessage.messageId,
        content: 'Sequestrada',
        authorization: fixture.ownerAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN'))

      expect(() => editMessage(fixture.db, {
        messageId: memberMessage.messageId,
        content: 'Editada por outro membro',
        authorization: createMessageOperationAuthorization({
          actorFingerprint: 'sha256:' + 'e'.repeat(64), isAuthorized: true, isOwner: true
        })
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_FORBIDDEN'))

      const removedByOwner = deleteMessage(fixture.db, {
        messageId: memberMessage.messageId,
        authorization: fixture.ownerAuthorization,
        nowSeconds: Math.floor(Date.now() / 1000) + 500
      })
      expect(removedByOwner.deletedAt).not.toBeNull()
    } finally {
      fixture.db.close()
    }
  })

  it('listagem é bounded, ordenada e aceita cursor afterSequence', () => {
    const fixture = createMessageFixture()
    try {
      for (let index = 1; index <= 10; index++) {
        createMessage(fixture.db, {
          channelId: fixture.channel.channelId,
          content: `Mensagem ${index}`,
          clientMessageId: index.toString(16).padStart(32, '0'),
          authorization: fixture.ownerAuthorization,
          nowSeconds: 1000 + index
        })
      }

      expect(listMessages(fixture.db, { channelId: fixture.channel.channelId })).toHaveLength(10)
      expect(listMessages(fixture.db, { channelId: fixture.channel.channelId, limit: 4 })).toHaveLength(4)
      const cursor = listMessages(fixture.db, { channelId: fixture.channel.channelId, afterSequence: 7, limit: 2 })
      expect(cursor.map((message) => message.sequence)).toEqual([8, 9])
      expect(() => listMessages(fixture.db, { channelId: 'f'.repeat(32) }))
        .toThrow(new ServerDatabaseError('SERVER_MESSAGE_NOT_FOUND'))
      expect(() => listMessages(fixture.db, { channelId: fixture.channel.channelId, afterSequence: -1 }))
        .toThrow(new ServerDatabaseError('SERVER_MESSAGE_INVALID'))
    } finally {
      fixture.db.close()
    }
  })

  it('conteúdo inválido, canal arquivado e capacidade máxima falham fechados', () => {
    const fixture = createMessageFixture()
    try {
      expect(() => createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'a'.repeat(MAX_MESSAGE_CONTENT_CODE_POINTS + 1),
        clientMessageId: 'e'.repeat(32),
        authorization: fixture.ownerAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_INVALID'))
      expect(() => createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'linha\nquebrada',
        clientMessageId: 'e'.repeat(32),
        authorization: fixture.ownerAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_INVALID'))

      setChannelArchived(fixture.db, {
        channelId: fixture.channel.channelId, archived: true,
        actorFingerprint: fixture.owner.fingerprint, isOwner: true
      })
      expect(() => createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'Após arquivo',
        clientMessageId: 'e'.repeat(32),
        authorization: fixture.ownerAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_CHANNEL_ARCHIVED'))
    } finally {
      fixture.db.close()
    }
  })

  it('canal com mensagem não pode ser removido (FK RESTRICT) e remoção preserva banco', () => {
    const fixture = createMessageFixture()
    try {
      createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'Única',
        clientMessageId: 'f'.repeat(32),
        authorization: fixture.ownerAuthorization
      })
      const sizeBefore = readFileSync(fixture.dbPath).length
      expect(() => deleteChannel(fixture.db, {
        channelId: fixture.channel.channelId,
        actorFingerprint: fixture.owner.fingerprint,
        isOwner: true
      })).toThrow()
      expect(readFileSync(fixture.dbPath).length).toBe(sizeBefore)
      expect(getChannelByName(fixture.db, 'Geral')).toBeDefined()
    } finally {
      fixture.db.close()
    }
  })

  it('migração v5 -> v6 adiciona messages e preserva dados', () => {
    const root = createTempDirSync()
    testRoots.push(root)
    const dbPath = join(root, DATABASE_FILE_NAME)
    const owner = createTestDeviceIdentity()
    initializeServerDatabase(dbPath, owner)

    const raw = new DatabaseSync(dbPath)
    raw.exec('DROP TABLE messages; DROP INDEX IF EXISTS messages_channel_sequence; PRAGMA user_version = 5;')
    raw.close()

    const migrated = openServerDatabase(dbPath, {
      deviceFingerprint: owner.fingerprint,
      publicKey: owner.publicKey
    })
    try {
      expect(migrated.prepare('PRAGMA user_version;').get()).toMatchObject({ user_version: 6 })
      expect(migrated.prepare('SELECT COUNT(*) AS count FROM messages;').get()).toMatchObject({ count: 0 })
      expect(migrated.prepare('SELECT COUNT(*) AS count FROM members;').get()).toMatchObject({ count: 1 })
    } finally {
      migrated.close()
    }
  })

  it('capacidade de MAX_MESSAGES_PER_CHANNEL é imposta e reversível', () => {
    const fixture = createMessageFixture()
    try {
      const capacities = MAX_MESSAGES_PER_CHANNEL
      for (let index = 0; index < capacities; index++) {
        createMessage(fixture.db, {
          channelId: fixture.channel.channelId,
          content: `m${index}`,
          clientMessageId: index.toString(16).padStart(32, '0'),
          authorization: fixture.ownerAuthorization
        })
      }
      expect(() => createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'estouro',
        clientMessageId: 'f'.repeat(32),
        authorization: fixture.ownerAuthorization
      })).toThrow(new ServerDatabaseError('SERVER_MESSAGE_CAPACITY_REACHED'))

      const first = listMessages(fixture.db, { channelId: fixture.channel.channelId, limit: 1 })[0]!
      deleteMessage(fixture.db, { messageId: first.messageId, authorization: fixture.ownerAuthorization })
      const recovered = createMessage(fixture.db, {
        channelId: fixture.channel.channelId,
        content: 'após limpeza',
        clientMessageId: 'f'.repeat(32),
        authorization: fixture.ownerAuthorization
      })
      expect(recovered.sequence).toBe(capacities + 1)
    } finally {
      fixture.db.close()
    }
  }, 30000)
})

function createTestDeviceIdentity() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const fingerprint = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`

  return createAuthenticatedCandidateDevice(fingerprint, publicKey)
}

function createServerFixture() {
  const serverKey = generateKeyPairSync('ed25519')
  const serverPublicKey = Buffer.from(serverKey.publicKey.export({ format: 'der', type: 'spki' }))
  const serverId = `sha256:${createHash('sha256').update(serverPublicKey).digest('hex')}`
  const ownerDevice = createTestDeviceIdentity()

  return {
    serverId,
    serverPublicKey,
    serverPrivateKey: serverKey.privateKey,
    ownerDevice
  }
}

async function createTempDir(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-db-test-'))
  testRoots.push(root)
  return root
}
