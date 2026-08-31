import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
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
  DATABASE_FILE_NAME,
  DATABASE_SCHEMA_VERSION,
  getMemberByFingerprint,
  getStoredInvite,
  initializeServerDatabase,
  listMembers,
  openServerDatabase,
  registerIssuedInvite,
  revokeServerInvite,
  validateServerDatabaseFile,
  verifyPersistedMemberAuthorization
} from './server-database'
import { createServerInvite } from './server-invite'

const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('fundação segura de SQLite, membership, invites, certificates e admissão', () => {
  it('inicializa novo banco SQLite com schema version 4, members, member_certificates e invites tables', async () => {
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
      .prepare("SELECT type, name, tbl_name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name ASC;")
      .all()
    const members = listMembers(db)
    const certs = db.prepare('SELECT COUNT(*) as count FROM member_certificates;').get() as { count: number }
    db.close()

    expect(version.user_version).toBe(DATABASE_SCHEMA_VERSION)
    expect(foreignKeys.foreign_keys).toBe(1)
    expect(trustedSchema.trusted_schema).toBe(0)
    expect(schemaObjects).toEqual([
      { type: 'table', name: 'invites', tbl_name: 'invites' },
      { type: 'table', name: 'member_certificates', tbl_name: 'member_certificates' },
      { type: 'table', name: 'members', tbl_name: 'members' }
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
      dbV3.close()

      // Abrir o banco com expectedOwner migra de forma segura para v4
      const dbMigrated = openServerDatabase(dbPath, {
        deviceFingerprint: fixture.ownerDevice.fingerprint,
        publicKey: fixture.ownerDevice.publicKey
      })

      const version = dbMigrated.prepare('PRAGMA user_version;').get() as { user_version: number }
      expect(version.user_version).toBe(4)

      const certCount = dbMigrated.prepare('SELECT COUNT(*) as count FROM member_certificates;').get() as { count: number }
      expect(certCount.count).toBe(0)
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
