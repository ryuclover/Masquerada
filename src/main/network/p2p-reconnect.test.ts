import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import {
  DATABASE_FILE_NAME,
  listMembers,
  openServerDatabase
} from '../servers/server-database'
import {
  AdmissionMessageType,
  decodeMemberReconnectRequest,
  decodeMemberReconnectResponse,
  encodeMemberReconnectRequest,
  encodeMemberReconnectResponse,
  MemberReconnectResponseStatus
} from './p2p-admission'
import {
  discoverLanServer,
  startLanDiscoveryResponder,
  type LanDiscoveryResponder
} from './lan-discovery'
import {
  connectLanTcpPeer,
  startLanTcpServer,
  type LanTcpServerHandle
} from './lan-transport'

const testRoots: string[] = []
const activeServers: LanTcpServerHandle[] = []
const activeResponders: LanDiscoveryResponder[] = []

afterEach(async () => {
  await Promise.all(activeResponders.splice(0).map((r) => r.close()))
  await Promise.all(activeServers.splice(0).map((s) => s.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('p2p-reconnect: reconexão autenticada de membro existente sem convite', () => {
  describe('protocolo, wire format e parsers estritos (testes 84)', () => {
    it('(84) codifica e decodifica MEMBER_RECONNECT_REQUEST exatamente em 2 bytes', () => {
      const encoded = encodeMemberReconnectRequest()
      expect(encoded).toHaveLength(2)
      expect(encoded[0]).toBe(1) // version
      expect(encoded[1]).toBe(AdmissionMessageType.MEMBER_RECONNECT_REQUEST) // 0x03

      const decoded = decodeMemberReconnectRequest(encoded)
      expect(decoded.version).toBe(1)
      expect(decoded.messageType).toBe(AdmissionMessageType.MEMBER_RECONNECT_REQUEST)

      // Rejeita buffers malformados (vazio, 1 byte, versão errada, trailing bytes)
      expect(() => decodeMemberReconnectRequest(Buffer.alloc(0))).toThrowError()
      expect(() => decodeMemberReconnectRequest(Buffer.from([1]))).toThrowError()
      expect(() => decodeMemberReconnectRequest(Buffer.from([2, 0x03]))).toThrowError()
      expect(() => decodeMemberReconnectRequest(Buffer.from([1, 0x03, 0x00]))).toThrowError()
    })

    it('(84) codifica e decodifica MEMBER_RECONNECT_RESPONSE exatamente em 3 bytes', () => {
      const authResp = encodeMemberReconnectResponse({
        version: 1,
        messageType: AdmissionMessageType.MEMBER_RECONNECT_RESPONSE,
        status: MemberReconnectResponseStatus.AUTHORIZED
      })
      expect(authResp).toHaveLength(3)
      expect(authResp[0]).toBe(1)
      expect(authResp[1]).toBe(AdmissionMessageType.MEMBER_RECONNECT_RESPONSE) // 0x04
      expect(authResp[2]).toBe(MemberReconnectResponseStatus.AUTHORIZED) // 0x01

      const decodedAuth = decodeMemberReconnectResponse(authResp)
      expect(decodedAuth.status).toBe(MemberReconnectResponseStatus.AUTHORIZED)

      const rejResp = encodeMemberReconnectResponse({
        version: 1,
        messageType: AdmissionMessageType.MEMBER_RECONNECT_RESPONSE,
        status: MemberReconnectResponseStatus.REJECTED
      })
      expect(decodeMemberReconnectResponse(rejResp).status).toBe(MemberReconnectResponseStatus.REJECTED)

      // Rejeita status desconhecido ou trailing bytes
      expect(() => decodeMemberReconnectResponse(Buffer.from([1, 0x04, 0x99]))).toThrowError()
      expect(() => decodeMemberReconnectResponse(Buffer.from([1, 0x04, 0x01, 0x00]))).toThrowError()
    })
  })

  describe('reconexão end-to-end de membros legítimos (testes 65, 66, 75, 76, 77, 78, 79)', () => {
    it('(65 e 77-79) reconecta membro não-owner admitido sem convite e com zero mutação no banco', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // 1. Primeira admissão com convite
      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const firstConn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const firstRes = await firstConn.waitForAdmission()
      expect(firstRes.status).toBe('admitted')
      firstConn.destroy()

      // Snapshot do banco antes da reconexão
      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const dbBefore = openServerDatabase(dbPath)
      const membersBefore = listMembers(dbBefore)
      const certsBefore = dbBefore.prepare('SELECT * FROM member_certificates;').all()
      const invitesBefore = dbBefore.prepare('SELECT * FROM invites;').all()
      dbBefore.close()

      // 2. Reconexão sem convite
      const reconnectConn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect' // SEM INVITE
      })

      const reconnectRes = await reconnectConn.waitForAuthorization()
      expect(reconnectRes.status).toBe('authorized')
      expect(reconnectConn.getState()).toBe('MEMBER_CONNECTED')
      reconnectConn.destroy()

      // Snapshot do banco após a reconexão: ZERO MUTAÇÃO
      const dbAfter = openServerDatabase(dbPath)
      const membersAfter = listMembers(dbAfter)
      const certsAfter = dbAfter.prepare('SELECT * FROM member_certificates;').all()
      const invitesAfter = dbAfter.prepare('SELECT * FROM invites;').all()
      dbAfter.close()

      expect(membersAfter).toEqual(membersBefore)
      expect(certsAfter).toEqual(certsBefore)
      expect(invitesAfter).toEqual(invitesBefore)
    })

    it('(66) reconecta o Initial Owner com sucesso através da autorização do Initial Owner Binding', async () => {
      const serverFixture = await createLocalServerFixture()

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      // Owner conecta em modo reconnect
      const ownerConn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: serverFixture.ownerDevice.fingerprint,
        devicePublicKey: serverFixture.ownerDevice.publicKey,
        devicePrivateKey: serverFixture.ownerPrivateKey,
        authorizationMode: 'reconnect'
      })

      const res = await ownerConn.waitForAuthorization()
      expect(res.status).toBe('authorized')
      expect(ownerConn.getState()).toBe('MEMBER_CONNECTED')
      ownerConn.destroy()
    })

    it('(75 e 76) reconexão de membro legítimo é autorizada mesmo se o convite original tiver sido revogado ou expirado', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { invite, encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      // 1. Admissão inicial
      const conn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      await conn.waitForAdmission()
      conn.destroy()

      // Revoga o convite original no banco
      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const db = openServerDatabase(dbPath)
      db.prepare('UPDATE invites SET revoked = 1, expires_at = 100 WHERE invite_id = ?;').run(invite.inviteId)
      db.close()

      // 2. Reconexão após revogação/expiração do convite -> AUTHORIZED
      const reconnectConn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })

      const res = await reconnectConn.waitForAuthorization()
      expect(res.status).toBe('authorized')
      reconnectConn.destroy()
    })
  })

  describe('rejeição de invasores, DB tampering e certificados forjados (testes 67 a 72)', () => {
    it('(67) rejeita reconexão de dispositivo completamente novo/desconhecido que nunca foi admitido', async () => {
      const serverFixture = await createLocalServerFixture()
      const unknownClient = createClientFixture()

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const conn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: unknownClient.fingerprint,
        devicePublicKey: unknownClient.publicKey,
        devicePrivateKey: unknownClient.privateKey,
        authorizationMode: 'reconnect'
      })

      await expect(conn.waitForAuthorization()).rejects.toThrowError()
      conn.destroy()
    })

    it('(68) DB Tampering: linha injetada em members sem certificate é rejeitada na reconexão end-to-end', async () => {
      const serverFixture = await createLocalServerFixture()
      const attackerClient = createClientFixture()

      // Atacante injeta sua chave em members sem criar certificado
      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const dbRaw = new DatabaseSync(dbPath)
      dbRaw.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        attackerClient.fingerprint,
        attackerClient.publicKey
      )
      dbRaw.close()

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const conn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: attackerClient.fingerprint,
        devicePublicKey: attackerClient.publicKey,
        devicePrivateKey: attackerClient.privateKey,
        authorizationMode: 'reconnect'
      })

      await expect(conn.waitForAuthorization()).rejects.toThrowError()
      conn.destroy()
    })

    it('(69 e 70) DB Tampering: certificado com assinatura forjada ou alterada falha fechado no reconnect', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // Admite legitimamente
      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const conn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      await conn.waitForAdmission()
      conn.destroy()

      // Corrompe a assinatura do certificado no banco
      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const dbRaw = new DatabaseSync(dbPath)
      const fakeSig = Buffer.alloc(64, 0x77)
      dbRaw.prepare('UPDATE member_certificates SET signature = ? WHERE device_fingerprint = ?;').run(
        fakeSig,
        clientFixture.fingerprint
      )
      dbRaw.close()

      const reconnectConn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })

      await expect(reconnectConn.waitForAuthorization()).rejects.toThrowError()
      reconnectConn.destroy()
    })

    it('(72) Cross-Server: membro de outro servidor transplantado para banco do Server B é rejeitado no reconnect', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // Admite B no Server A
      const { encoded: inviteToken } = await serverFixtureA.storage.createLocalServerInvite(
        serverFixtureA.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandleA = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixtureA.storage,
        localStorageId: serverFixtureA.storageId,
        serverId: serverFixtureA.serverId,
        serverPublicKey: serverFixtureA.publicKey,
        serverPrivateKey: serverFixtureA.privateKey
      })
      activeServers.push(serverHandleA)

      const connA = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandleA.port },
        expectedServerId: serverFixtureA.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      await connA.waitForAdmission()
      connA.destroy()

      // Copia a row e o certificado de A para o banco do Server B
      const dbPathA = join(serverFixtureA.userDataDir, 'servers', serverFixtureA.storageId, DATABASE_FILE_NAME)
      const dbPathB = join(serverFixtureB.userDataDir, 'servers', serverFixtureB.storageId, DATABASE_FILE_NAME)

      const dbA = new DatabaseSync(dbPathA)
      const certA = dbA.prepare('SELECT * FROM member_certificates WHERE device_fingerprint = ?;').get(clientFixture.fingerprint) as {
        device_fingerprint: string
        certificate_version: number
        admission_invite_id: string
        signature: Uint8Array
      }
      dbA.close()

      const dbB = new DatabaseSync(dbPathB)
      dbB.prepare('INSERT INTO members (device_fingerprint, device_public_key) VALUES (?, ?);').run(
        clientFixture.fingerprint,
        clientFixture.publicKey
      )
      dbB.prepare('INSERT INTO member_certificates (device_fingerprint, certificate_version, admission_invite_id, signature) VALUES (?, ?, ?, ?);').run(
        certA.device_fingerprint,
        certA.certificate_version,
        certA.admission_invite_id,
        certA.signature
      )
      dbB.close()

      // Inicia Server B e tenta reconectar
      const serverHandleB = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixtureB.storage,
        localStorageId: serverFixtureB.storageId,
        serverId: serverFixtureB.serverId,
        serverPublicKey: serverFixtureB.publicKey,
        serverPrivateKey: serverFixtureB.privateKey
      })
      activeServers.push(serverHandleB)

      const connB = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandleB.port },
        expectedServerId: serverFixtureB.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })

      // Rejeitado por violação de serverId binding na assinatura do certificado
      await expect(connB.waitForAuthorization()).rejects.toThrowError()
      connB.destroy()
    })
  })

  describe('integração LAN Discovery e recarga de processo (testes 89, 90, 91)', () => {
    it('(89) fluxo integrado: LAN Discovery direcionada -> Direct TCP -> Handshake -> Reconnect sem invite', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // Admite primeiro
      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const responder = await startLanDiscoveryResponder({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        boundHandles: [serverHandle],
        bindAddress: '127.0.0.1',
        port: 45555,
        allowLoopbackForTesting: true
      })
      activeResponders.push(responder)

      // Admissão
      const firstConn = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      await firstConn.waitForAdmission()
      firstConn.destroy()

      // Descoberta via UDP
      const discovered = await discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        port: 45555,
        targetUnicastAddress: '127.0.0.1',
        allowLoopbackForTesting: true
      })

      const targetEndpoint = discovered.endpoints[0]!

      // Reconexão ao endpoint descoberto SEM INVITE
      const reconnectConn = connectLanTcpPeer({
        endpoint: targetEndpoint,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })

      const res = await reconnectConn.waitForAuthorization()
      expect(res.status).toBe('authorized')
      expect(reconnectConn.getState()).toBe('MEMBER_CONNECTED')
      reconnectConn.destroy()
    })

    it('(90) recarga do servidor a partir do disco persiste e valida autorização na reconexão', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // Admite
      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandle1 = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      const port1 = serverHandle1.port

      const conn1 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: port1 },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      await conn1.waitForAdmission()
      conn1.destroy()
      await serverHandle1.close()

      // Reinicia novo listener com novo storage instance recarregando do disco
      const reloadedStorage = createLocalServerStorage(
        serverFixture.userDataDir,
        serverFixture.fakeSecureStorage.storage,
        serverFixture.ownerDevice
      )

      const serverHandle2 = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: reloadedStorage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle2)

      const conn2 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle2.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })

      const res = await conn2.waitForAuthorization()
      expect(res.status).toBe('authorized')
      conn2.destroy()
    })

    it('(91) validação ocorre em cada nova conexão: alteração no banco invalida reconexão subsequente', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 1 }
      )

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      // 1. Primeira admissão
      const conn1 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      await conn1.waitForAdmission()
      conn1.destroy()

      // 2. Primeira reconexão -> Sucesso
      const conn2 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })
      const res2 = await conn2.waitForAuthorization()
      expect(res2.status).toBe('authorized')
      conn2.destroy()

      // 3. Corrompe o certificado no banco
      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const db = new DatabaseSync(dbPath)
      db.prepare('DELETE FROM member_certificates WHERE device_fingerprint = ?;').run(clientFixture.fingerprint)
      db.close()

      // 4. Segunda reconexão -> Falha fechada (sem cache inseguro)
      const conn3 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        authorizationMode: 'reconnect'
      })
      await expect(conn3.waitForAuthorization()).rejects.toThrowError()
      conn3.destroy()
    })

    it('(86 e 87) regressão de admissão: first-time device e ALREADY_MEMBER continuam funcionando normalmente', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        { expiresAt: 2000000000, maxUses: 2 }
      )

      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      // 1. Primeira admissão com invite
      const conn1 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })
      const res1 = await conn1.waitForAdmission()
      expect(res1.status).toBe('admitted')
      conn1.destroy()

      // 2. Reapresentação do mesmo invite pelo Admission Protocol legado -> already_member sem erro
      const conn2 = connectLanTcpPeer({
        endpoint: { family: 4, address: '127.0.0.1', port: serverHandle.port },
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken,
        authorizationMode: 'admission'
      })
      const res2 = await conn2.waitForAdmission()
      expect(res2.status).toBe('already_member')
      conn2.destroy()
    })
  })
})

function createClientFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const fingerprint = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
  return {
    fingerprint,
    publicKey,
    privateKey: keyPair.privateKey
  }
}

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-reconnect-'))
  testRoots.push(root)

  const fakeSecureStorage = createFakeSecureStorage()
  const ownerKeyPair = generateKeyPairSync('ed25519')
  const ownerPublicKey = Buffer.from(ownerKeyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const ownerFingerprint = `sha256:${createHash('sha256').update(ownerPublicKey).digest('hex')}`

  const ownerDevice = createAuthenticatedCandidateDevice(ownerFingerprint, ownerPublicKey)

  let idCounter = 1
  const storage = createLocalServerStorage(root, fakeSecureStorage.storage, ownerDevice, {
    platform: 'win32',
    generateStorageId: () => (idCounter++).toString(16).padStart(32, '0')
  })

  const server = await storage.createLocalServer('Servidor Reconnect Teste')

  const serverKeyPair = fakeSecureStorage.lastGeneratedServerKey
  if (!serverKeyPair) {
    throw new Error('Chave do servidor não encontrada')
  }

  return {
    storage,
    fakeSecureStorage,
    userDataDir: root,
    storageId: server.localStorageId,
    serverId: server.serverId,
    publicKey: server.identity.publicKey,
    privateKey: serverKeyPair,
    ownerDevice,
    ownerPrivateKey: ownerKeyPair.privateKey
  }
}

function createFakeSecureStorage() {
  const plaintextByCiphertext = new Map<string, string>()
  let encryptionCount = 0
  let lastKey: KeyObject | undefined

  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (plaintext: string) => {
        encryptionCount += 1
        const ciphertext = `server-protected:${encryptionCount}`
        plaintextByCiphertext.set(ciphertext, plaintext)

        try {
          const derBuffer = Buffer.from(plaintext, 'base64')
          lastKey = createPrivateKey({ key: derBuffer, format: 'der', type: 'pkcs8' })
        } catch {
          lastKey = undefined
        }

        return Buffer.from(ciphertext)
      },
      decryptString: (encrypted: Buffer) => {
        const plaintext = plaintextByCiphertext.get(encrypted.toString('utf8'))
        if (!plaintext) throw new Error('Ciphertext inválido')
        return plaintext
      }
    },
    get lastGeneratedServerKey() {
      return lastKey
    }
  }
}
