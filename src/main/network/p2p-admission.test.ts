import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  createAuthenticatedCandidateDevice,
  type EstablishedClientHandshakeContext,
  type EstablishedServerHandshakeContext
} from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import {
  DATABASE_FILE_NAME,
  listMembers,
  openServerDatabase
} from '../servers/server-database'
import {
  ClientAdmissionFlow,
  decodeAdmissionRequest,
  decodeAdmissionResponse,
  ServerAdmissionHandler
} from './p2p-admission'
import {
  ClientHandshake,
  ServerHandshake
} from './p2p-handshake'
import {
  ClientSessionSetup,
  SecureSession,
  ServerSessionSetup
} from './p2p-session'
import {
  encodeProtocolFrame,
  ProtocolFrameType
} from './protocol-frame'

const testRoots: string[] = []

afterEach(async () => {
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('protocolo seguro de admissão de membros sobre a SecureSession', () => {
  describe('admissão completa ponta-a-ponta em memória', () => {
    it('admite novo membro atomicamente dentro de SecureSession confidencial (single-use)', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // 1. Owner emite convite single-use
      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      // 2. Handshake mútuo em memória
      const { clientContext, serverContext } = performHandshake(
        clientFixture,
        serverFixture
      )

      // 3. Acordo de chaves efêmero X25519 e SecureSession
      const { clientSession, serverSession } = establishSessions(
        clientContext,
        serverContext
      )

      // 4. Client cria ADMISSION_REQUEST cifrado
      const clientAdmission = new ClientAdmissionFlow({
        context: clientContext,
        session: clientSession,
        invite: inviteToken
      })
      const encryptedRequestFrame = clientAdmission.createEncryptedAdmissionRequest()

      // Verifica confidencialidade no frame externo (sem MQR1. e sem o bearer secret em plaintext)
      expect(encryptedRequestFrame.includes(Buffer.from('MQR1.', 'ascii'))).toBe(false)
      const tokenPayloadPart = inviteToken.slice(5) // base64url part
      expect(encryptedRequestFrame.includes(Buffer.from(tokenPayloadPart, 'ascii'))).toBe(false)

      // 5. Server processa requisição cifrada
      const serverAdmission = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext,
        session: serverSession
      })

      const serverResult = await serverAdmission.processEncryptedAdmissionRequest(
        encryptedRequestFrame
      )
      expect(serverResult.status).toBe('admitted')
      expect(serverResult.member?.deviceFingerprint).toBe(clientFixture.fingerprint)

      // 6. Client processa resposta cifrada do servidor
      const clientResult = clientAdmission.processEncryptedAdmissionResponse(
        serverResult.responseFrame
      )
      expect(clientResult.status).toBe('admitted')

      // 7. Confere persistência no SQLite do servidor
      const members = getServerMembers(serverFixture)
      expect(members).toHaveLength(2) // Owner + Client B
      expect(members.some((m) => m.deviceFingerprint === clientFixture.fingerprint)).toBe(true)

      // 8. Novo candidato Device C tenta reutilizar o mesmo convite esgotado em nova sessão
      const candidateC = createClientFixture()
      const { clientContext: ctxC, serverContext: srvCtxC } = performHandshake(
        candidateC,
        serverFixture
      )
      const { clientSession: sessionC, serverSession: srvSessionC } = establishSessions(
        ctxC,
        srvCtxC
      )

      const admissionC = new ClientAdmissionFlow({
        context: ctxC,
        session: sessionC,
        invite: inviteToken
      })
      const reqFrameC = admissionC.createEncryptedAdmissionRequest()

      const srvAdmissionC = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: srvCtxC,
        session: srvSessionC
      })

      const srvResC = await srvAdmissionC.processEncryptedAdmissionRequest(reqFrameC)
      expect(srvResC.status).toBe('rejected')

      const clientResC = admissionC.processEncryptedAdmissionResponse(srvResC.responseFrame)
      expect(clientResC.status).toBe('rejected')

      // O número de membros permanece 2
      const finalMembers = getServerMembers(serverFixture)
      expect(finalMembers).toHaveLength(2)
    })

    it('admite exatamente N dispositivos em convite limited-use (maxUses = 3) e bloqueia o 4º', async () => {
      const serverFixture = await createLocalServerFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 3
        }
      )

      const clientB = createClientFixture()
      const clientC = createClientFixture()
      const clientD = createClientFixture()
      const clientE = createClientFixture()

      // B, C e D são admitidos
      for (const client of [clientB, clientC, clientD]) {
        const { clientContext, serverContext } = performHandshake(client, serverFixture)
        const { clientSession, serverSession } = establishSessions(clientContext, serverContext)

        const clientAdm = new ClientAdmissionFlow({ context: clientContext, session: clientSession, invite: inviteToken })
        const reqFrame = clientAdm.createEncryptedAdmissionRequest()

        const srvAdm = new ServerAdmissionHandler({
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverContext,
          session: serverSession
        })
        const srvRes = await srvAdm.processEncryptedAdmissionRequest(reqFrame)
        expect(srvRes.status).toBe('admitted')
        expect(clientAdm.processEncryptedAdmissionResponse(srvRes.responseFrame).status).toBe('admitted')
      }

      // E tenta admissão e é rejeitado
      const { clientContext: ctxE, serverContext: srvCtxE } = performHandshake(clientE, serverFixture)
      const { clientSession: sessionE, serverSession: srvSessionE } = establishSessions(ctxE, srvCtxE)
      const clientAdmE = new ClientAdmissionFlow({ context: ctxE, session: sessionE, invite: inviteToken })
      const reqFrameE = clientAdmE.createEncryptedAdmissionRequest()
      const srvAdmE = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: srvCtxE,
        session: srvSessionE
      })
      const srvResE = await srvAdmE.processEncryptedAdmissionRequest(reqFrameE)
      expect(srvResE.status).toBe('rejected')
      expect(clientAdmE.processEncryptedAdmissionResponse(srvResE.responseFrame).status).toBe('rejected')

      const members = getServerMembers(serverFixture)
      expect(members).toHaveLength(4) // Owner + B + C + D
    })
  })

  describe('idempotência, membros duplicados e perda de resposta', () => {
    it('retorna already_member e não consome novo uso se um membro já admitido apresentar o convite novamente', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientB = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 3
        }
      )

      // 1. Admissão inicial de B
      const pair1 = performHandshake(clientB, serverFixture)
      const sess1 = establishSessions(pair1.clientContext, pair1.serverContext)
      const adm1 = new ClientAdmissionFlow({ context: pair1.clientContext, session: sess1.clientSession, invite: inviteToken })
      const srvAdm1 = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: pair1.serverContext,
        session: sess1.serverSession
      })
      const res1 = await srvAdm1.processEncryptedAdmissionRequest(adm1.createEncryptedAdmissionRequest())
      expect(res1.status).toBe('admitted')

      // 2. Nova sessão para B com o mesmo convite
      const pair2 = performHandshake(clientB, serverFixture)
      const sess2 = establishSessions(pair2.clientContext, pair2.serverContext)
      const adm2 = new ClientAdmissionFlow({ context: pair2.clientContext, session: sess2.clientSession, invite: inviteToken })
      const srvAdm2 = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: pair2.serverContext,
        session: sess2.serverSession
      })
      const res2 = await srvAdm2.processEncryptedAdmissionRequest(adm2.createEncryptedAdmissionRequest())
      expect(res2.status).toBe('already_member')

      const clientRes2 = adm2.processEncryptedAdmissionResponse(res2.responseFrame)
      expect(clientRes2.status).toBe('already_member')

      // O número de membros continua 2 (não foi duplicado)
      const members = getServerMembers(serverFixture)
      expect(members).toHaveLength(2)
    })

    it('mantém a membership commitada sem rollback se a resposta de rede for perdida', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientB = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      // 1. Sessão 1: commit de admissão é executado com sucesso no server
      const pair1 = performHandshake(clientB, serverFixture)
      const sess1 = establishSessions(pair1.clientContext, pair1.serverContext)
      const adm1 = new ClientAdmissionFlow({ context: pair1.clientContext, session: sess1.clientSession, invite: inviteToken })
      const srvAdm1 = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: pair1.serverContext,
        session: sess1.serverSession
      })
      const res1 = await srvAdm1.processEncryptedAdmissionRequest(adm1.createEncryptedAdmissionRequest())
      expect(res1.status).toBe('admitted')

      // Simulação: res1.responseFrame é descartado e nunca chega ao cliente

      // 2. Cliente tenta reconectar em nova sessão e reenviar o convite
      const pair2 = performHandshake(clientB, serverFixture)
      const sess2 = establishSessions(pair2.clientContext, pair2.serverContext)
      const adm2 = new ClientAdmissionFlow({ context: pair2.clientContext, session: sess2.clientSession, invite: inviteToken })
      const srvAdm2 = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: pair2.serverContext,
        session: sess2.serverSession
      })
      const res2 = await srvAdm2.processEncryptedAdmissionRequest(adm2.createEncryptedAdmissionRequest())
      expect(res2.status).toBe('already_member')

      const clientRes2 = adm2.processEncryptedAdmissionResponse(res2.responseFrame)
      expect(clientRes2.status).toBe('already_member')
    })
  })

  describe('validações de segurança, binding e limites', () => {
    it('rejeita requisições enviadas em frames plaintext que não sejam SESSION (ex: HANDSHAKE)', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientB = createClientFixture()

      const pair = performHandshake(clientB, serverFixture)
      const sess = establishSessions(pair.clientContext, pair.serverContext)

      const srvAdm = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: pair.serverContext,
        session: sess.serverSession
      })

      // Frame HANDSHAKE tentando passar convite em plaintext
      const plaintextFrame = encodeProtocolFrame({
        type: ProtocolFrameType.HANDSHAKE,
        payload: Buffer.from('MQR1.plaintext_token', 'ascii')
      })

      await expect(srvAdm.processEncryptedAdmissionRequest(plaintextFrame)).rejects.toMatchObject({
        name: 'ProtocolError',
        code: 'PROTOCOL_FRAME_TYPE_UNSUPPORTED'
      })
    })

    it('rejeita admissão com convite de outro servidor', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()
      const client = createClientFixture()

      // Convite criado no Server A
      const { encoded: inviteA } = await serverFixtureA.storage.createLocalServerInvite(
        serverFixtureA.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      // Sessão estabelecida com Server B
      const pairB = performHandshake(client, serverFixtureB)
      const sessB = establishSessions(pairB.clientContext, pairB.serverContext)

      const clientAdm = new ClientAdmissionFlow({
        context: pairB.clientContext,
        session: sessB.clientSession,
        invite: inviteA
      })
      const reqFrame = clientAdm.createEncryptedAdmissionRequest()

      const srvAdmB = new ServerAdmissionHandler({
        storage: serverFixtureB.storage,
        localStorageId: serverFixtureB.storageId,
        serverContext: pairB.serverContext,
        session: sessB.serverSession
      })

      const res = await srvAdmB.processEncryptedAdmissionRequest(reqFrame)
      expect(res.status).toBe('rejected')
      expect(clientAdm.processEncryptedAdmissionResponse(res.responseFrame).status).toBe('rejected')
    })

    it('rejeita combinação de ServerContext com LocalServer divergente', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()
      const client = createClientFixture()

      const pairA = performHandshake(client, serverFixtureA)
      const sessA = establishSessions(pairA.clientContext, pairA.serverContext)

      // Tenta acoplar ServerContext do Server A com storageId do Server B
      const invalidHandler = new ServerAdmissionHandler({
        storage: serverFixtureB.storage,
        localStorageId: serverFixtureB.storageId,
        serverContext: pairA.serverContext,
        session: sessA.serverSession
      })

      const clientAdm = new ClientAdmissionFlow({
        context: pairA.clientContext,
        session: sessA.clientSession,
        invite: 'MQR1.dummy'
      })
      const req = clientAdm.createEncryptedAdmissionRequest()

      await expect(invalidHandler.processEncryptedAdmissionRequest(req)).rejects.toMatchObject({
        name: 'AdmissionError',
        code: 'ADMISSION_SERVER_MISMATCH'
      })
    })

    it('rejeita request adulterado por 1 bit com falha AEAD e destrói a sessão', async () => {
      const serverFixture = await createLocalServerFixture()
      const client = createClientFixture()

      const pair = performHandshake(client, serverFixture)
      const sess = establishSessions(pair.clientContext, pair.serverContext)

      const clientAdm = new ClientAdmissionFlow({
        context: pair.clientContext,
        session: sess.clientSession,
        invite: 'MQR1.valid_looking_token'
      })
      const reqFrame = clientAdm.createEncryptedAdmissionRequest()

      // Adultera 1 byte do ciphertext/tag (último byte do frame)
      reqFrame[reqFrame.length - 1] = (reqFrame[reqFrame.length - 1] ?? 0) ^ 0x01

      const srvAdm = new ServerAdmissionHandler({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverContext: pair.serverContext,
        session: sess.serverSession
      })

      await expect(srvAdm.processEncryptedAdmissionRequest(reqFrame)).rejects.toMatchObject({
        name: 'SessionError',
        code: 'SESSION_AUTHENTICATION_FAILED'
      })
      expect(sess.serverSession.isDestroyed()).toBe(true)
    })

    it('rejeita tentativa de instanciar ClientAdmissionFlow com contexto forjado', () => {
      const fakeContext = {
        role: 'client',
        transcriptHash: Buffer.alloc(32),
        server: { serverId: 'sha256:' + 'a'.repeat(64), publicKey: Buffer.alloc(44) },
        deviceFingerprint: 'sha256:' + 'b'.repeat(64),
        devicePublicKey: Buffer.alloc(44),
        devicePrivateKey: {} as KeyObject
      } as unknown as EstablishedClientHandshakeContext

      const fakeSession = new SecureSession({
        role: 'client',
        sessionId: Buffer.alloc(32),
        transcriptHash: Buffer.alloc(32),
        sendKey: Buffer.alloc(32),
        receiveKey: Buffer.alloc(32),
        sendNoncePrefix: Buffer.alloc(4),
        receiveNoncePrefix: Buffer.alloc(4)
      })

      expect(
        () =>
          new ClientAdmissionFlow({
            context: fakeContext,
            session: fakeSession,
            invite: 'MQR1.abc'
          })
      ).toThrowError(expect.objectContaining({ name: 'AdmissionError', code: 'ADMISSION_CONTEXT_INVALID' }))
    })
  })

  describe('robustez de parsing e pseudo-fuzzing determinístico', () => {
    it('rejeita payloads de aplicação malformados sem crashar o processo', () => {
      // Vazio
      expect(() => decodeAdmissionRequest(Buffer.alloc(0))).toThrow()
      // 1 byte
      expect(() => decodeAdmissionRequest(Buffer.from([0x01]))).toThrow()
      // Versão inválida
      expect(() => decodeAdmissionRequest(Buffer.from([0x99, 0x01, 0x00, 0x05, 0x41, 0x42, 0x43, 0x44, 0x45]))).toThrow()
      // Message type inválido
      expect(() => decodeAdmissionRequest(Buffer.from([0x01, 0x99, 0x00, 0x05, 0x41, 0x42, 0x43, 0x44, 0x45]))).toThrow()
      // Prefixo diferente de MQR1.
      expect(() => decodeAdmissionRequest(Buffer.from([0x01, 0x01, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44]))).toThrow()

      // Pseudo fuzzing determinístico
      let state = 0xabcdef12
      function nextByte(): number {
        state = (state * 1664525 + 1013904223) >>> 0
        return state & 0xff
      }

      for (let i = 0; i < 50; i++) {
        const len = (nextByte() % 64) + 1
        const buf = Buffer.alloc(len)
        for (let j = 0; j < len; j++) buf[j] = nextByte()

        expect(() => decodeAdmissionRequest(buf)).toThrow()
        expect(() => decodeAdmissionResponse(buf)).toThrow()
      }
    })
  })
})

function getServerMembers(serverFixture: { userDataDir: string; storageId: string }) {
  const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
  const db = openServerDatabase(dbPath)
  const members = listMembers(db)
  db.close()
  return members
}

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-p2p-admission-'))
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

  const server = await storage.createLocalServer('Servidor Teste Admissão')

  // Obtém chaves do servidor
  const serverKeyPair = fakeSecureStorage.lastGeneratedServerKey
  if (!serverKeyPair) {
    throw new Error('Chave do servidor não encontrada')
  }

  return {
    storage,
    userDataDir: root,
    storageId: server.localStorageId,
    serverId: server.serverId,
    publicKey: server.identity.publicKey,
    privateKey: serverKeyPair
  }
}

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

function performHandshake(
  client: ReturnType<typeof createClientFixture>,
  server: { serverId: string; publicKey: Buffer; privateKey: KeyObject }
): {
  clientContext: EstablishedClientHandshakeContext
  serverContext: EstablishedServerHandshakeContext
} {
  const clientHandshake = new ClientHandshake({
    expectedServerId: server.serverId,
    deviceFingerprint: client.fingerprint,
    devicePublicKey: client.publicKey,
    devicePrivateKey: client.privateKey
  })

  const serverHandshake = new ServerHandshake({
    serverId: server.serverId,
    serverPublicKey: server.publicKey,
    serverPrivateKey: server.privateKey
  })

  const hello = clientHandshake.createClientHello()
  const proof = serverHandshake.processClientHello(hello)
  const clientProof = clientHandshake.processServerProof(proof)
  const serverRes = serverHandshake.processClientProof(clientProof)
  clientHandshake.processServerFinish(serverRes.finishMessage)

  return {
    clientContext: clientHandshake.getEstablishedContext(),
    serverContext: serverHandshake.getEstablishedContext()
  }
}

function establishSessions(
  clientContext: EstablishedClientHandshakeContext,
  serverContext: EstablishedServerHandshakeContext
): {
  clientSession: SecureSession
  serverSession: SecureSession
} {
  const clientSetup = new ClientSessionSetup(clientContext)
  const serverSetup = new ServerSessionSetup(serverContext)

  const clientKeyShare = clientSetup.createClientKeyShare()
  const serverKeyShare = serverSetup.processClientKeyShare(clientKeyShare)
  const clientKeyConfirm = clientSetup.processServerKeyShare(serverKeyShare)
  const { serverKeyConfirm, session: serverSession } =
    serverSetup.processClientKeyConfirm(clientKeyConfirm)
  const clientSession = clientSetup.processServerKeyConfirm(serverKeyConfirm)

  return { clientSession, serverSession }
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

        // Parse key from PKCS8 DER base64
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
