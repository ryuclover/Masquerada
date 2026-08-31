import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  type EstablishedClientHandshakeContext,
  type EstablishedServerHandshakeContext
} from '../security/authenticated-candidate'
import {
  ClientHandshake,
  ServerHandshake
} from './p2p-handshake'
import {
  ClientSessionSetup,
  decodeClientKeyShare,
  decodeKeyConfirmMessage,
  decodeKeyExchangeFrame,
  decodeServerKeyShare,
  decodeSessionFrame,
  decodeSessionPayload,
  encodeClientKeyShare,
  encodeKeyExchangeFrame,
  encodeSessionFrame,
  isSecureSession,
  KeyExchangeMessageType,
  MAX_SESSION_PLAINTEXT_BYTES,
  SecureSession,
  ServerSessionSetup,
  SESSION_SETUP_VERSION,
  type SessionErrorCode
} from './p2p-session'
import { ProtocolFrameType } from './protocol-frame'

describe('acordo de chaves efêmero e sessão segura P2P em memória', () => {
  describe('estabelecimento completo de sessão e confirmação mútua', () => {
    it('estabelece SecureSession bidirecional autenticada e confidencial', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()

      const clientSetup = new ClientSessionSetup(clientContext)
      const serverSetup = new ServerSessionSetup(serverContext)

      // 1. Client -> Server: CLIENT_KEY_SHARE
      const clientKeyShare = clientSetup.createClientKeyShare()
      expect(clientSetup.getState()).toBe('WAITING_SERVER_KEY_SHARE')

      // 2. Server -> Client: SERVER_KEY_SHARE
      const serverKeyShare = serverSetup.processClientKeyShare(clientKeyShare)
      expect(serverSetup.getState()).toBe('WAITING_CLIENT_KEY_CONFIRM')

      // 3. Client -> Server: CLIENT_KEY_CONFIRM
      const clientKeyConfirm = clientSetup.processServerKeyShare(serverKeyShare)
      expect(clientSetup.getState()).toBe('WAITING_SERVER_KEY_CONFIRM')

      // 4. Server -> Client: SERVER_KEY_CONFIRM e Server SecureSession
      const { serverKeyConfirm, session: serverSession } =
        serverSetup.processClientKeyConfirm(clientKeyConfirm)
      expect(serverSetup.getState()).toBe('ESTABLISHED')
      expect(isSecureSession(serverSession)).toBe(true)

      // 5. Client processa SERVER_KEY_CONFIRM e produz Client SecureSession
      const clientSession = clientSetup.processServerKeyConfirm(serverKeyConfirm)
      expect(clientSetup.getState()).toBe('ESTABLISHED')
      expect(isSecureSession(clientSession)).toBe(true)

      // Ambos derivam exatamente o mesmo sessionId de 32 bytes
      expect(clientSession.sessionId).toEqual(serverSession.sessionId)
      expect(clientSession.sessionId).toHaveLength(32)

      // Teste de tráfego de aplicação Client -> Server
      const clientMsg = Buffer.from('Mensagem confidencial do Cliente para o Servidor', 'utf8')
      const encryptedC2S = clientSession.encrypt(clientMsg)
      const decryptedAtServer = serverSession.decrypt(encryptedC2S)
      expect(decryptedAtServer.toString('utf8')).toBe(clientMsg.toString('utf8'))

      // Teste de tráfego de aplicação Server -> Client
      const serverMsg = Buffer.from('Resposta confidencial do Servidor para o Cliente', 'utf8')
      const encryptedS2C = serverSession.encrypt(serverMsg)
      const decryptedAtClient = clientSession.decrypt(encryptedS2C)
      expect(decryptedAtClient.toString('utf8')).toBe(serverMsg.toString('utf8'))
    })

    it('gera sessionIds e chaves efêmeras distintas para sessões independentes', () => {
      const pair1 = createEstablishedHandshakePair()
      const pair2 = createEstablishedHandshakePair()

      const s1 = establishTestSessions(pair1.clientContext, pair1.serverContext)
      const s2 = establishTestSessions(pair2.clientContext, pair2.serverContext)

      expect(s1.clientSession.sessionId).not.toEqual(s2.clientSession.sessionId)
    })

    it('permite envio de payload vazio e de payload no limite máximo (MAX_SESSION_PLAINTEXT_BYTES)', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      // Payload vazio
      const empty = Buffer.alloc(0)
      const encEmpty = clientSession.encrypt(empty)
      expect(serverSession.decrypt(encEmpty)).toEqual(empty)

      // Payload máximo
      const maxPayload = Buffer.alloc(MAX_SESSION_PLAINTEXT_BYTES, 0x42)
      const encMax = clientSession.encrypt(maxPayload)
      expect(serverSession.decrypt(encMax)).toEqual(maxPayload)
    })

    it('integra corretamente com os tipos de frame ProtocolFrameType.KEY_EXCHANGE e SESSION', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const clientSetup = new ClientSessionSetup(clientContext)
      const serverSetup = new ServerSessionSetup(serverContext)

      const clientShare = clientSetup.createClientKeyShare()
      const keyExchangeFrame = encodeKeyExchangeFrame(clientShare)
      expect(decodeKeyExchangeFrame(decodeSessionOrExchangeFrame(keyExchangeFrame, ProtocolFrameType.KEY_EXCHANGE))).toEqual(clientShare)

      const serverShare = serverSetup.processClientKeyShare(clientShare)
      const clientConfirm = clientSetup.processServerKeyShare(serverShare)
      const { serverKeyConfirm, session: serverSession } = serverSetup.processClientKeyConfirm(clientConfirm)
      const clientSession = clientSetup.processServerKeyConfirm(serverKeyConfirm)

      const payload = Buffer.from('Dados de Sessão', 'utf8')
      const encrypted = clientSession.encrypt(payload)
      const sessionFrame = encodeSessionFrame(encrypted)

      const extractedPayload = decodeSessionFrame(
        decodeSessionOrExchangeFrame(sessionFrame, ProtocolFrameType.SESSION)
      )
      expect(serverSession.decrypt(extractedPayload)).toEqual(payload)
    })
  })

  describe('separação direcional de chaves e defesa contra reflexão', () => {
    it('produz ciphertexts diferentes para o mesmo plaintext e sequence nas direções opostas', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const plaintext = Buffer.from('Mensagem idêntica', 'utf8')
      const c2s = clientSession.encrypt(plaintext) // Sequence 1 Client -> Server
      const s2c = serverSession.encrypt(plaintext) // Sequence 1 Server -> Client

      expect(c2s).not.toEqual(s2c)

      // Tentativa de reflexão: entregar c2s (gerado por C->S) para o próprio cliente decriptar (espera S->C)
      expectSessionError(() => clientSession.decrypt(c2s), 'SESSION_AUTHENTICATION_FAILED')
    })
  })

  describe('proteção contra tampering e validação de key shares', () => {
    it('rejeita Client Key Share se a assinatura Ed25519 for adulterada', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const clientSetup = new ClientSessionSetup(clientContext)
      const serverSetup = new ServerSessionSetup(serverContext)

      const share = clientSetup.createClientKeyShare()
      // Adultera 1 bit da assinatura (último byte)
      share[share.length - 1] = (share[share.length - 1] ?? 0) ^ 0x01

      expectSessionError(() => serverSetup.processClientKeyShare(share), 'SESSION_SIGNATURE_INVALID')
      expect(serverSetup.getState()).toBe('FAILED')
    })

    it('rejeita Server Key Share se a assinatura Ed25519 for adulterada', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const clientSetup = new ClientSessionSetup(clientContext)
      const serverSetup = new ServerSessionSetup(serverContext)

      const clientShare = clientSetup.createClientKeyShare()
      const serverShare = serverSetup.processClientKeyShare(clientShare)
      // Adultera assinatura do servidor
      serverShare[serverShare.length - 1] = (serverShare[serverShare.length - 1] ?? 0) ^ 0x01

      expectSessionError(() => clientSetup.processServerKeyShare(serverShare), 'SESSION_SIGNATURE_INVALID')
      expect(clientSetup.getState()).toBe('FAILED')
    })

    it('rejeita Client Key Share capturado de outra sessão com transcriptHash diferente', () => {
      const pairA = createEstablishedHandshakePair()
      const pairB = createEstablishedHandshakePair()

      const clientSetupA = new ClientSessionSetup(pairA.clientContext)
      const serverSetupB = new ServerSessionSetup(pairB.serverContext)

      const shareFromA = clientSetupA.createClientKeyShare()

      expectSessionError(() => serverSetupB.processClientKeyShare(shareFromA), 'SESSION_SIGNATURE_INVALID')
      expect(serverSetupB.getState()).toBe('FAILED')
    })

    it('rejeita chave pública efêmera malformada ou que não seja X25519', () => {
      const { serverContext } = createEstablishedHandshakePair()
      const serverSetup = new ServerSessionSetup(serverContext)

      // Chave Ed25519 passada onde se esperava X25519
      const edKeyPair = generateKeyPairSync('ed25519')
      const edPublicKey = Buffer.from(edKeyPair.publicKey.export({ format: 'der', type: 'spki' }))

      const fakeShare = encodeClientKeyShare({
        sessionSetupVersion: SESSION_SETUP_VERSION,
        clientEphemeralPublicKey: edPublicKey,
        clientKeyShareSignature: Buffer.alloc(64)
      })

      expectSessionError(() => serverSetup.processClientKeyShare(fakeShare), 'SESSION_KEY_SHARE_INVALID')
    })
  })

  describe('validação de confirmação de chaves e AEAD', () => {
    it('rejeita Client Key Confirm adulterado', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const clientSetup = new ClientSessionSetup(clientContext)
      const serverSetup = new ServerSessionSetup(serverContext)

      const clientShare = clientSetup.createClientKeyShare()
      const serverShare = serverSetup.processClientKeyShare(clientShare)
      const clientConfirm = clientSetup.processServerKeyShare(serverShare)

      // Adultera 1 bit da tag de autenticação de confirmação
      clientConfirm[clientConfirm.length - 1] = (clientConfirm[clientConfirm.length - 1] ?? 0) ^ 0x01

      expectSessionError(() => serverSetup.processClientKeyConfirm(clientConfirm), 'SESSION_CONFIRMATION_INVALID')
      expect(serverSetup.getState()).toBe('FAILED')
    })

    it('rejeita Server Key Confirm adulterado', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const clientSetup = new ClientSessionSetup(clientContext)
      const serverSetup = new ServerSessionSetup(serverContext)

      const clientShare = clientSetup.createClientKeyShare()
      const serverShare = serverSetup.processClientKeyShare(clientShare)
      const clientConfirm = clientSetup.processServerKeyShare(serverShare)
      const { serverKeyConfirm } = serverSetup.processClientKeyConfirm(clientConfirm)

      serverKeyConfirm[serverKeyConfirm.length - 1] = (serverKeyConfirm[serverKeyConfirm.length - 1] ?? 0) ^ 0x01

      expectSessionError(() => clientSetup.processServerKeyConfirm(serverKeyConfirm), 'SESSION_CONFIRMATION_INVALID')
      expect(clientSetup.getState()).toBe('FAILED')
    })

    it('rejeita payload de sessão com 1 bit de ciphertext adulterado', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const encrypted = clientSession.encrypt(Buffer.from('Dados Importantes', 'utf8'))
      // Adultera 1 byte do ciphertext (está no meio antes da tag de 16 bytes)
      encrypted[10] = (encrypted[10] ?? 0) ^ 0x01

      expectSessionError(() => serverSession.decrypt(encrypted), 'SESSION_AUTHENTICATION_FAILED')
      expect(serverSession.isDestroyed()).toBe(true)
    })

    it('rejeita payload de sessão com 1 bit de auth tag adulterado', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const encrypted = clientSession.encrypt(Buffer.from('Dados Importantes', 'utf8'))
      encrypted[encrypted.length - 1] = (encrypted[encrypted.length - 1] ?? 0) ^ 0x01

      expectSessionError(() => serverSession.decrypt(encrypted), 'SESSION_AUTHENTICATION_FAILED')
      expect(serverSession.isDestroyed()).toBe(true)
    })
  })

  describe('política estrita de sequência, replay, gap e reorder', () => {
    it('aceita sequências estritamente crescentes (1, 2, 3)', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const f1 = clientSession.encrypt(Buffer.from('Mensagem 1', 'utf8'))
      const f2 = clientSession.encrypt(Buffer.from('Mensagem 2', 'utf8'))
      const f3 = clientSession.encrypt(Buffer.from('Mensagem 3', 'utf8'))

      expect(serverSession.decrypt(f1).toString('utf8')).toBe('Mensagem 1')
      expect(serverSession.decrypt(f2).toString('utf8')).toBe('Mensagem 2')
      expect(serverSession.decrypt(f3).toString('utf8')).toBe('Mensagem 3')
    })

    it('rejeita replay do mesmo frame (duplicata de sequence 1)', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const f1 = clientSession.encrypt(Buffer.from('Mensagem 1', 'utf8'))
      serverSession.decrypt(f1)

      // Replay de f1
      expectSessionError(() => serverSession.decrypt(f1), 'SESSION_SEQUENCE_VIOLATION')
      expect(serverSession.isDestroyed()).toBe(true)
    })

    it('rejeita lacuna de sequência (gap: recebe 1 e depois 3 sem 2)', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const f1 = clientSession.encrypt(Buffer.from('Mensagem 1', 'utf8'))
      clientSession.encrypt(Buffer.from('Mensagem 2 (perdido)', 'utf8'))
      const f3 = clientSession.encrypt(Buffer.from('Mensagem 3', 'utf8'))

      serverSession.decrypt(f1)
      expectSessionError(() => serverSession.decrypt(f3), 'SESSION_SEQUENCE_VIOLATION')
      expect(serverSession.isDestroyed()).toBe(true)
    })

    it('rejeita reordenação de sequência (reorder: recebe 2 antes de 1)', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      clientSession.encrypt(Buffer.from('Mensagem 1', 'utf8'))
      const f2 = clientSession.encrypt(Buffer.from('Mensagem 2', 'utf8'))

      expectSessionError(() => serverSession.decrypt(f2), 'SESSION_SEQUENCE_VIOLATION')
      expect(serverSession.isDestroyed()).toBe(true)
    })

    it('rejeita cross-session replay (frame de Session A entregue na Session B)', () => {
      const pairA = createEstablishedHandshakePair()
      const pairB = createEstablishedHandshakePair()

      const sA = establishTestSessions(pairA.clientContext, pairA.serverContext)
      const sB = establishTestSessions(pairB.clientContext, pairB.serverContext)

      const frameFromA = sA.clientSession.encrypt(Buffer.from('Segredo A', 'utf8'))

      expectSessionError(() => sB.serverSession.decrypt(frameFromA), 'SESSION_AUTHENTICATION_FAILED')
      expect(sB.serverSession.isDestroyed()).toBe(true)
    })
  })

  describe('lifecycle, destruição segura e limites', () => {
    it('impede encrypt e decrypt após destroy() explícito', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession } = establishTestSessions(clientContext, serverContext)

      clientSession.destroy()
      expect(clientSession.isDestroyed()).toBe(true)

      expectSessionError(() => clientSession.encrypt(Buffer.from('teste', 'utf8')), 'SESSION_DESTROYED')
      expectSessionError(() => clientSession.decrypt(Buffer.alloc(50)), 'SESSION_DESTROYED')
    })

    it('invalida a sessão permanentemente após qualquer erro de autenticação AEAD', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession, serverSession } = establishTestSessions(clientContext, serverContext)

      const corrupted = clientSession.encrypt(Buffer.from('Msg 1', 'utf8'))
      corrupted[10] = (corrupted[10] ?? 0) ^ 0x01

      expectSessionError(() => serverSession.decrypt(corrupted), 'SESSION_AUTHENTICATION_FAILED')

      // Próxima mensagem legítima subsequente falha fechada com SESSION_DESTROYED
      const legitimate = clientSession.encrypt(Buffer.from('Msg 2', 'utf8'))
      expectSessionError(() => serverSession.decrypt(legitimate), 'SESSION_DESTROYED')
    })

    it('rejeita tentativa de encriptar payload maior que MAX_SESSION_PLAINTEXT_BYTES', () => {
      const { clientContext, serverContext } = createEstablishedHandshakePair()
      const { clientSession } = establishTestSessions(clientContext, serverContext)

      const oversized = Buffer.alloc(MAX_SESSION_PLAINTEXT_BYTES + 1)
      expectSessionError(() => clientSession.encrypt(oversized), 'SESSION_PLAINTEXT_TOO_LARGE')
    })

    it('rejeita inicialização de ClientSessionSetup com contexto forjado ou cast arbitrário', () => {
      const fakeContext = {
        role: 'client',
        transcriptHash: Buffer.alloc(32),
        server: { serverId: 'sha256:' + 'a'.repeat(64), publicKey: Buffer.alloc(44) },
        deviceFingerprint: 'sha256:' + 'b'.repeat(64),
        devicePublicKey: Buffer.alloc(44),
        devicePrivateKey: {} as KeyObject
      } as unknown as EstablishedClientHandshakeContext

      expectSessionError(() => new ClientSessionSetup(fakeContext), 'SESSION_CONTEXT_INVALID')
    })
  })

  describe('robustez contra inputs aleatórios (pseudo-fuzzing determinístico)', () => {
    it('rejeita decodificações de buffers aleatórios ou truncados sem crashar o processo', () => {
      const randomSeed = 0x12345678
      let state = randomSeed

      function nextRandomByte(): number {
        state = (state * 1664525 + 1013904223) >>> 0
        return state & 0xff
      }

      for (let i = 0; i < 50; i++) {
        const len = (nextRandomByte() % 100) + 1
        const buf = Buffer.alloc(len)
        for (let j = 0; j < len; j++) buf[j] = nextRandomByte()

        expect(() => decodeClientKeyShare(buf)).toThrow()
        expect(() => decodeServerKeyShare(buf)).toThrow()
        expect(() => decodeSessionPayload(buf)).toThrow()
        expect(() =>
          decodeKeyConfirmMessage(KeyExchangeMessageType.CLIENT_KEY_CONFIRM, buf)
        ).toThrow()
      }
    })
  })
})

function createEstablishedHandshakePair(): {
  clientContext: EstablishedClientHandshakeContext
  serverContext: EstablishedServerHandshakeContext
} {
  const serverFixture = createServerFixture()
  const clientFixture = createClientFixture()

  const clientHandshake = new ClientHandshake({
    expectedServerId: serverFixture.serverId,
    deviceFingerprint: clientFixture.fingerprint,
    devicePublicKey: clientFixture.publicKey,
    devicePrivateKey: clientFixture.privateKey
  })

  const serverHandshake = new ServerHandshake({
    serverId: serverFixture.serverId,
    serverPublicKey: serverFixture.publicKey,
    serverPrivateKey: serverFixture.privateKey
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

function establishTestSessions(
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

function createServerFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const serverId = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`

  return {
    serverId,
    publicKey,
    privateKey: keyPair.privateKey
  }
}

function decodeSessionOrExchangeFrame(
  frameBuffer: Buffer,
  expectedType: ProtocolFrameType
) {
  // Simples parser de frame para os testes
  const payload = frameBuffer.subarray(12)
  return {
    version: 1 as const,
    type: expectedType,
    flags: 0,
    payloadLength: payload.length,
    payload
  }
}

function expectSessionError(operation: () => unknown, code: SessionErrorCode): void {
  expect(operation).toThrowError(
    expect.objectContaining({
      name: 'SessionError',
      code
    })
  )
}
