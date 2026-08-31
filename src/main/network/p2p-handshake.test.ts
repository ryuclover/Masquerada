import { createHash, generateKeyPairSync, sign } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  isAuthenticatedCandidateDevice,
  isAuthenticatedServerIdentity
} from '../security/authenticated-candidate'
import {
  decodeSingleProtocolFrame,
  ProtocolFrameType
} from './protocol-frame'
import {
  ClientHandshake,
  decodeClientHello,
  decodeHandshakeFrame,
  decodeServerProof,
  encodeClientHello,
  encodeClientProof,
  encodeHandshakeFrame,
  encodeServerProof,
  type HandshakeErrorCode,
  HANDSHAKE_VERSION,
  ServerHandshake
} from './p2p-handshake'

describe('handshake criptográfico mútuo e autenticação P2P em memória', () => {
  describe('fluxo completo e autenticação mútua bem-sucedida', () => {
    it('executa handshake completo e produz identidades autenticadas e transcript hashes idênticos', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const server = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      // 1. Client -> Server: CLIENT_HELLO
      const clientHello = client.createClientHello()
      expect(client.getState()).toBe('WAITING_SERVER_PROOF')

      // 2. Server -> Client: SERVER_PROOF
      const serverProof = server.processClientHello(clientHello)
      expect(server.getState()).toBe('WAITING_CLIENT_PROOF')

      // 3. Client -> Server: CLIENT_PROOF
      const clientProof = client.processServerProof(serverProof)
      expect(client.getState()).toBe('WAITING_SERVER_FINISH')

      // 4. Server -> Client: SERVER_FINISH
      const serverResult = server.processClientProof(clientProof)
      expect(server.getState()).toBe('ESTABLISHED')
      expect(isAuthenticatedCandidateDevice(serverResult.candidate)).toBe(true)
      expect(serverResult.candidate.fingerprint).toBe(clientFixture.fingerprint)
      expect(serverResult.candidate.publicKey).toEqual(clientFixture.publicKey)

      // 5. Client finaliza com SERVER_FINISH
      const clientResult = client.processServerFinish(serverResult.finishMessage)
      expect(client.getState()).toBe('ESTABLISHED')
      expect(isAuthenticatedServerIdentity(clientResult.server)).toBe(true)
      expect(clientResult.server.serverId).toBe(serverFixture.serverId)
      expect(clientResult.server.publicKey).toEqual(serverFixture.publicKey)

      // 6. Verificação de transcript hash idêntico em ambos os lados
      expect(clientResult.transcriptHash.length).toBe(32)
      expect(clientResult.transcriptHash).toEqual(serverResult.transcriptHash)
    })

    it('gera nonces e transcript hashes distintos para handshakes sucessivos', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const runHandshake = () => {
        const client = new ClientHandshake({
          expectedServerId: serverFixture.serverId,
          deviceFingerprint: clientFixture.fingerprint,
          devicePublicKey: clientFixture.publicKey,
          devicePrivateKey: clientFixture.privateKey
        })
        const server = new ServerHandshake({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey
        })

        const hello = client.createClientHello()
        const proof = server.processClientHello(hello)
        const clientProof = client.processServerProof(proof)
        const serverRes = server.processClientProof(clientProof)
        const clientRes = client.processServerFinish(serverRes.finishMessage)

        return { clientHash: clientRes.transcriptHash, serverHash: serverRes.transcriptHash }
      }

      const run1 = runHandshake()
      const run2 = runHandshake()

      expect(run1.clientHash).toEqual(run1.serverHash)
      expect(run2.clientHash).toEqual(run2.serverHash)
      expect(run1.clientHash).not.toEqual(run2.clientHash)
    })

    it('integra perfeitamente com o framing ProtocolFrameType.HANDSHAKE', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const clientHello = client.createClientHello()
      const frameBuffer = encodeHandshakeFrame(clientHello)

      const protocolFrame = decodeSingleProtocolFrame(frameBuffer)
      expect(protocolFrame.type).toBe(ProtocolFrameType.HANDSHAKE)

      const extractedPayload = decodeHandshakeFrame(protocolFrame)
      expect(extractedPayload).toEqual(clientHello)
    })
  })

  describe('state machines e mensagens fora de ordem', () => {
    it('rejeita Client Proof entregue antes de Server Proof', () => {
      const clientFixture = createClientFixture()
      const serverFixture = createServerFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      // Inicia estado WAITING_SERVER_PROOF
      client.createClientHello()

      const fakeClientProof = encodeClientProof({
        handshakeVersion: HANDSHAKE_VERSION,
        clientSignature: Buffer.alloc(64)
      })

      expectHandshakeError(() => client.processServerProof(fakeClientProof), 'HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED')
      expect(client.getState()).toBe('FAILED')
    })

    it('rejeita chamadas repetidas após ESTABLISHED ou FAILED', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })
      const server = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const hello = client.createClientHello()
      const proof = server.processClientHello(hello)
      const clientProof = client.processServerProof(proof)
      const serverRes = server.processClientProof(clientProof)
      client.processServerFinish(serverRes.finishMessage)

      expect(client.getState()).toBe('ESTABLISHED')
      expect(server.getState()).toBe('ESTABLISHED')

      // Tentativa de reuso após ESTABLISHED
      expectHandshakeError(() => client.createClientHello(), 'HANDSHAKE_STATE_INVALID')
      expectHandshakeError(() => server.processClientHello(hello), 'HANDSHAKE_STATE_INVALID')
    })
  })

  describe('testes negativos e validações criptográficas', () => {
    it('rejeita conexão quando serverId esperado diverge do servidor que respondeu', () => {
      const serverA = createServerFixture()
      const serverB = createServerFixture()
      const clientFixture = createClientFixture()

      // Cliente espera Server A
      const client = new ClientHandshake({
        expectedServerId: serverA.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      // Servidor B responde
      const serverBInstance = new ServerHandshake({
        serverId: serverB.serverId,
        serverPublicKey: serverB.publicKey,
        serverPrivateKey: serverB.privateKey
      })

      const hello = client.createClientHello()
      // Server B rejeita porque expectedServerId é diferente de serverB.serverId
      expectHandshakeError(() => serverBInstance.processClientHello(hello), 'HANDSHAKE_SERVER_ID_MISMATCH')
      expect(serverBInstance.getState()).toBe('FAILED')
    })

    it('rejeita Server Proof se a assinatura do servidor for adulterada', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const server = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const hello = client.createClientHello()
      const proof = server.processClientHello(hello)

      // Adultera 1 bit da assinatura do servidor (último byte)
      proof[proof.length - 1] = (proof[proof.length - 1] ?? 0) ^ 0x01

      expectHandshakeError(() => client.processServerProof(proof), 'HANDSHAKE_SERVER_PROOF_INVALID')
      expect(client.getState()).toBe('FAILED')
    })

    it('rejeita Client Proof se a assinatura do cliente for adulterada', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const server = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const hello = client.createClientHello()
      const proof = server.processClientHello(hello)
      const clientProof = client.processServerProof(proof)

      // Adultera 1 bit da assinatura do cliente
      clientProof[clientProof.length - 1] = (clientProof[clientProof.length - 1] ?? 0) ^ 0x01

      expectHandshakeError(() => server.processClientProof(clientProof), 'HANDSHAKE_CLIENT_PROOF_INVALID')
      expect(server.getState()).toBe('FAILED')
    })

    it('rejeita Server Finish se a assinatura de finalização for adulterada', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const server = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const hello = client.createClientHello()
      const proof = server.processClientHello(hello)
      const clientProof = client.processServerProof(proof)
      const serverRes = server.processClientProof(clientProof)

      // Adultera 1 bit do finish message
      serverRes.finishMessage[serverRes.finishMessage.length - 1] =
        (serverRes.finishMessage[serverRes.finishMessage.length - 1] ?? 0) ^ 0x01

      expectHandshakeError(() => client.processServerFinish(serverRes.finishMessage), 'HANDSHAKE_SERVER_FINISH_INVALID')
      expect(client.getState()).toBe('FAILED')
    })
  })

  describe('proteção contra replay e tampering', () => {
    it('rejeita replay de Server Proof antigo em um novo handshake com novo clientNonce', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      // Handshake 1
      const client1 = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })
      const server = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const hello1 = client1.createClientHello()
      const proof1 = server.processClientHello(hello1)

      // Handshake 2 com novo clientNonce
      const client2 = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })
      client2.createClientHello()

      // Tenta alimentar proof1 capturado no client2
      expectHandshakeError(() => client2.processServerProof(proof1), 'HANDSHAKE_SERVER_PROOF_INVALID')
      expect(client2.getState()).toBe('FAILED')
    })

    it('rejeita replay de Client Proof antiga contra novo serverNonce', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client1 = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })
      const server1 = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const hello1 = client1.createClientHello()
      const proof1 = server1.processClientHello(hello1)
      const clientProof1 = client1.processServerProof(proof1)

      // Nova tentativa de handshake no servidor
      const server2 = new ServerHandshake({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      server2.processClientHello(hello1)

      // Apresenta clientProof1 antiga no server2 (que tem um novo serverNonce)
      expectHandshakeError(() => server2.processClientProof(clientProof1), 'HANDSHAKE_CLIENT_PROOF_INVALID')
      expect(server2.getState()).toBe('FAILED')
    })
  })

  describe('domain separation e segurança contra assinaturas cruzadas', () => {
    it('rejeita prova gerada com domínio cruzado diferente de SERVER_PROOF_DOMAIN', () => {
      const serverFixture = createServerFixture()
      const clientFixture = createClientFixture()

      const client = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      client.createClientHello()

      // Assinatura gerada sob domínio de device-auth ou client-proof
      const fakeSignature = sign(null, Buffer.from('some-data'), serverFixture.privateKey)
      const fakeProof = encodeServerProof({
        handshakeVersion: HANDSHAKE_VERSION,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverNonce: Buffer.alloc(32, 0x01),
        serverSignature: fakeSignature
      })

      expectHandshakeError(() => client.processServerProof(fakeProof), 'HANDSHAKE_SERVER_PROOF_INVALID')
    })
  })

  describe('validação de decoders e robustez de mensagens', () => {
    it('rejeita decodificação de ClientHello com handshakeVersion desconhecida', () => {
      const helloBuffer = encodeClientHello({
        handshakeVersion: 99 as unknown as number,
        expectedServerId: 'sha256:' + 'a'.repeat(64),
        candidateFingerprint: 'sha256:' + 'b'.repeat(64),
        candidatePublicKey: Buffer.alloc(44),
        clientNonce: Buffer.alloc(32)
      })

      expectHandshakeError(() => decodeClientHello(helloBuffer), 'HANDSHAKE_VERSION_UNSUPPORTED')
    })

    it('rejeita decodificação de ServerProof com discriminator incorreto', () => {
      const buffer = Buffer.alloc(150)
      buffer.writeUInt8(0x99, 0) // Invalid discriminator
      buffer.writeUInt8(HANDSHAKE_VERSION, 1)

      expectHandshakeError(() => decodeServerProof(buffer), 'HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED')
    })
  })
})

function createClientFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const fingerprint = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`

  return {
    publicKey,
    privateKey: keyPair.privateKey,
    fingerprint
  }
}

function createServerFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const serverId = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`

  return {
    publicKey,
    privateKey: keyPair.privateKey,
    serverId
  }
}

function expectHandshakeError(
  operation: () => unknown,
  code: HandshakeErrorCode
): void {
  expect(operation).toThrowError(
    expect.objectContaining({
      name: 'HandshakeError',
      code
    })
  )
}
