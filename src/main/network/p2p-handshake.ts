import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

import {
  createAuthenticatedCandidateDevice,
  createAuthenticatedServerIdentity,
  createEstablishedClientHandshakeContext,
  createEstablishedServerHandshakeContext,
  type AuthenticatedCandidateDevice,
  type AuthenticatedServerIdentity,
  type EstablishedClientHandshakeContext,
  type EstablishedServerHandshakeContext
} from '../security/authenticated-candidate'
import {
  encodeProtocolFrame,
  ProtocolError,
  ProtocolFrameType,
  PROTOCOL_VERSION,
  type ProtocolFrame
} from './protocol-frame'

export const HANDSHAKE_VERSION = 1
export const NONCE_BYTES = 32
export const SIGNATURE_BYTES = 64
export const MAX_HANDSHAKE_MESSAGE_BYTES = 4096
const MAX_PUBLIC_KEY_BYTES = 256
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/

export const SERVER_PROOF_DOMAIN = 'Masquerada/p2p-handshake/server-proof/v1'
export const CLIENT_PROOF_DOMAIN = 'Masquerada/p2p-handshake/client-proof/v1'
export const SERVER_FINISH_DOMAIN = 'Masquerada/p2p-handshake/server-finish/v1'

export enum HandshakeMessageType {
  CLIENT_HELLO = 0x01,
  SERVER_PROOF = 0x02,
  CLIENT_PROOF = 0x03,
  SERVER_FINISH = 0x04
}

export type HandshakeErrorCode =
  | 'HANDSHAKE_VERSION_UNSUPPORTED'
  | 'HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED'
  | 'HANDSHAKE_MESSAGE_INVALID'
  | 'HANDSHAKE_STATE_INVALID'
  | 'HANDSHAKE_SERVER_ID_MISMATCH'
  | 'HANDSHAKE_SERVER_PROOF_INVALID'
  | 'HANDSHAKE_CLIENT_PROOF_INVALID'
  | 'HANDSHAKE_SERVER_FINISH_INVALID'
  | 'HANDSHAKE_KEY_INVALID'
  | 'HANDSHAKE_FAILED'

const ERROR_MESSAGES: Record<HandshakeErrorCode, string> = {
  HANDSHAKE_VERSION_UNSUPPORTED: 'A versão do handshake não é suportada.',
  HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED: 'O tipo da mensagem de handshake não é suportado.',
  HANDSHAKE_MESSAGE_INVALID: 'A mensagem de handshake recebida é inválida ou está malformada.',
  HANDSHAKE_STATE_INVALID: 'A mensagem de handshake foi recebida em um estado inválido.',
  HANDSHAKE_SERVER_ID_MISMATCH: 'A identidade do servidor não corresponde ao serverId esperado.',
  HANDSHAKE_SERVER_PROOF_INVALID: 'A prova de identidade do servidor é inválida.',
  HANDSHAKE_CLIENT_PROOF_INVALID: 'A prova de identidade do cliente é inválida.',
  HANDSHAKE_SERVER_FINISH_INVALID: 'A confirmação final do servidor é inválida.',
  HANDSHAKE_KEY_INVALID: 'A chave pública apresentada no handshake é inválida.',
  HANDSHAKE_FAILED: 'Ocorreu uma falha na negociação do handshake.'
}

export class HandshakeError extends Error {
  readonly code: HandshakeErrorCode

  constructor(code: HandshakeErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'HandshakeError'
    this.code = code
  }
}

export interface ClientHello {
  readonly handshakeVersion: number
  readonly expectedServerId: string
  readonly candidateFingerprint: string
  readonly candidatePublicKey: Buffer
  readonly clientNonce: Buffer
}

export interface ServerProof {
  readonly handshakeVersion: number
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverNonce: Buffer
  readonly serverSignature: Buffer
}

export interface ClientProof {
  readonly handshakeVersion: number
  readonly clientSignature: Buffer
}

export interface ServerFinish {
  readonly handshakeVersion: number
  readonly serverFinishSignature: Buffer
}

export interface ClientHandshakeOptions {
  readonly expectedServerId: string
  readonly expectedServerPublicKey?: Buffer
  readonly deviceFingerprint: string
  readonly devicePublicKey: Buffer
  readonly devicePrivateKey: KeyObject
}

export interface ServerHandshakeOptions {
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverPrivateKey: KeyObject
}

export class ClientHandshake {
  private state: 'INITIAL' | 'WAITING_SERVER_PROOF' | 'WAITING_SERVER_FINISH' | 'ESTABLISHED' | 'FAILED' = 'INITIAL'
  private readonly expectedServerId: string
  private readonly expectedServerPublicKey?: Buffer
  private readonly deviceFingerprint: string
  private readonly devicePublicKey: Buffer
  private readonly devicePrivateKey: KeyObject

  private clientNonce?: Buffer
  private clientHelloBuffer?: Buffer
  private serverProofBuffer?: Buffer
  private clientProofBuffer?: Buffer
  private serverNonce?: Buffer
  private authenticatedServer?: AuthenticatedServerIdentity
  private establishedContext?: EstablishedClientHandshakeContext

  constructor(options: ClientHandshakeOptions) {
    this.expectedServerId = options.expectedServerId
    this.expectedServerPublicKey = options.expectedServerPublicKey
      ? Buffer.from(options.expectedServerPublicKey)
      : undefined
    this.deviceFingerprint = options.deviceFingerprint
    this.devicePublicKey = validatePublicKeyDer(options.devicePublicKey, options.deviceFingerprint)
    this.devicePrivateKey = options.devicePrivateKey
  }

  createClientHello(): Buffer {
    if (this.state !== 'INITIAL') {
      this.state = 'FAILED'
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }

    try {
      this.clientNonce = randomBytes(NONCE_BYTES)
      const hello: ClientHello = {
        handshakeVersion: HANDSHAKE_VERSION,
        expectedServerId: this.expectedServerId,
        candidateFingerprint: this.deviceFingerprint,
        candidatePublicKey: this.devicePublicKey,
        clientNonce: this.clientNonce
      }

      this.clientHelloBuffer = encodeClientHello(hello)
      this.state = 'WAITING_SERVER_PROOF'
      return this.clientHelloBuffer
    } catch (error) {
      this.state = 'FAILED'
      if (error instanceof HandshakeError) throw error
      throw new HandshakeError('HANDSHAKE_FAILED')
    }
  }

  processServerProof(serverProofBytes: Buffer): Buffer {
    if (this.state !== 'WAITING_SERVER_PROOF' || !this.clientNonce || !this.clientHelloBuffer) {
      this.state = 'FAILED'
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }

    try {
      const serverProof = decodeServerProof(serverProofBytes)
      this.serverProofBuffer = Buffer.from(serverProofBytes)
      this.serverNonce = serverProof.serverNonce

      if (serverProof.serverId !== this.expectedServerId) {
        throw new HandshakeError('HANDSHAKE_SERVER_ID_MISMATCH')
      }

      const canonicalServerKey = validatePublicKeyDer(serverProof.serverPublicKey, serverProof.serverId)
      if (this.expectedServerPublicKey && !canonicalServerKey.equals(this.expectedServerPublicKey)) {
        throw new HandshakeError('HANDSHAKE_SERVER_ID_MISMATCH')
      }

      // Validação da assinatura do Server Proof
      const serverProofDigest = buildServerProofPayload(
        this.expectedServerId,
        this.deviceFingerprint,
        this.devicePublicKey,
        this.clientNonce,
        serverProof.serverId,
        canonicalServerKey,
        serverProof.serverNonce
      )

      const serverKeyObject = createPublicKey({ key: canonicalServerKey, format: 'der', type: 'spki' })
      const isValid = verify(null, serverProofDigest, serverKeyObject, serverProof.serverSignature)

      if (!isValid) {
        throw new HandshakeError('HANDSHAKE_SERVER_PROOF_INVALID')
      }

      this.authenticatedServer = createAuthenticatedServerIdentity(serverProof.serverId, canonicalServerKey)

      // Construção e assinatura do Client Proof
      const clientProofPayload = buildClientProofPayload(
        this.clientHelloBuffer,
        this.serverProofBuffer,
        serverProof.serverNonce,
        this.deviceFingerprint
      )

      const clientSignature = sign(null, clientProofPayload, this.devicePrivateKey)
      const clientProof: ClientProof = {
        handshakeVersion: HANDSHAKE_VERSION,
        clientSignature
      }

      this.clientProofBuffer = encodeClientProof(clientProof)
      this.state = 'WAITING_SERVER_FINISH'
      return this.clientProofBuffer
    } catch (error) {
      this.state = 'FAILED'
      if (error instanceof HandshakeError) throw error
      throw new HandshakeError('HANDSHAKE_FAILED')
    }
  }

  processServerFinish(serverFinishBytes: Buffer): {
    server: AuthenticatedServerIdentity
    transcriptHash: Buffer
    context: EstablishedClientHandshakeContext
  } {
    if (
      this.state !== 'WAITING_SERVER_FINISH' ||
      !this.clientHelloBuffer ||
      !this.serverProofBuffer ||
      !this.clientProofBuffer ||
      !this.authenticatedServer
    ) {
      this.state = 'FAILED'
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }

    try {
      const serverFinish = decodeServerFinish(serverFinishBytes)
      const finishPayload = buildServerFinishPayload(
        this.clientHelloBuffer,
        this.serverProofBuffer,
        this.clientProofBuffer
      )

      const serverKeyObject = createPublicKey({
        key: this.authenticatedServer.publicKey,
        format: 'der',
        type: 'spki'
      })

      const isValid = verify(null, finishPayload, serverKeyObject, serverFinish.serverFinishSignature)
      if (!isValid) {
        throw new HandshakeError('HANDSHAKE_SERVER_FINISH_INVALID')
      }

      const fullTranscript = Buffer.concat([
        this.clientHelloBuffer,
        this.serverProofBuffer,
        this.clientProofBuffer,
        serverFinishBytes
      ])

      const transcriptHash = createHash('sha256').update(fullTranscript).digest()

      this.establishedContext = createEstablishedClientHandshakeContext({
        transcriptHash,
        server: this.authenticatedServer,
        deviceFingerprint: this.deviceFingerprint,
        devicePublicKey: this.devicePublicKey,
        devicePrivateKey: this.devicePrivateKey
      })

      this.state = 'ESTABLISHED'
      return {
        server: this.authenticatedServer,
        transcriptHash,
        context: this.establishedContext
      }
    } catch (error) {
      this.state = 'FAILED'
      if (error instanceof HandshakeError) throw error
      throw new HandshakeError('HANDSHAKE_FAILED')
    }
  }

  getEstablishedContext(): EstablishedClientHandshakeContext {
    if (this.state !== 'ESTABLISHED' || !this.establishedContext) {
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }
    return this.establishedContext
  }

  getState(): string {
    return this.state
  }
}

export class ServerHandshake {
  private state: 'INITIAL' | 'WAITING_CLIENT_PROOF' | 'ESTABLISHED' | 'FAILED' = 'INITIAL'
  private readonly serverId: string
  private readonly serverPublicKey: Buffer
  private readonly serverPrivateKey: KeyObject

  private serverNonce?: Buffer
  private clientHello?: ClientHello
  private clientHelloBuffer?: Buffer
  private serverProofBuffer?: Buffer
  private clientProofBuffer?: Buffer
  private authenticatedCandidate?: AuthenticatedCandidateDevice
  private establishedContext?: EstablishedServerHandshakeContext

  constructor(options: ServerHandshakeOptions) {
    this.serverId = options.serverId
    this.serverPublicKey = validatePublicKeyDer(options.serverPublicKey, options.serverId)
    this.serverPrivateKey = options.serverPrivateKey
  }

  processClientHello(clientHelloBytes: Buffer): Buffer {
    if (this.state !== 'INITIAL') {
      this.state = 'FAILED'
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }

    try {
      this.clientHello = decodeClientHello(clientHelloBytes)
      this.clientHelloBuffer = Buffer.from(clientHelloBytes)

      if (this.clientHello.expectedServerId !== this.serverId) {
        throw new HandshakeError('HANDSHAKE_SERVER_ID_MISMATCH')
      }

      const canonicalCandidateKey = validatePublicKeyDer(
        this.clientHello.candidatePublicKey,
        this.clientHello.candidateFingerprint
      )

      this.serverNonce = randomBytes(NONCE_BYTES)

      const serverProofPayload = buildServerProofPayload(
        this.clientHello.expectedServerId,
        this.clientHello.candidateFingerprint,
        canonicalCandidateKey,
        this.clientHello.clientNonce,
        this.serverId,
        this.serverPublicKey,
        this.serverNonce
      )

      const serverSignature = sign(null, serverProofPayload, this.serverPrivateKey)

      const serverProof: ServerProof = {
        handshakeVersion: HANDSHAKE_VERSION,
        serverId: this.serverId,
        serverPublicKey: this.serverPublicKey,
        serverNonce: this.serverNonce,
        serverSignature
      }

      this.serverProofBuffer = encodeServerProof(serverProof)
      this.state = 'WAITING_CLIENT_PROOF'
      return this.serverProofBuffer
    } catch (error) {
      this.state = 'FAILED'
      if (error instanceof HandshakeError) throw error
      throw new HandshakeError('HANDSHAKE_FAILED')
    }
  }

  processClientProof(clientProofBytes: Buffer): {
    candidate: AuthenticatedCandidateDevice
    finishMessage: Buffer
    transcriptHash: Buffer
    context: EstablishedServerHandshakeContext
  } {
    if (
      this.state !== 'WAITING_CLIENT_PROOF' ||
      !this.clientHello ||
      !this.clientHelloBuffer ||
      !this.serverProofBuffer ||
      !this.serverNonce
    ) {
      this.state = 'FAILED'
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }

    try {
      const clientProof = decodeClientProof(clientProofBytes)
      this.clientProofBuffer = Buffer.from(clientProofBytes)

      const clientProofPayload = buildClientProofPayload(
        this.clientHelloBuffer,
        this.serverProofBuffer,
        this.serverNonce,
        this.clientHello.candidateFingerprint
      )

      const candidateKeyObject = createPublicKey({
        key: this.clientHello.candidatePublicKey,
        format: 'der',
        type: 'spki'
      })

      const isValid = verify(null, clientProofPayload, candidateKeyObject, clientProof.clientSignature)
      if (!isValid) {
        throw new HandshakeError('HANDSHAKE_CLIENT_PROOF_INVALID')
      }

      this.authenticatedCandidate = createAuthenticatedCandidateDevice(
        this.clientHello.candidateFingerprint,
        this.clientHello.candidatePublicKey
      )

      // Gera Server Finish
      const finishPayload = buildServerFinishPayload(
        this.clientHelloBuffer,
        this.serverProofBuffer,
        this.clientProofBuffer
      )

      const serverFinishSignature = sign(null, finishPayload, this.serverPrivateKey)
      const serverFinish: ServerFinish = {
        handshakeVersion: HANDSHAKE_VERSION,
        serverFinishSignature
      }

      const finishMessage = encodeServerFinish(serverFinish)

      const fullTranscript = Buffer.concat([
        this.clientHelloBuffer,
        this.serverProofBuffer,
        this.clientProofBuffer,
        finishMessage
      ])

      const transcriptHash = createHash('sha256').update(fullTranscript).digest()

      this.establishedContext = createEstablishedServerHandshakeContext({
        transcriptHash,
        candidate: this.authenticatedCandidate,
        serverId: this.serverId,
        serverPublicKey: this.serverPublicKey,
        serverPrivateKey: this.serverPrivateKey
      })

      this.state = 'ESTABLISHED'
      return {
        candidate: this.authenticatedCandidate,
        finishMessage,
        transcriptHash,
        context: this.establishedContext
      }
    } catch (error) {
      this.state = 'FAILED'
      if (error instanceof HandshakeError) throw error
      throw new HandshakeError('HANDSHAKE_FAILED')
    }
  }

  getEstablishedContext(): EstablishedServerHandshakeContext {
    if (this.state !== 'ESTABLISHED' || !this.establishedContext) {
      throw new HandshakeError('HANDSHAKE_STATE_INVALID')
    }
    return this.establishedContext
  }

  getState(): string {
    return this.state
  }
}

// Framing helpers
export function encodeHandshakeFrame(handshakeMessage: Buffer): Buffer {
  return encodeProtocolFrame({
    type: ProtocolFrameType.HANDSHAKE,
    payload: handshakeMessage
  })
}

export function decodeHandshakeFrame(frame: ProtocolFrame): Buffer {
  if (frame.type !== ProtocolFrameType.HANDSHAKE) {
    throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
  }
  return frame.payload
}

// Canonical encoding / decoding
export function encodeClientHello(hello: ClientHello): Buffer {
  const expectedServerIdBuffer = Buffer.from(hello.expectedServerId, 'ascii')
  const candidateFingerprintBuffer = Buffer.from(hello.candidateFingerprint, 'ascii')

  const totalLength =
    2 + // type (1) + version (1)
    1 + expectedServerIdBuffer.length +
    1 + candidateFingerprintBuffer.length +
    2 + hello.candidatePublicKey.length +
    NONCE_BYTES

  if (totalLength > MAX_HANDSHAKE_MESSAGE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(HandshakeMessageType.CLIENT_HELLO, offset++)
  buffer.writeUInt8(hello.handshakeVersion, offset++)

  buffer.writeUInt8(expectedServerIdBuffer.length, offset++)
  expectedServerIdBuffer.copy(buffer, offset)
  offset += expectedServerIdBuffer.length

  buffer.writeUInt8(candidateFingerprintBuffer.length, offset++)
  candidateFingerprintBuffer.copy(buffer, offset)
  offset += candidateFingerprintBuffer.length

  buffer.writeUInt16BE(hello.candidatePublicKey.length, offset)
  offset += 2
  hello.candidatePublicKey.copy(buffer, offset)
  offset += hello.candidatePublicKey.length

  hello.clientNonce.copy(buffer, offset, 0, NONCE_BYTES)

  return buffer
}

export function decodeClientHello(buffer: Buffer): ClientHello {
  if (buffer.length < 2 || buffer.length > MAX_HANDSHAKE_MESSAGE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  let offset = 0
  const messageType = buffer.readUInt8(offset++)
  if (messageType !== HandshakeMessageType.CLIENT_HELLO) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED')
  }

  if (buffer.length < 2 + 1 + 1 + 2 + NONCE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const handshakeVersion = buffer.readUInt8(offset++)
  if (handshakeVersion !== HANDSHAKE_VERSION) {
    throw new HandshakeError('HANDSHAKE_VERSION_UNSUPPORTED')
  }

  const expectedServerIdLen = buffer.readUInt8(offset++)
  if (offset + expectedServerIdLen > buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }
  const expectedServerId = buffer.subarray(offset, offset + expectedServerIdLen).toString('ascii')
  offset += expectedServerIdLen

  if (!FINGERPRINT_PATTERN.test(expectedServerId)) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const candidateFingerprintLen = buffer.readUInt8(offset++)
  if (offset + candidateFingerprintLen > buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }
  const candidateFingerprint = buffer.subarray(offset, offset + candidateFingerprintLen).toString('ascii')
  offset += candidateFingerprintLen

  if (!FINGERPRINT_PATTERN.test(candidateFingerprint)) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  if (offset + 2 > buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }
  const keyLen = buffer.readUInt16BE(offset)
  offset += 2

  if (keyLen === 0 || keyLen > MAX_PUBLIC_KEY_BYTES || offset + keyLen > buffer.length) {
    throw new HandshakeError('HANDSHAKE_KEY_INVALID')
  }
  const candidatePublicKey = Buffer.from(buffer.subarray(offset, offset + keyLen))
  offset += keyLen

  if (offset + NONCE_BYTES !== buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }
  const clientNonce = Buffer.from(buffer.subarray(offset, offset + NONCE_BYTES))

  return {
    handshakeVersion,
    expectedServerId,
    candidateFingerprint,
    candidatePublicKey,
    clientNonce
  }
}

export function encodeServerProof(proof: ServerProof): Buffer {
  const serverIdBuffer = Buffer.from(proof.serverId, 'ascii')

  const totalLength =
    2 +
    1 + serverIdBuffer.length +
    2 + proof.serverPublicKey.length +
    NONCE_BYTES +
    SIGNATURE_BYTES

  if (totalLength > MAX_HANDSHAKE_MESSAGE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(HandshakeMessageType.SERVER_PROOF, offset++)
  buffer.writeUInt8(proof.handshakeVersion, offset++)

  buffer.writeUInt8(serverIdBuffer.length, offset++)
  serverIdBuffer.copy(buffer, offset)
  offset += serverIdBuffer.length

  buffer.writeUInt16BE(proof.serverPublicKey.length, offset)
  offset += 2
  proof.serverPublicKey.copy(buffer, offset)
  offset += proof.serverPublicKey.length

  proof.serverNonce.copy(buffer, offset, 0, NONCE_BYTES)
  offset += NONCE_BYTES

  proof.serverSignature.copy(buffer, offset, 0, SIGNATURE_BYTES)

  return buffer
}

export function decodeServerProof(buffer: Buffer): ServerProof {
  if (buffer.length < 2 || buffer.length > MAX_HANDSHAKE_MESSAGE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  let offset = 0
  const messageType = buffer.readUInt8(offset++)
  if (messageType !== HandshakeMessageType.SERVER_PROOF) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED')
  }

  if (buffer.length < 2 + 1 + 2 + NONCE_BYTES + SIGNATURE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const handshakeVersion = buffer.readUInt8(offset++)
  if (handshakeVersion !== HANDSHAKE_VERSION) {
    throw new HandshakeError('HANDSHAKE_VERSION_UNSUPPORTED')
  }

  const serverIdLen = buffer.readUInt8(offset++)
  if (offset + serverIdLen > buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }
  const serverId = buffer.subarray(offset, offset + serverIdLen).toString('ascii')
  offset += serverIdLen

  if (!FINGERPRINT_PATTERN.test(serverId)) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  if (offset + 2 > buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }
  const keyLen = buffer.readUInt16BE(offset)
  offset += 2

  if (keyLen === 0 || keyLen > MAX_PUBLIC_KEY_BYTES || offset + keyLen > buffer.length) {
    throw new HandshakeError('HANDSHAKE_KEY_INVALID')
  }
  const serverPublicKey = Buffer.from(buffer.subarray(offset, offset + keyLen))
  offset += keyLen

  if (offset + NONCE_BYTES + SIGNATURE_BYTES !== buffer.length) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const serverNonce = Buffer.from(buffer.subarray(offset, offset + NONCE_BYTES))
  offset += NONCE_BYTES

  const serverSignature = Buffer.from(buffer.subarray(offset, offset + SIGNATURE_BYTES))

  return {
    handshakeVersion,
    serverId,
    serverPublicKey,
    serverNonce,
    serverSignature
  }
}

export function encodeClientProof(proof: ClientProof): Buffer {
  const totalLength = 2 + SIGNATURE_BYTES
  const buffer = Buffer.allocUnsafe(totalLength)
  buffer.writeUInt8(HandshakeMessageType.CLIENT_PROOF, 0)
  buffer.writeUInt8(proof.handshakeVersion, 1)
  proof.clientSignature.copy(buffer, 2, 0, SIGNATURE_BYTES)
  return buffer
}

export function decodeClientProof(buffer: Buffer): ClientProof {
  if (buffer.length < 2) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const messageType = buffer.readUInt8(0)
  if (messageType !== HandshakeMessageType.CLIENT_PROOF) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED')
  }

  if (buffer.length !== 2 + SIGNATURE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const handshakeVersion = buffer.readUInt8(1)
  if (handshakeVersion !== HANDSHAKE_VERSION) {
    throw new HandshakeError('HANDSHAKE_VERSION_UNSUPPORTED')
  }

  const clientSignature = Buffer.from(buffer.subarray(2, 2 + SIGNATURE_BYTES))

  return {
    handshakeVersion,
    clientSignature
  }
}

export function encodeServerFinish(finish: ServerFinish): Buffer {
  const totalLength = 2 + SIGNATURE_BYTES
  const buffer = Buffer.allocUnsafe(totalLength)
  buffer.writeUInt8(HandshakeMessageType.SERVER_FINISH, 0)
  buffer.writeUInt8(finish.handshakeVersion, 1)
  finish.serverFinishSignature.copy(buffer, 2, 0, SIGNATURE_BYTES)
  return buffer
}

export function decodeServerFinish(buffer: Buffer): ServerFinish {
  if (buffer.length < 2) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const messageType = buffer.readUInt8(0)
  if (messageType !== HandshakeMessageType.SERVER_FINISH) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_TYPE_UNSUPPORTED')
  }

  if (buffer.length !== 2 + SIGNATURE_BYTES) {
    throw new HandshakeError('HANDSHAKE_MESSAGE_INVALID')
  }

  const handshakeVersion = buffer.readUInt8(1)
  if (handshakeVersion !== HANDSHAKE_VERSION) {
    throw new HandshakeError('HANDSHAKE_VERSION_UNSUPPORTED')
  }

  const serverFinishSignature = Buffer.from(buffer.subarray(2, 2 + SIGNATURE_BYTES))

  return {
    handshakeVersion,
    serverFinishSignature
  }
}

function buildServerProofPayload(
  expectedServerId: string,
  candidateFingerprint: string,
  candidatePublicKey: Buffer,
  clientNonce: Buffer,
  serverId: string,
  serverPublicKey: Buffer,
  serverNonce: Buffer
): Buffer {
  const domainBuf = Buffer.from(SERVER_PROOF_DOMAIN, 'utf8')
  const expectedServerIdBuf = Buffer.from(expectedServerId, 'ascii')
  const candidateFingerprintBuf = Buffer.from(candidateFingerprint, 'ascii')
  const serverIdBuf = Buffer.from(serverId, 'ascii')

  const totalLength =
    2 + domainBuf.length +
    1 + // handshakeVersion
    1 + // protocolVersion
    2 + expectedServerIdBuf.length +
    2 + candidateFingerprintBuf.length +
    2 + candidatePublicKey.length +
    NONCE_BYTES +
    2 + serverIdBuf.length +
    2 + serverPublicKey.length +
    NONCE_BYTES

  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt16BE(domainBuf.length, offset)
  offset += 2
  domainBuf.copy(buffer, offset)
  offset += domainBuf.length

  buffer.writeUInt8(HANDSHAKE_VERSION, offset++)
  buffer.writeUInt8(PROTOCOL_VERSION, offset++)

  buffer.writeUInt16BE(expectedServerIdBuf.length, offset)
  offset += 2
  expectedServerIdBuf.copy(buffer, offset)
  offset += expectedServerIdBuf.length

  buffer.writeUInt16BE(candidateFingerprintBuf.length, offset)
  offset += 2
  candidateFingerprintBuf.copy(buffer, offset)
  offset += candidateFingerprintBuf.length

  buffer.writeUInt16BE(candidatePublicKey.length, offset)
  offset += 2
  candidatePublicKey.copy(buffer, offset)
  offset += candidatePublicKey.length

  clientNonce.copy(buffer, offset, 0, NONCE_BYTES)
  offset += NONCE_BYTES

  buffer.writeUInt16BE(serverIdBuf.length, offset)
  offset += 2
  serverIdBuf.copy(buffer, offset)
  offset += serverIdBuf.length

  buffer.writeUInt16BE(serverPublicKey.length, offset)
  offset += 2
  serverPublicKey.copy(buffer, offset)
  offset += serverPublicKey.length

  serverNonce.copy(buffer, offset, 0, NONCE_BYTES)

  return buffer
}

function buildClientProofPayload(
  clientHelloBuffer: Buffer,
  serverProofBuffer: Buffer,
  serverNonce: Buffer,
  candidateFingerprint: string
): Buffer {
  const domainBuf = Buffer.from(CLIENT_PROOF_DOMAIN, 'utf8')
  const candidateFingerprintBuf = Buffer.from(candidateFingerprint, 'ascii')

  const totalLength =
    2 + domainBuf.length +
    1 + // handshakeVersion
    1 + // protocolVersion
    4 + clientHelloBuffer.length +
    4 + serverProofBuffer.length +
    NONCE_BYTES +
    2 + candidateFingerprintBuf.length

  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt16BE(domainBuf.length, offset)
  offset += 2
  domainBuf.copy(buffer, offset)
  offset += domainBuf.length

  buffer.writeUInt8(HANDSHAKE_VERSION, offset++)
  buffer.writeUInt8(PROTOCOL_VERSION, offset++)

  buffer.writeUInt32BE(clientHelloBuffer.length, offset)
  offset += 4
  clientHelloBuffer.copy(buffer, offset)
  offset += clientHelloBuffer.length

  buffer.writeUInt32BE(serverProofBuffer.length, offset)
  offset += 4
  serverProofBuffer.copy(buffer, offset)
  offset += serverProofBuffer.length

  serverNonce.copy(buffer, offset, 0, NONCE_BYTES)
  offset += NONCE_BYTES

  buffer.writeUInt16BE(candidateFingerprintBuf.length, offset)
  offset += 2
  candidateFingerprintBuf.copy(buffer, offset)

  return buffer
}

function buildServerFinishPayload(
  clientHelloBuffer: Buffer,
  serverProofBuffer: Buffer,
  clientProofBuffer: Buffer
): Buffer {
  const domainBuf = Buffer.from(SERVER_FINISH_DOMAIN, 'utf8')

  const totalLength =
    2 + domainBuf.length +
    1 + // handshakeVersion
    1 + // protocolVersion
    4 + clientHelloBuffer.length +
    4 + serverProofBuffer.length +
    4 + clientProofBuffer.length

  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt16BE(domainBuf.length, offset)
  offset += 2
  domainBuf.copy(buffer, offset)
  offset += domainBuf.length

  buffer.writeUInt8(HANDSHAKE_VERSION, offset++)
  buffer.writeUInt8(PROTOCOL_VERSION, offset++)

  buffer.writeUInt32BE(clientHelloBuffer.length, offset)
  offset += 4
  clientHelloBuffer.copy(buffer, offset)
  offset += clientHelloBuffer.length

  buffer.writeUInt32BE(serverProofBuffer.length, offset)
  offset += 4
  serverProofBuffer.copy(buffer, offset)
  offset += serverProofBuffer.length

  buffer.writeUInt32BE(clientProofBuffer.length, offset)
  offset += 4
  clientProofBuffer.copy(buffer, offset)

  return buffer
}

function validatePublicKeyDer(publicKeyBytes: Buffer, expectedFingerprint: string): Buffer {
  let keyObject: KeyObject

  try {
    keyObject = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' })
  } catch {
    throw new HandshakeError('HANDSHAKE_KEY_INVALID')
  }

  if (keyObject.type !== 'public' || keyObject.asymmetricKeyType !== 'ed25519') {
    throw new HandshakeError('HANDSHAKE_KEY_INVALID')
  }

  const canonicalDer = Buffer.from(keyObject.export({ format: 'der', type: 'spki' }))

  if (!canonicalDer.equals(publicKeyBytes)) {
    throw new HandshakeError('HANDSHAKE_KEY_INVALID')
  }

  const calculatedFingerprint = `sha256:${createHash('sha256').update(canonicalDer).digest('hex')}`

  if (calculatedFingerprint !== expectedFingerprint) {
    throw new HandshakeError('HANDSHAKE_KEY_INVALID')
  }

  return canonicalDer
}
