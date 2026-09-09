import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

import {
  isEstablishedClientHandshakeContext,
  isEstablishedServerHandshakeContext,
  type EstablishedClientHandshakeContext,
  type EstablishedServerHandshakeContext
} from '../security/authenticated-candidate'
import {
  HANDSHAKE_VERSION
} from './p2p-handshake'
import {
  encodeProtocolFrame,
  ProtocolError,
  ProtocolFrameType,
  PROTOCOL_VERSION,
  type ProtocolFrame
} from './protocol-frame'

export const SESSION_SETUP_VERSION = 1
export const SESSION_VERSION = 1

export const AES_KEY_BYTES = 32
export const AEAD_TAG_BYTES = 16
export const NONCE_PREFIX_BYTES = 4
export const NONCE_BYTES = 12
export const SEQUENCE_BYTES = 8
export const SESSION_ID_BYTES = 32
export const SIGNATURE_BYTES = 64
export const MAX_KEY_EXCHANGE_MESSAGE_BYTES = 4096
export const SESSION_HEADER_AND_TAG_BYTES = 1 + SEQUENCE_BYTES + AEAD_TAG_BYTES // 25 bytes
export const MAX_SESSION_PLAINTEXT_BYTES = 64 * 1024 - SESSION_HEADER_AND_TAG_BYTES // 65511 bytes
export const MAX_SEQUENCE_NUMBER = 0xffffffff_fffffffen // Safe bound before overflow

export const CLIENT_KEY_SHARE_DOMAIN = 'Masquerada/p2p-session/client-key-share/v1'
export const SERVER_KEY_SHARE_DOMAIN = 'Masquerada/p2p-session/server-key-share/v1'
export const SESSION_ID_DOMAIN = 'Masquerada/p2p-session/session-id/v1'
export const SESSION_AEAD_DOMAIN = 'Masquerada/p2p-session/aead/v1'
export const CLIENT_CONFIRM_TOKEN = Buffer.from('Masquerada/p2p-session/client-confirm/v1', 'ascii')
export const SERVER_CONFIRM_TOKEN = Buffer.from('Masquerada/p2p-session/server-confirm/v1', 'ascii')

export enum KeyExchangeMessageType {
  CLIENT_KEY_SHARE = 0x01,
  SERVER_KEY_SHARE = 0x02,
  CLIENT_KEY_CONFIRM = 0x03,
  SERVER_KEY_CONFIRM = 0x04
}

export type SessionErrorCode =
  | 'SESSION_CONTEXT_INVALID'
  | 'SESSION_KEY_SHARE_INVALID'
  | 'SESSION_SIGNATURE_INVALID'
  | 'SESSION_DIFFIE_HELLMAN_FAILED'
  | 'SESSION_MESSAGE_INVALID'
  | 'SESSION_MESSAGE_TYPE_UNSUPPORTED'
  | 'SESSION_VERSION_UNSUPPORTED'
  | 'SESSION_STATE_INVALID'
  | 'SESSION_CONFIRMATION_INVALID'
  | 'SESSION_AUTHENTICATION_FAILED'
  | 'SESSION_SEQUENCE_VIOLATION'
  | 'SESSION_SEQUENCE_EXHAUSTED'
  | 'SESSION_PLAINTEXT_TOO_LARGE'
  | 'SESSION_DESTROYED'
  | 'SESSION_FAILED'

const ERROR_MESSAGES: Record<SessionErrorCode, string> = {
  SESSION_CONTEXT_INVALID: 'O contexto de handshake autenticado fornecido é inválido.',
  SESSION_KEY_SHARE_INVALID: 'A chave pública efêmera X25519 recebida é inválida ou malformada.',
  SESSION_SIGNATURE_INVALID: 'A assinatura criptográfica do key share é inválida.',
  SESSION_DIFFIE_HELLMAN_FAILED: 'Falha no cálculo do acordo de chaves X25519 efêmero.',
  SESSION_MESSAGE_INVALID: 'A mensagem de estabelecimento de sessão é inválida ou truncada.',
  SESSION_MESSAGE_TYPE_UNSUPPORTED: 'O discriminador da mensagem de sessão é desconhecido.',
  SESSION_VERSION_UNSUPPORTED: 'A versão de sessão recebida não é suportada.',
  SESSION_STATE_INVALID: 'A operação foi executada em um estado de sessão inválido.',
  SESSION_CONFIRMATION_INVALID: 'A confirmação de chaves de sessão falhou na validação.',
  SESSION_AUTHENTICATION_FAILED: 'Falha de integridade ou autenticação AEAD no payload de sessão.',
  SESSION_SEQUENCE_VIOLATION: 'Violação de sequência monotônica detectada (replay, gap ou reorder).',
  SESSION_SEQUENCE_EXHAUSTED: 'O contador de sequência da sessão atingiu o limite máximo.',
  SESSION_PLAINTEXT_TOO_LARGE: 'O tamanho do plaintext excede o limite máximo permitido.',
  SESSION_DESTROYED: 'A sessão segura já foi destruída e não aceita novas operações.',
  SESSION_FAILED: 'Ocorreu uma falha irrecuperável durante a sessão segura.'
}

export class SessionError extends Error {
  readonly code: SessionErrorCode

  constructor(code: SessionErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'SessionError'
    this.code = code
  }
}

export interface ClientKeyShare {
  readonly sessionSetupVersion: number
  readonly clientEphemeralPublicKey: Buffer
  readonly clientKeyShareSignature: Buffer
}

export interface ServerKeyShare {
  readonly sessionSetupVersion: number
  readonly serverEphemeralPublicKey: Buffer
  readonly serverKeyShareSignature: Buffer
}

export interface EncryptedSessionPayload {
  readonly sessionVersion: number
  readonly sequence: bigint
  readonly ciphertext: Buffer
  readonly authTag: Buffer
}

const secureSessionInstances = new WeakSet<object>()

export interface ISecureSession {
  readonly role: 'client' | 'server'
  readonly sessionId: Buffer
  readonly transcriptHash: Buffer
  encrypt(plaintext: Buffer): Buffer
  decrypt(sessionPayloadBuffer: Buffer): Buffer
  destroy(): void
  isDestroyed(): boolean
  getSendSequence(): bigint
  getExpectedReceiveSequence(): bigint
}

export class SecureSession implements ISecureSession {
  readonly role: 'client' | 'server'
  readonly sessionId: Buffer
  readonly transcriptHash: Buffer

  private readonly sendKey: Buffer
  private readonly receiveKey: Buffer
  private readonly sendNoncePrefix: Buffer
  private readonly receiveNoncePrefix: Buffer
  private sendSequence: bigint
  private expectedReceiveSequence: bigint
  private destroyed = false

  constructor(options: {
    role: 'client' | 'server'
    sessionId: Buffer
    transcriptHash: Buffer
    sendKey: Buffer
    receiveKey: Buffer
    sendNoncePrefix: Buffer
    receiveNoncePrefix: Buffer
    initialSendSequence?: bigint
    initialExpectedReceiveSequence?: bigint
  }) {
    this.role = options.role
    this.sessionId = Buffer.from(options.sessionId)
    this.transcriptHash = Buffer.from(options.transcriptHash)
    this.sendKey = Buffer.from(options.sendKey)
    this.receiveKey = Buffer.from(options.receiveKey)
    this.sendNoncePrefix = Buffer.from(options.sendNoncePrefix)
    this.receiveNoncePrefix = Buffer.from(options.receiveNoncePrefix)
    this.sendSequence = options.initialSendSequence ?? 1n
    this.expectedReceiveSequence = options.initialExpectedReceiveSequence ?? 1n

    secureSessionInstances.add(this)
  }

  encrypt(plaintext: Buffer): Buffer {
    if (this.destroyed) {
      throw new SessionError('SESSION_DESTROYED')
    }

    if (plaintext.length > MAX_SESSION_PLAINTEXT_BYTES) {
      throw new SessionError('SESSION_PLAINTEXT_TOO_LARGE')
    }

    if (this.sendSequence > MAX_SEQUENCE_NUMBER) {
      this.destroy()
      throw new SessionError('SESSION_SEQUENCE_EXHAUSTED')
    }

    const currentSequence = this.sendSequence
    this.sendSequence += 1n

    const nonce = buildAeadNonce(this.sendNoncePrefix, currentSequence)
    const sendDirection = this.role === 'client' ? 1 : 2
    const aad = buildAeadAssociatedData(
      sendDirection,
      this.sessionId,
      this.transcriptHash,
      currentSequence
    )

    try {
      const cipher = createCipheriv('aes-256-gcm', this.sendKey, nonce)
      cipher.setAAD(aad)

      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
      const authTag = cipher.getAuthTag()

      return encodeSessionPayload({
        sessionVersion: SESSION_VERSION,
        sequence: currentSequence,
        ciphertext,
        authTag
      })
    } catch {
      this.destroy()
      throw new SessionError('SESSION_FAILED')
    }
  }

  decrypt(sessionPayloadBuffer: Buffer): Buffer {
    if (this.destroyed) {
      throw new SessionError('SESSION_DESTROYED')
    }

    let parsed: EncryptedSessionPayload
    try {
      parsed = decodeSessionPayload(sessionPayloadBuffer)
    } catch (error) {
      this.destroy()
      if (error instanceof SessionError) throw error
      throw new SessionError('SESSION_MESSAGE_INVALID')
    }

    if (parsed.sequence !== this.expectedReceiveSequence) {
      this.destroy()
      throw new SessionError('SESSION_SEQUENCE_VIOLATION')
    }

    this.expectedReceiveSequence += 1n

    const receiveDirection = this.role === 'client' ? 2 : 1
    const nonce = buildAeadNonce(this.receiveNoncePrefix, parsed.sequence)
    const aad = buildAeadAssociatedData(
      receiveDirection,
      this.sessionId,
      this.transcriptHash,
      parsed.sequence
    )

    try {
      const decipher = createDecipheriv('aes-256-gcm', this.receiveKey, nonce)
      decipher.setAAD(aad)
      decipher.setAuthTag(parsed.authTag)

      const plaintext = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()])
      return plaintext
    } catch {
      this.destroy()
      throw new SessionError('SESSION_AUTHENTICATION_FAILED')
    }
  }

  destroy(): void {
    if (!this.destroyed) {
      this.destroyed = true
      this.sendKey.fill(0)
      this.receiveKey.fill(0)
      this.sendNoncePrefix.fill(0)
      this.receiveNoncePrefix.fill(0)
    }
  }

  isDestroyed(): boolean {
    return this.destroyed
  }

  getSendSequence(): bigint {
    return this.sendSequence
  }

  getExpectedReceiveSequence(): bigint {
    return this.expectedReceiveSequence
  }
}

export function isSecureSession(value: unknown): value is SecureSession {
  return typeof value === 'object' && value !== null && secureSessionInstances.has(value)
}

export class ClientSessionSetup {
  private state:
    | 'INITIAL'
    | 'WAITING_SERVER_KEY_SHARE'
    | 'WAITING_SERVER_KEY_CONFIRM'
    | 'ESTABLISHED'
    | 'FAILED' = 'INITIAL'

  private readonly context: EstablishedClientHandshakeContext
  private clientEphemeralKeyPair?: { publicKey: Buffer; privateKey: KeyObject }
  private clientKeyShareBuffer?: Buffer
  private serverEphemeralPublicKey?: Buffer
  private sharedSecret?: Buffer
  private derivedKeys?: DerivedSessionKeys

  constructor(context: EstablishedClientHandshakeContext) {
    if (!isEstablishedClientHandshakeContext(context)) {
      throw new SessionError('SESSION_CONTEXT_INVALID')
    }
    this.context = context
  }

  createClientKeyShare(): Buffer {
    if (this.state !== 'INITIAL') {
      this.fail()
      throw new SessionError('SESSION_STATE_INVALID')
    }

    try {
      const keyPair = generateKeyPairSync('x25519')
      const clientEphemeralPublicKey = Buffer.from(
        keyPair.publicKey.export({ format: 'der', type: 'spki' })
      )
      this.clientEphemeralKeyPair = {
        publicKey: clientEphemeralPublicKey,
        privateKey: keyPair.privateKey
      }

      const payloadToSign = buildClientKeySharePayload(
        this.context.transcriptHash,
        this.context.server.serverId,
        this.context.deviceFingerprint,
        clientEphemeralPublicKey
      )

      const clientKeyShareSignature = sign(null, payloadToSign, this.context.devicePrivateKey)
      const share: ClientKeyShare = {
        sessionSetupVersion: SESSION_SETUP_VERSION,
        clientEphemeralPublicKey,
        clientKeyShareSignature
      }

      this.clientKeyShareBuffer = encodeClientKeyShare(share)
      this.state = 'WAITING_SERVER_KEY_SHARE'
      return this.clientKeyShareBuffer
    } catch (error) {
      this.fail()
      if (error instanceof SessionError) throw error
      throw new SessionError('SESSION_FAILED')
    }
  }

  processServerKeyShare(serverKeyShareBytes: Buffer): Buffer {
    if (
      this.state !== 'WAITING_SERVER_KEY_SHARE' ||
      !this.clientEphemeralKeyPair ||
      !this.clientKeyShareBuffer
    ) {
      this.fail()
      throw new SessionError('SESSION_STATE_INVALID')
    }

    try {
      const serverKeyShare = decodeServerKeyShare(serverKeyShareBytes)
      this.serverEphemeralPublicKey = validateX25519PublicKey(
        serverKeyShare.serverEphemeralPublicKey
      )

      // Valida assinatura Ed25519 do servidor
      const payloadToVerify = buildServerKeySharePayload(
        this.context.transcriptHash,
        this.context.server.serverId,
        this.context.deviceFingerprint,
        this.clientEphemeralKeyPair.publicKey,
        this.serverEphemeralPublicKey
      )

      const serverEdKeyObject = createPublicKey({
        key: this.context.server.publicKey,
        format: 'der',
        type: 'spki'
      })

      const isValidSignature = verify(
        null,
        payloadToVerify,
        serverEdKeyObject,
        serverKeyShare.serverKeyShareSignature
      )

      if (!isValidSignature) {
        throw new SessionError('SESSION_SIGNATURE_INVALID')
      }

      // Calcula Diffie-Hellman efêmero
      const serverX25519KeyObject = createPublicKey({
        key: this.serverEphemeralPublicKey,
        format: 'der',
        type: 'spki'
      })

      this.sharedSecret = computeX25519SharedSecret(
        this.clientEphemeralKeyPair.privateKey,
        serverX25519KeyObject
      )

      this.derivedKeys = deriveSessionKeys({
        sharedSecret: this.sharedSecret,
        transcriptHash: this.context.transcriptHash,
        serverId: this.context.server.serverId,
        candidateFingerprint: this.context.deviceFingerprint,
        clientEphemeralPublicKey: this.clientEphemeralKeyPair.publicKey,
        serverEphemeralPublicKey: this.serverEphemeralPublicKey
      })

      // Limpa chave efêmera privada e shared secret brutos
      this.sharedSecret.fill(0)
      this.sharedSecret = undefined
      this.clientEphemeralKeyPair = undefined

      // Gera CLIENT_KEY_CONFIRM usando sequence 0
      const confirmCipher = createCipheriv(
        'aes-256-gcm',
        this.derivedKeys.clientToServerKey,
        buildAeadNonce(this.derivedKeys.clientToServerNoncePrefix, 0n)
      )
      const aad = buildAeadAssociatedData(
        1, // Client -> Server
        this.derivedKeys.sessionId,
        this.context.transcriptHash,
        0n
      )
      confirmCipher.setAAD(aad)

      const ciphertext = Buffer.concat([
        confirmCipher.update(CLIENT_CONFIRM_TOKEN),
        confirmCipher.final()
      ])
      const authTag = confirmCipher.getAuthTag()

      const clientKeyConfirm = encodeKeyConfirmMessage(
        KeyExchangeMessageType.CLIENT_KEY_CONFIRM,
        {
          sessionVersion: SESSION_VERSION,
          sequence: 0n,
          ciphertext,
          authTag
        }
      )

      this.state = 'WAITING_SERVER_KEY_CONFIRM'
      return clientKeyConfirm
    } catch (error) {
      this.fail()
      if (error instanceof SessionError) throw error
      throw new SessionError('SESSION_FAILED')
    }
  }

  processServerKeyConfirm(serverKeyConfirmBytes: Buffer): SecureSession {
    if (this.state !== 'WAITING_SERVER_KEY_CONFIRM' || !this.derivedKeys) {
      this.fail()
      throw new SessionError('SESSION_STATE_INVALID')
    }

    try {
      const parsed = decodeKeyConfirmMessage(
        KeyExchangeMessageType.SERVER_KEY_CONFIRM,
        serverKeyConfirmBytes
      )

      if (parsed.sequence !== 0n) {
        throw new SessionError('SESSION_CONFIRMATION_INVALID')
      }

      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.derivedKeys.serverToClientKey,
        buildAeadNonce(this.derivedKeys.serverToClientNoncePrefix, 0n)
      )
      const aad = buildAeadAssociatedData(
        2, // Server -> Client
        this.derivedKeys.sessionId,
        this.context.transcriptHash,
        0n
      )
      decipher.setAAD(aad)
      decipher.setAuthTag(parsed.authTag)

      const decrypted = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()])
      if (!decrypted.equals(SERVER_CONFIRM_TOKEN)) {
        throw new SessionError('SESSION_CONFIRMATION_INVALID')
      }

      const session = new SecureSession({
        role: 'client',
        sessionId: this.derivedKeys.sessionId,
        transcriptHash: this.context.transcriptHash,
        sendKey: this.derivedKeys.clientToServerKey,
        receiveKey: this.derivedKeys.serverToClientKey,
        sendNoncePrefix: this.derivedKeys.clientToServerNoncePrefix,
        receiveNoncePrefix: this.derivedKeys.serverToClientNoncePrefix,
        initialSendSequence: 1n,
        initialExpectedReceiveSequence: 1n
      })

      this.state = 'ESTABLISHED'
      this.clearKeyMaterial()
      return session
    } catch (error) {
      this.fail()
      if (error instanceof SessionError) throw error
      throw new SessionError('SESSION_CONFIRMATION_INVALID')
    }
  }

  getState(): string {
    return this.state
  }

  private fail(): void {
    this.destroy()
  }

  destroy(): void {
    this.state = 'FAILED'
    this.clearKeyMaterial()
  }

  private clearKeyMaterial(): void {
    this.clientEphemeralKeyPair = undefined
    this.clientKeyShareBuffer = undefined
    this.serverEphemeralPublicKey = undefined
    if (this.sharedSecret) {
      this.sharedSecret.fill(0)
      this.sharedSecret = undefined
    }
    if (this.derivedKeys) {
      this.derivedKeys.clientToServerKey.fill(0)
      this.derivedKeys.serverToClientKey.fill(0)
      this.derivedKeys.clientToServerNoncePrefix.fill(0)
      this.derivedKeys.serverToClientNoncePrefix.fill(0)
      this.derivedKeys = undefined
    }
  }
}

export class ServerSessionSetup {
  private state:
    | 'INITIAL'
    | 'WAITING_CLIENT_KEY_CONFIRM'
    | 'ESTABLISHED'
    | 'FAILED' = 'INITIAL'

  private readonly context: EstablishedServerHandshakeContext
  private clientEphemeralPublicKey?: Buffer
  private serverEphemeralKeyPair?: { publicKey: Buffer; privateKey: KeyObject }
  private sharedSecret?: Buffer
  private derivedKeys?: DerivedSessionKeys

  constructor(context: EstablishedServerHandshakeContext) {
    if (!isEstablishedServerHandshakeContext(context)) {
      throw new SessionError('SESSION_CONTEXT_INVALID')
    }
    this.context = context
  }

  processClientKeyShare(clientKeyShareBytes: Buffer): Buffer {
    if (this.state !== 'INITIAL') {
      this.fail()
      throw new SessionError('SESSION_STATE_INVALID')
    }

    try {
      const clientKeyShare = decodeClientKeyShare(clientKeyShareBytes)
      this.clientEphemeralPublicKey = validateX25519PublicKey(
        clientKeyShare.clientEphemeralPublicKey
      )

      // Valida assinatura Ed25519 do cliente candidato
      const payloadToVerify = buildClientKeySharePayload(
        this.context.transcriptHash,
        this.context.serverId,
        this.context.candidate.fingerprint,
        this.clientEphemeralPublicKey
      )

      const candidateEdKeyObject = createPublicKey({
        key: this.context.candidate.publicKey,
        format: 'der',
        type: 'spki'
      })

      const isValidSignature = verify(
        null,
        payloadToVerify,
        candidateEdKeyObject,
        clientKeyShare.clientKeyShareSignature
      )

      if (!isValidSignature) {
        throw new SessionError('SESSION_SIGNATURE_INVALID')
      }

      // Gera ephemeral X25519 keypair do servidor
      const keyPair = generateKeyPairSync('x25519')
      const serverEphemeralPublicKey = Buffer.from(
        keyPair.publicKey.export({ format: 'der', type: 'spki' })
      )
      this.serverEphemeralKeyPair = {
        publicKey: serverEphemeralPublicKey,
        privateKey: keyPair.privateKey
      }

      // Assina Server Key Share
      const payloadToSign = buildServerKeySharePayload(
        this.context.transcriptHash,
        this.context.serverId,
        this.context.candidate.fingerprint,
        this.clientEphemeralPublicKey,
        serverEphemeralPublicKey
      )

      const serverKeyShareSignature = sign(null, payloadToSign, this.context.serverPrivateKey)

      // Calcula Diffie-Hellman efêmero
      const clientX25519KeyObject = createPublicKey({
        key: this.clientEphemeralPublicKey,
        format: 'der',
        type: 'spki'
      })

      this.sharedSecret = computeX25519SharedSecret(
        this.serverEphemeralKeyPair.privateKey,
        clientX25519KeyObject
      )

      this.derivedKeys = deriveSessionKeys({
        sharedSecret: this.sharedSecret,
        transcriptHash: this.context.transcriptHash,
        serverId: this.context.serverId,
        candidateFingerprint: this.context.candidate.fingerprint,
        clientEphemeralPublicKey: this.clientEphemeralPublicKey,
        serverEphemeralPublicKey: serverEphemeralPublicKey
      })

      // Limpa material secreto bruto
      this.sharedSecret.fill(0)
      this.sharedSecret = undefined
      this.serverEphemeralKeyPair = undefined

      const serverKeyShare: ServerKeyShare = {
        sessionSetupVersion: SESSION_SETUP_VERSION,
        serverEphemeralPublicKey,
        serverKeyShareSignature
      }

      const responseBuffer = encodeServerKeyShare(serverKeyShare)
      this.state = 'WAITING_CLIENT_KEY_CONFIRM'
      return responseBuffer
    } catch (error) {
      this.fail()
      if (error instanceof SessionError) throw error
      throw new SessionError('SESSION_FAILED')
    }
  }

  processClientKeyConfirm(clientKeyConfirmBytes: Buffer): {
    serverKeyConfirm: Buffer
    session: SecureSession
  } {
    if (this.state !== 'WAITING_CLIENT_KEY_CONFIRM' || !this.derivedKeys) {
      this.fail()
      throw new SessionError('SESSION_STATE_INVALID')
    }

    try {
      const parsed = decodeKeyConfirmMessage(
        KeyExchangeMessageType.CLIENT_KEY_CONFIRM,
        clientKeyConfirmBytes
      )

      if (parsed.sequence !== 0n) {
        throw new SessionError('SESSION_CONFIRMATION_INVALID')
      }

      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.derivedKeys.clientToServerKey,
        buildAeadNonce(this.derivedKeys.clientToServerNoncePrefix, 0n)
      )
      const aad = buildAeadAssociatedData(
        1, // Client -> Server
        this.derivedKeys.sessionId,
        this.context.transcriptHash,
        0n
      )
      decipher.setAAD(aad)
      decipher.setAuthTag(parsed.authTag)

      const decrypted = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()])
      if (!decrypted.equals(CLIENT_CONFIRM_TOKEN)) {
        throw new SessionError('SESSION_CONFIRMATION_INVALID')
      }

      // Gera SERVER_KEY_CONFIRM
      const confirmCipher = createCipheriv(
        'aes-256-gcm',
        this.derivedKeys.serverToClientKey,
        buildAeadNonce(this.derivedKeys.serverToClientNoncePrefix, 0n)
      )
      const serverAad = buildAeadAssociatedData(
        2, // Server -> Client
        this.derivedKeys.sessionId,
        this.context.transcriptHash,
        0n
      )
      confirmCipher.setAAD(serverAad)

      const ciphertext = Buffer.concat([
        confirmCipher.update(SERVER_CONFIRM_TOKEN),
        confirmCipher.final()
      ])
      const authTag = confirmCipher.getAuthTag()

      const serverKeyConfirm = encodeKeyConfirmMessage(
        KeyExchangeMessageType.SERVER_KEY_CONFIRM,
        {
          sessionVersion: SESSION_VERSION,
          sequence: 0n,
          ciphertext,
          authTag
        }
      )

      const session = new SecureSession({
        role: 'server',
        sessionId: this.derivedKeys.sessionId,
        transcriptHash: this.context.transcriptHash,
        sendKey: this.derivedKeys.serverToClientKey,
        receiveKey: this.derivedKeys.clientToServerKey,
        sendNoncePrefix: this.derivedKeys.serverToClientNoncePrefix,
        receiveNoncePrefix: this.derivedKeys.clientToServerNoncePrefix,
        initialSendSequence: 1n,
        initialExpectedReceiveSequence: 1n
      })

      this.state = 'ESTABLISHED'
      this.clearKeyMaterial()
      return {
        serverKeyConfirm,
        session
      }
    } catch (error) {
      this.fail()
      if (error instanceof SessionError) throw error
      throw new SessionError('SESSION_CONFIRMATION_INVALID')
    }
  }

  getState(): string {
    return this.state
  }

  private fail(): void {
    this.destroy()
  }

  destroy(): void {
    this.state = 'FAILED'
    this.clearKeyMaterial()
  }

  private clearKeyMaterial(): void {
    this.serverEphemeralKeyPair = undefined
    this.clientEphemeralPublicKey = undefined
    if (this.sharedSecret) {
      this.sharedSecret.fill(0)
      this.sharedSecret = undefined
    }
    if (this.derivedKeys) {
      this.derivedKeys.clientToServerKey.fill(0)
      this.derivedKeys.serverToClientKey.fill(0)
      this.derivedKeys.clientToServerNoncePrefix.fill(0)
      this.derivedKeys.serverToClientNoncePrefix.fill(0)
      this.derivedKeys = undefined
    }
  }
}

// Framing helpers for Key Exchange and Session
export function encodeKeyExchangeFrame(message: Buffer): Buffer {
  return encodeProtocolFrame({
    type: ProtocolFrameType.KEY_EXCHANGE,
    payload: message
  })
}

export function decodeKeyExchangeFrame(frame: ProtocolFrame): Buffer {
  if (frame.type !== ProtocolFrameType.KEY_EXCHANGE) {
    throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
  }
  return frame.payload
}

export function encodeSessionFrame(sessionPayload: Buffer): Buffer {
  return encodeProtocolFrame({
    type: ProtocolFrameType.SESSION,
    payload: sessionPayload
  })
}

export function decodeSessionFrame(frame: ProtocolFrame): Buffer {
  if (frame.type !== ProtocolFrameType.SESSION) {
    throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
  }
  return frame.payload
}

// Low level encoders / decoders
export function encodeClientKeyShare(share: ClientKeyShare): Buffer {
  const totalLength = 2 + 2 + share.clientEphemeralPublicKey.length + SIGNATURE_BYTES
  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(KeyExchangeMessageType.CLIENT_KEY_SHARE, offset++)
  buffer.writeUInt8(share.sessionSetupVersion, offset++)

  buffer.writeUInt16BE(share.clientEphemeralPublicKey.length, offset)
  offset += 2
  share.clientEphemeralPublicKey.copy(buffer, offset)
  offset += share.clientEphemeralPublicKey.length

  share.clientKeyShareSignature.copy(buffer, offset, 0, SIGNATURE_BYTES)
  return buffer
}

export function decodeClientKeyShare(buffer: Buffer): ClientKeyShare {
  if (buffer.length < 2 || buffer.length > MAX_KEY_EXCHANGE_MESSAGE_BYTES) {
    throw new SessionError('SESSION_MESSAGE_INVALID')
  }

  let offset = 0
  const messageType = buffer.readUInt8(offset++)
  if (messageType !== KeyExchangeMessageType.CLIENT_KEY_SHARE) {
    throw new SessionError('SESSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  const sessionSetupVersion = buffer.readUInt8(offset++)
  if (sessionSetupVersion !== SESSION_SETUP_VERSION) {
    throw new SessionError('SESSION_VERSION_UNSUPPORTED')
  }

  if (offset + 2 > buffer.length) {
    throw new SessionError('SESSION_MESSAGE_INVALID')
  }
  const keyLen = buffer.readUInt16BE(offset)
  offset += 2

  if (keyLen === 0 || offset + keyLen + SIGNATURE_BYTES !== buffer.length) {
    throw new SessionError('SESSION_KEY_SHARE_INVALID')
  }

  const clientEphemeralPublicKey = Buffer.from(buffer.subarray(offset, offset + keyLen))
  offset += keyLen

  const clientKeyShareSignature = Buffer.from(buffer.subarray(offset, offset + SIGNATURE_BYTES))

  return {
    sessionSetupVersion,
    clientEphemeralPublicKey,
    clientKeyShareSignature
  }
}

export function encodeServerKeyShare(share: ServerKeyShare): Buffer {
  const totalLength = 2 + 2 + share.serverEphemeralPublicKey.length + SIGNATURE_BYTES
  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(KeyExchangeMessageType.SERVER_KEY_SHARE, offset++)
  buffer.writeUInt8(share.sessionSetupVersion, offset++)

  buffer.writeUInt16BE(share.serverEphemeralPublicKey.length, offset)
  offset += 2
  share.serverEphemeralPublicKey.copy(buffer, offset)
  offset += share.serverEphemeralPublicKey.length

  share.serverKeyShareSignature.copy(buffer, offset, 0, SIGNATURE_BYTES)
  return buffer
}

export function decodeServerKeyShare(buffer: Buffer): ServerKeyShare {
  if (buffer.length < 2 || buffer.length > MAX_KEY_EXCHANGE_MESSAGE_BYTES) {
    throw new SessionError('SESSION_MESSAGE_INVALID')
  }

  let offset = 0
  const messageType = buffer.readUInt8(offset++)
  if (messageType !== KeyExchangeMessageType.SERVER_KEY_SHARE) {
    throw new SessionError('SESSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  const sessionSetupVersion = buffer.readUInt8(offset++)
  if (sessionSetupVersion !== SESSION_SETUP_VERSION) {
    throw new SessionError('SESSION_VERSION_UNSUPPORTED')
  }

  if (offset + 2 > buffer.length) {
    throw new SessionError('SESSION_MESSAGE_INVALID')
  }
  const keyLen = buffer.readUInt16BE(offset)
  offset += 2

  if (keyLen === 0 || offset + keyLen + SIGNATURE_BYTES !== buffer.length) {
    throw new SessionError('SESSION_KEY_SHARE_INVALID')
  }

  const serverEphemeralPublicKey = Buffer.from(buffer.subarray(offset, offset + keyLen))
  offset += keyLen

  const serverKeyShareSignature = Buffer.from(buffer.subarray(offset, offset + SIGNATURE_BYTES))

  return {
    sessionSetupVersion,
    serverEphemeralPublicKey,
    serverKeyShareSignature
  }
}

export function encodeKeyConfirmMessage(
  messageType: KeyExchangeMessageType.CLIENT_KEY_CONFIRM | KeyExchangeMessageType.SERVER_KEY_CONFIRM,
  payload: EncryptedSessionPayload
): Buffer {
  const totalLength = 1 + 1 + SEQUENCE_BYTES + payload.ciphertext.length + AEAD_TAG_BYTES
  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(messageType, offset++)
  buffer.writeUInt8(payload.sessionVersion, offset++)

  buffer.writeBigUInt64BE(payload.sequence, offset)
  offset += SEQUENCE_BYTES

  payload.ciphertext.copy(buffer, offset)
  offset += payload.ciphertext.length

  payload.authTag.copy(buffer, offset, 0, AEAD_TAG_BYTES)
  return buffer
}

export function decodeKeyConfirmMessage(
  expectedMessageType:
    | KeyExchangeMessageType.CLIENT_KEY_CONFIRM
    | KeyExchangeMessageType.SERVER_KEY_CONFIRM,
  buffer: Buffer
): EncryptedSessionPayload {
  if (buffer.length < 1 + SESSION_HEADER_AND_TAG_BYTES || buffer.length > MAX_KEY_EXCHANGE_MESSAGE_BYTES) {
    throw new SessionError('SESSION_MESSAGE_INVALID')
  }

  let offset = 0
  const messageType = buffer.readUInt8(offset++)
  if (messageType !== expectedMessageType) {
    throw new SessionError('SESSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  const sessionVersion = buffer.readUInt8(offset++)
  if (sessionVersion !== SESSION_VERSION) {
    throw new SessionError('SESSION_VERSION_UNSUPPORTED')
  }

  const sequence = buffer.readBigUInt64BE(offset)
  offset += SEQUENCE_BYTES

  const ciphertextLen = buffer.length - offset - AEAD_TAG_BYTES
  const ciphertext = Buffer.from(buffer.subarray(offset, offset + ciphertextLen))
  offset += ciphertextLen

  const authTag = Buffer.from(buffer.subarray(offset, offset + AEAD_TAG_BYTES))

  return {
    sessionVersion,
    sequence,
    ciphertext,
    authTag
  }
}

export function encodeSessionPayload(payload: EncryptedSessionPayload): Buffer {
  const totalLength = 1 + SEQUENCE_BYTES + payload.ciphertext.length + AEAD_TAG_BYTES
  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(payload.sessionVersion, offset++)

  buffer.writeBigUInt64BE(payload.sequence, offset)
  offset += SEQUENCE_BYTES

  payload.ciphertext.copy(buffer, offset)
  offset += payload.ciphertext.length

  payload.authTag.copy(buffer, offset, 0, AEAD_TAG_BYTES)
  return buffer
}

export function decodeSessionPayload(buffer: Buffer): EncryptedSessionPayload {
  if (buffer.length < SESSION_HEADER_AND_TAG_BYTES) {
    throw new SessionError('SESSION_MESSAGE_INVALID')
  }

  let offset = 0
  const sessionVersion = buffer.readUInt8(offset++)
  if (sessionVersion !== SESSION_VERSION) {
    throw new SessionError('SESSION_VERSION_UNSUPPORTED')
  }

  const sequence = buffer.readBigUInt64BE(offset)
  offset += SEQUENCE_BYTES

  const ciphertextLen = buffer.length - offset - AEAD_TAG_BYTES
  const ciphertext = Buffer.from(buffer.subarray(offset, offset + ciphertextLen))
  offset += ciphertextLen

  const authTag = Buffer.from(buffer.subarray(offset, offset + AEAD_TAG_BYTES))

  return {
    sessionVersion,
    sequence,
    ciphertext,
    authTag
  }
}

// Key Derivation and Verification Helpers
export interface DerivedSessionKeys {
  readonly sessionId: Buffer
  readonly clientToServerKey: Buffer
  readonly serverToClientKey: Buffer
  readonly clientToServerNoncePrefix: Buffer
  readonly serverToClientNoncePrefix: Buffer
}

export function deriveSessionKeys(options: {
  sharedSecret: Buffer
  transcriptHash: Buffer
  serverId: string
  candidateFingerprint: string
  clientEphemeralPublicKey: Buffer
  serverEphemeralPublicKey: Buffer
}): DerivedSessionKeys {
  const sessionId = createHash('sha256')
    .update(Buffer.from(SESSION_ID_DOMAIN, 'ascii'))
    .update(options.transcriptHash)
    .update(options.clientEphemeralPublicKey)
    .update(options.serverEphemeralPublicKey)
    .digest()

  const hkdfInfo = Buffer.concat([
    Buffer.from('Masquerada/p2p-session/hkdf/v1', 'ascii'),
    Buffer.from([PROTOCOL_VERSION, HANDSHAKE_VERSION, SESSION_SETUP_VERSION]),
    Buffer.from(options.serverId, 'ascii'),
    Buffer.from(options.candidateFingerprint, 'ascii'),
    options.clientEphemeralPublicKey,
    options.serverEphemeralPublicKey
  ])

  // Total required: 32 + 32 + 4 + 4 = 72 bytes
  const derivedBuffer = Buffer.from(
    hkdfSync('sha256', options.sharedSecret, options.transcriptHash, hkdfInfo, 72)
  )

  let offset = 0
  const clientToServerKey = Buffer.from(derivedBuffer.subarray(offset, offset + AES_KEY_BYTES))
  offset += AES_KEY_BYTES

  const serverToClientKey = Buffer.from(derivedBuffer.subarray(offset, offset + AES_KEY_BYTES))
  offset += AES_KEY_BYTES

  const clientToServerNoncePrefix = Buffer.from(
    derivedBuffer.subarray(offset, offset + NONCE_PREFIX_BYTES)
  )
  offset += NONCE_PREFIX_BYTES

  const serverToClientNoncePrefix = Buffer.from(
    derivedBuffer.subarray(offset, offset + NONCE_PREFIX_BYTES)
  )
  derivedBuffer.fill(0)

  return {
    sessionId,
    clientToServerKey,
    serverToClientKey,
    clientToServerNoncePrefix,
    serverToClientNoncePrefix
  }
}

export function buildAeadNonce(noncePrefix: Buffer, sequence: bigint): Buffer {
  const nonce = Buffer.allocUnsafe(NONCE_BYTES)
  noncePrefix.copy(nonce, 0, 0, NONCE_PREFIX_BYTES)
  nonce.writeBigUInt64BE(sequence, NONCE_PREFIX_BYTES)
  return nonce
}

export function buildAeadAssociatedData(
  direction: number,
  sessionId: Buffer,
  transcriptHash: Buffer,
  sequence: bigint
): Buffer {
  const domainBuffer = Buffer.from(SESSION_AEAD_DOMAIN, 'ascii')
  const seqBuf = Buffer.allocUnsafe(SEQUENCE_BYTES)
  seqBuf.writeBigUInt64BE(sequence, 0)

  return Buffer.concat([
    domainBuffer,
    Buffer.from([PROTOCOL_VERSION, SESSION_VERSION, direction]),
    sessionId,
    transcriptHash,
    seqBuf
  ])
}

export function buildClientKeySharePayload(
  transcriptHash: Buffer,
  serverId: string,
  candidateFingerprint: string,
  clientEphemeralPublicKey: Buffer
): Buffer {
  const domainBuffer = Buffer.from(CLIENT_KEY_SHARE_DOMAIN, 'ascii')
  const serverIdBuffer = Buffer.from(serverId, 'ascii')
  const candidateFingerprintBuffer = Buffer.from(candidateFingerprint, 'ascii')

  return Buffer.concat([
    domainBuffer,
    Buffer.from([PROTOCOL_VERSION, HANDSHAKE_VERSION, SESSION_SETUP_VERSION]),
    transcriptHash,
    Buffer.from([serverIdBuffer.length]),
    serverIdBuffer,
    Buffer.from([candidateFingerprintBuffer.length]),
    candidateFingerprintBuffer,
    clientEphemeralPublicKey
  ])
}

export function buildServerKeySharePayload(
  transcriptHash: Buffer,
  serverId: string,
  candidateFingerprint: string,
  clientEphemeralPublicKey: Buffer,
  serverEphemeralPublicKey: Buffer
): Buffer {
  const domainBuffer = Buffer.from(SERVER_KEY_SHARE_DOMAIN, 'ascii')
  const serverIdBuffer = Buffer.from(serverId, 'ascii')
  const candidateFingerprintBuffer = Buffer.from(candidateFingerprint, 'ascii')

  return Buffer.concat([
    domainBuffer,
    Buffer.from([PROTOCOL_VERSION, HANDSHAKE_VERSION, SESSION_SETUP_VERSION]),
    transcriptHash,
    Buffer.from([serverIdBuffer.length]),
    serverIdBuffer,
    Buffer.from([candidateFingerprintBuffer.length]),
    candidateFingerprintBuffer,
    clientEphemeralPublicKey,
    serverEphemeralPublicKey
  ])
}

function validateX25519PublicKey(derBytes: Buffer): Buffer {
  try {
    const keyObject = createPublicKey({
      key: derBytes,
      format: 'der',
      type: 'spki'
    })

    if (keyObject.type !== 'public' || keyObject.asymmetricKeyType !== 'x25519') {
      throw new SessionError('SESSION_KEY_SHARE_INVALID')
    }

    const canonical = keyObject.export({ format: 'der', type: 'spki' })
    return Buffer.from(canonical)
  } catch (error) {
    if (error instanceof SessionError) throw error
    throw new SessionError('SESSION_KEY_SHARE_INVALID')
  }
}

function computeX25519SharedSecret(
  privateKey: KeyObject,
  publicKey: KeyObject
): Buffer {
  try {
    const secret = diffieHellman({
      privateKey,
      publicKey
    })
    return secret
  } catch {
    throw new SessionError('SESSION_DIFFIE_HELLMAN_FAILED')
  }
}
