import {
  isEstablishedClientHandshakeContext,
  isEstablishedServerHandshakeContext,
  type EstablishedClientHandshakeContext,
  type EstablishedServerHandshakeContext
} from '../security/authenticated-candidate'
import {
  type LocalServerStorage
} from '../servers/local-server-storage'
import {
  type Member
} from '../servers/server-database'
import {
  encodeSessionFrame,
  isSecureSession,
  SessionError,
  type SecureSession
} from './p2p-session'
import {
  decodeSingleProtocolFrame,
  ProtocolError,
  ProtocolFrameType
} from './protocol-frame'

export const ADMISSION_PROTOCOL_VERSION = 1
export const MAX_ADMISSION_REQUEST_BYTES = 8192
export const MAX_ADMISSION_RESPONSE_BYTES = 1024
export const MAX_INVITE_TOKEN_BYTES = 4096

export enum AdmissionMessageType {
  ADMISSION_REQUEST = 0x01,
  ADMISSION_RESPONSE = 0x02,
  MEMBER_RECONNECT_REQUEST = 0x03,
  MEMBER_RECONNECT_RESPONSE = 0x04
}

export enum AdmissionResponseStatus {
  SUCCESS = 0x01,
  REJECTED = 0x02,
  ALREADY_MEMBER = 0x03
}

export enum MemberReconnectResponseStatus {
  AUTHORIZED = 0x01,
  REJECTED = 0x02
}

export type AdmissionErrorCode =
  | 'ADMISSION_CONTEXT_INVALID'
  | 'ADMISSION_SESSION_INVALID'
  | 'ADMISSION_SERVER_MISMATCH'
  | 'ADMISSION_CANDIDATE_MISMATCH'
  | 'ADMISSION_MESSAGE_INVALID'
  | 'ADMISSION_MESSAGE_TYPE_UNSUPPORTED'
  | 'ADMISSION_VERSION_UNSUPPORTED'
  | 'ADMISSION_REQUEST_TOO_LARGE'
  | 'ADMISSION_INVITE_INVALID'
  | 'ADMISSION_STATE_INVALID'
  | 'ADMISSION_RECONNECT_REJECTED'
  | 'ADMISSION_FAILED'

const ERROR_MESSAGES: Record<AdmissionErrorCode, string> = {
  ADMISSION_CONTEXT_INVALID: 'O contexto de handshake autenticado para admissão é inválido.',
  ADMISSION_SESSION_INVALID: 'A sessão segura fornecida para admissão é inválida ou incompatível.',
  ADMISSION_SERVER_MISMATCH: 'O servidor local não corresponde ao serverId autenticado na sessão.',
  ADMISSION_CANDIDATE_MISMATCH: 'A identidade do candidato não corresponde ao contexto da sessão.',
  ADMISSION_MESSAGE_INVALID: 'A mensagem de admissão recebida é inválida, truncada ou malformada.',
  ADMISSION_MESSAGE_TYPE_UNSUPPORTED: 'O tipo da mensagem do protocolo de admissão não é suportado.',
  ADMISSION_VERSION_UNSUPPORTED: 'A versão do protocolo de admissão recebida não é suportada.',
  ADMISSION_REQUEST_TOO_LARGE: 'O tamanho da requisição de admissão excede o limite máximo permitido.',
  ADMISSION_INVITE_INVALID: 'O token de convite fornecido é inválido ou malformado.',
  ADMISSION_STATE_INVALID: 'A operação de admissão foi chamada em um estado inválido.',
  ADMISSION_RECONNECT_REJECTED: 'A reconexão de membro existente foi rejeitada pelo servidor.',
  ADMISSION_FAILED: 'Falha durante o processamento da admissão do membro.'
}

export class AdmissionError extends Error {
  readonly code: AdmissionErrorCode

  constructor(code: AdmissionErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'AdmissionError'
    this.code = code
  }
}

export interface AdmissionRequest {
  readonly version: number
  readonly messageType: AdmissionMessageType.ADMISSION_REQUEST
  readonly invite: string
}

export interface AdmissionResponse {
  readonly version: number
  readonly messageType: AdmissionMessageType.ADMISSION_RESPONSE
  readonly status: AdmissionResponseStatus
}

export interface MemberReconnectRequest {
  readonly version: number
  readonly messageType: AdmissionMessageType.MEMBER_RECONNECT_REQUEST
}

export interface MemberReconnectResponse {
  readonly version: number
  readonly messageType: AdmissionMessageType.MEMBER_RECONNECT_RESPONSE
  readonly status: MemberReconnectResponseStatus
}

export interface ClientAdmissionResult {
  readonly status: 'admitted' | 'already_member' | 'rejected'
}

export interface ClientReconnectResult {
  readonly status: 'authorized' | 'rejected'
}

export interface ServerAdmissionProcessResult {
  readonly status: 'admitted' | 'already_member' | 'rejected'
  readonly responseFrame: Buffer
  readonly member?: Member
}

export interface ServerAuthorizationResult {
  readonly mode: 'admission' | 'reconnect'
  readonly status: 'admitted' | 'already_member' | 'authorized' | 'rejected'
  readonly responseFrame: Buffer
  readonly member?: Member
}

export class ClientAdmissionFlow {
  private state: 'INITIAL' | 'WAITING_RESPONSE' | 'COMPLETED' | 'FAILED' = 'INITIAL'
  private readonly context: EstablishedClientHandshakeContext
  private readonly session: SecureSession
  private readonly invite: string

  constructor(options: {
    context: EstablishedClientHandshakeContext
    session: SecureSession
    invite: string
  }) {
    if (!isEstablishedClientHandshakeContext(options.context)) {
      throw new AdmissionError('ADMISSION_CONTEXT_INVALID')
    }
    if (!isSecureSession(options.session) || options.session.role !== 'client') {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }
    if (
      !options.session.transcriptHash.equals(options.context.transcriptHash)
    ) {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }

    if (
      typeof options.invite !== 'string' ||
      options.invite.trim().length === 0 ||
      Buffer.byteLength(options.invite, 'ascii') > MAX_INVITE_TOKEN_BYTES
    ) {
      throw new AdmissionError('ADMISSION_INVITE_INVALID')
    }

    this.context = options.context
    this.session = options.session
    this.invite = options.invite.trim()
  }

  createEncryptedAdmissionRequest(): Buffer {
    if (this.state !== 'INITIAL') {
      this.state = 'FAILED'
      throw new AdmissionError('ADMISSION_STATE_INVALID')
    }

    try {
      const requestPayload = encodeAdmissionRequest({
        version: ADMISSION_PROTOCOL_VERSION,
        messageType: AdmissionMessageType.ADMISSION_REQUEST,
        invite: this.invite
      })

      const encryptedPayload = this.session.encrypt(requestPayload)
      const sessionFrame = encodeSessionFrame(encryptedPayload)

      this.state = 'WAITING_RESPONSE'
      return sessionFrame
    } catch (error) {
      this.state = 'FAILED'
      this.session.destroy()
      if (
        error instanceof AdmissionError ||
        error instanceof ProtocolError ||
        error instanceof SessionError
      ) {
        throw error
      }
      throw new AdmissionError('ADMISSION_FAILED')
    }
  }

  processEncryptedAdmissionResponse(responseFrameBytes: Buffer): ClientAdmissionResult {
    if (this.state !== 'WAITING_RESPONSE') {
      this.state = 'FAILED'
      throw new AdmissionError('ADMISSION_STATE_INVALID')
    }

    try {
      const frame = decodeSingleProtocolFrame(responseFrameBytes)
      if (frame.type !== ProtocolFrameType.SESSION) {
        throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
      }

      const decryptedPayload = this.session.decrypt(frame.payload)
      const response = decodeAdmissionResponse(decryptedPayload)

      this.state = 'COMPLETED'

      if (response.status === AdmissionResponseStatus.SUCCESS) {
        return { status: 'admitted' }
      } else if (response.status === AdmissionResponseStatus.ALREADY_MEMBER) {
        return { status: 'already_member' }
      } else {
        this.session.destroy()
        return { status: 'rejected' }
      }
    } catch (error) {
      this.state = 'FAILED'
      this.session.destroy()
      if (
        error instanceof AdmissionError ||
        error instanceof ProtocolError ||
        error instanceof SessionError
      ) {
        throw error
      }
      throw new AdmissionError('ADMISSION_FAILED')
    }
  }

  getState(): string {
    return this.state
  }
}

export class ClientMemberReconnectFlow {
  private state: 'INITIAL' | 'WAITING_RESPONSE' | 'COMPLETED' | 'FAILED' = 'INITIAL'
  private readonly context: EstablishedClientHandshakeContext
  private readonly session: SecureSession

  constructor(options: {
    context: EstablishedClientHandshakeContext
    session: SecureSession
  }) {
    if (!isEstablishedClientHandshakeContext(options.context)) {
      throw new AdmissionError('ADMISSION_CONTEXT_INVALID')
    }
    if (!isSecureSession(options.session) || options.session.role !== 'client') {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }
    if (
      !options.session.transcriptHash.equals(options.context.transcriptHash)
    ) {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }

    this.context = options.context
    this.session = options.session
  }

  createEncryptedReconnectRequest(): Buffer {
    if (this.state !== 'INITIAL') {
      this.state = 'FAILED'
      throw new AdmissionError('ADMISSION_STATE_INVALID')
    }

    try {
      const requestPayload = encodeMemberReconnectRequest({
        version: ADMISSION_PROTOCOL_VERSION,
        messageType: AdmissionMessageType.MEMBER_RECONNECT_REQUEST
      })

      const encryptedPayload = this.session.encrypt(requestPayload)
      const sessionFrame = encodeSessionFrame(encryptedPayload)

      this.state = 'WAITING_RESPONSE'
      return sessionFrame
    } catch (error) {
      this.state = 'FAILED'
      this.session.destroy()
      if (
        error instanceof AdmissionError ||
        error instanceof ProtocolError ||
        error instanceof SessionError
      ) {
        throw error
      }
      throw new AdmissionError('ADMISSION_FAILED')
    }
  }

  processEncryptedReconnectResponse(responseFrameBytes: Buffer): ClientReconnectResult {
    if (this.state !== 'WAITING_RESPONSE') {
      this.state = 'FAILED'
      throw new AdmissionError('ADMISSION_STATE_INVALID')
    }

    try {
      const frame = decodeSingleProtocolFrame(responseFrameBytes)
      if (frame.type !== ProtocolFrameType.SESSION) {
        throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
      }

      const decryptedPayload = this.session.decrypt(frame.payload)
      const response = decodeMemberReconnectResponse(decryptedPayload)

      this.state = 'COMPLETED'

      if (response.status === MemberReconnectResponseStatus.AUTHORIZED) {
        return { status: 'authorized' }
      } else {
        this.session.destroy()
        return { status: 'rejected' }
      }
    } catch (error) {
      this.state = 'FAILED'
      this.session.destroy()
      if (
        error instanceof AdmissionError ||
        error instanceof ProtocolError ||
        error instanceof SessionError
      ) {
        throw error
      }
      throw new AdmissionError('ADMISSION_FAILED')
    }
  }

  getState(): string {
    return this.state
  }
}

export class ServerAdmissionHandler {
  private state: 'WAITING_REQUEST' | 'COMPLETED' | 'FAILED' = 'WAITING_REQUEST'
  private readonly storage: LocalServerStorage
  private readonly localStorageId: string
  private readonly serverContext: EstablishedServerHandshakeContext
  private readonly session: SecureSession

  constructor(options: {
    storage: LocalServerStorage
    localStorageId: string
    serverContext: EstablishedServerHandshakeContext
    session: SecureSession
  }) {
    if (!isEstablishedServerHandshakeContext(options.serverContext)) {
      throw new AdmissionError('ADMISSION_CONTEXT_INVALID')
    }
    if (!isSecureSession(options.session) || options.session.role !== 'server') {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }
    if (
      !options.session.transcriptHash.equals(options.serverContext.transcriptHash)
    ) {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }

    this.storage = options.storage
    this.localStorageId = options.localStorageId
    this.serverContext = options.serverContext
    this.session = options.session
  }

  async processEncryptedAdmissionRequest(
    requestFrameBytes: Buffer
  ): Promise<ServerAdmissionProcessResult> {
    if (this.state !== 'WAITING_REQUEST') {
      this.state = 'FAILED'
      throw new AdmissionError('ADMISSION_STATE_INVALID')
    }

    try {
      // 1. Carrega servidor local e valida serverId binding
      const localServer = await this.storage.loadLocalServer(this.localStorageId)
      if (localServer.serverId !== this.serverContext.serverId) {
        throw new AdmissionError('ADMISSION_SERVER_MISMATCH')
      }

      // 2. Framing: exige ProtocolFrameType.SESSION
      const frame = decodeSingleProtocolFrame(requestFrameBytes)
      if (frame.type !== ProtocolFrameType.SESSION) {
        throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
      }

      // 3. Decripta com SecureSession (exatamente uma vez)
      const decryptedPlaintext = this.session.decrypt(frame.payload)

      // 4. Parseia ADMISSION_REQUEST
      const request = decodeAdmissionRequest(decryptedPlaintext)

      // 5. Executa admissão atômica usando AuthenticatedCandidateDevice do contexto da sessão
      let admissionResult:
        | { status: 'admitted'; member: Member }
        | { status: 'already_member' }
        | { status: 'rejected' }

      try {
        const admittedMember = await this.storage.admitLocalServerMemberWithInvite(
          this.localStorageId,
          request.invite,
          this.serverContext.candidate
        )
        admissionResult = { status: 'admitted', member: admittedMember }
      } catch (admissionErr: unknown) {
        if (
          typeof admissionErr === 'object' &&
          admissionErr !== null &&
          'code' in admissionErr &&
          (admissionErr as { code: string }).code === 'SERVER_MEMBER_ALREADY_EXISTS'
        ) {
          admissionResult = { status: 'already_member' }
        } else {
          admissionResult = { status: 'rejected' }
        }
      }

      // 6. Constrói resposta binária confidencial
      let responseStatus: AdmissionResponseStatus
      if (admissionResult.status === 'admitted') {
        responseStatus = AdmissionResponseStatus.SUCCESS
      } else if (admissionResult.status === 'already_member') {
        responseStatus = AdmissionResponseStatus.ALREADY_MEMBER
      } else {
        responseStatus = AdmissionResponseStatus.REJECTED
      }

      const encodedResponse = encodeAdmissionResponse({
        version: ADMISSION_PROTOCOL_VERSION,
        messageType: AdmissionMessageType.ADMISSION_RESPONSE,
        status: responseStatus
      })

      const encryptedResponsePayload = this.session.encrypt(encodedResponse)
      const responseFrame = encodeSessionFrame(encryptedResponsePayload)

      this.state = 'COMPLETED'

      if (admissionResult.status === 'rejected') {
        this.session.destroy()
        return {
          status: 'rejected',
          responseFrame
        }
      }

      return {
        status: admissionResult.status,
        responseFrame,
        member: admissionResult.status === 'admitted' ? admissionResult.member : undefined
      }
    } catch (error) {
      this.state = 'FAILED'
      this.session.destroy()
      if (
        error instanceof AdmissionError ||
        error instanceof ProtocolError ||
        error instanceof SessionError
      ) {
        throw error
      }
      throw new AdmissionError('ADMISSION_FAILED')
    }
  }

  getState(): string {
    return this.state
  }
}

/**
 * Roteador de autorização inicial do servidor:
 * Decripta o primeiro frame de aplicação exatamente uma vez e direciona
 * para Admission ou para Reconnect de membro existente.
 */
export class ServerAuthorizationRouter {
  private state: 'WAITING_REQUEST' | 'COMPLETED' | 'FAILED' = 'WAITING_REQUEST'
  private readonly storage: LocalServerStorage
  private readonly localStorageId: string
  private readonly serverContext: EstablishedServerHandshakeContext
  private readonly session: SecureSession

  constructor(options: {
    storage: LocalServerStorage
    localStorageId: string
    serverContext: EstablishedServerHandshakeContext
    session: SecureSession
  }) {
    if (!isEstablishedServerHandshakeContext(options.serverContext)) {
      throw new AdmissionError('ADMISSION_CONTEXT_INVALID')
    }
    if (!isSecureSession(options.session) || options.session.role !== 'server') {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }
    if (
      !options.session.transcriptHash.equals(options.serverContext.transcriptHash)
    ) {
      throw new AdmissionError('ADMISSION_SESSION_INVALID')
    }

    this.storage = options.storage
    this.localStorageId = options.localStorageId
    this.serverContext = options.serverContext
    this.session = options.session
  }

  async processEncryptedAuthorizationRequest(
    requestFrameBytes: Buffer
  ): Promise<ServerAuthorizationResult> {
    if (this.state !== 'WAITING_REQUEST') {
      this.state = 'FAILED'
      throw new AdmissionError('ADMISSION_STATE_INVALID')
    }

    try {
      // 1. Valida serverId binding
      const localServer = await this.storage.loadLocalServer(this.localStorageId)
      if (localServer.serverId !== this.serverContext.serverId) {
        throw new AdmissionError('ADMISSION_SERVER_MISMATCH')
      }

      // 2. Framing: exige ProtocolFrameType.SESSION
      const frame = decodeSingleProtocolFrame(requestFrameBytes)
      if (frame.type !== ProtocolFrameType.SESSION) {
        throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
      }

      // 3. Decripta com SecureSession (EXATAMENTE UMA VEZ)
      const decryptedPlaintext = this.session.decrypt(frame.payload)

      if (decryptedPlaintext.length < 2) {
        throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
      }

      const version = decryptedPlaintext.readUInt8(0)
      if (version !== ADMISSION_PROTOCOL_VERSION) {
        throw new AdmissionError('ADMISSION_VERSION_UNSUPPORTED')
      }

      const messageType = decryptedPlaintext.readUInt8(1)

      // Roteamento conforme messageType
      if (messageType === AdmissionMessageType.ADMISSION_REQUEST) {
        // FLUXO DE ADMISSÃO (0x01)
        const request = decodeAdmissionRequest(decryptedPlaintext)
        let admissionResult:
          | { status: 'admitted'; member: Member }
          | { status: 'already_member' }
          | { status: 'rejected' }

        try {
          const admittedMember = await this.storage.admitLocalServerMemberWithInvite(
            this.localStorageId,
            request.invite,
            this.serverContext.candidate
          )
          admissionResult = { status: 'admitted', member: admittedMember }
        } catch (admissionErr: unknown) {
          if (
            typeof admissionErr === 'object' &&
            admissionErr !== null &&
            'code' in admissionErr &&
            (admissionErr as { code: string }).code === 'SERVER_MEMBER_ALREADY_EXISTS'
          ) {
            admissionResult = { status: 'already_member' }
          } else {
            admissionResult = { status: 'rejected' }
          }
        }

        let responseStatus: AdmissionResponseStatus
        if (admissionResult.status === 'admitted') {
          responseStatus = AdmissionResponseStatus.SUCCESS
        } else if (admissionResult.status === 'already_member') {
          responseStatus = AdmissionResponseStatus.ALREADY_MEMBER
        } else {
          responseStatus = AdmissionResponseStatus.REJECTED
        }

        const encodedResponse = encodeAdmissionResponse({
          version: ADMISSION_PROTOCOL_VERSION,
          messageType: AdmissionMessageType.ADMISSION_RESPONSE,
          status: responseStatus
        })

        const encryptedResponsePayload = this.session.encrypt(encodedResponse)
        const responseFrame = encodeSessionFrame(encryptedResponsePayload)

        this.state = 'COMPLETED'

        if (admissionResult.status === 'rejected') {
          this.session.destroy()
        }

        return {
          mode: 'admission',
          status: admissionResult.status,
          responseFrame,
          member: admissionResult.status === 'admitted' ? admissionResult.member : undefined
        }
      } else if (messageType === AdmissionMessageType.MEMBER_RECONNECT_REQUEST) {
        // FLUXO DE RECONEXÃO DE MEMBRO EXISTENTE (0x03)
        decodeMemberReconnectRequest(decryptedPlaintext)

        // Deriva a identidade exclusivamente do candidate autenticado na sessão
        const candidate = this.serverContext.candidate
        let authResult: { isAuthorized: boolean; member?: Member }

        try {
          authResult = await this.storage.verifyLocalServerMemberAuthorization(
            this.localStorageId,
            candidate.fingerprint
          )
        } catch {
          authResult = { isAuthorized: false }
        }

        const responseStatus = authResult.isAuthorized
          ? MemberReconnectResponseStatus.AUTHORIZED
          : MemberReconnectResponseStatus.REJECTED

        const encodedResponse = encodeMemberReconnectResponse({
          version: ADMISSION_PROTOCOL_VERSION,
          messageType: AdmissionMessageType.MEMBER_RECONNECT_RESPONSE,
          status: responseStatus
        })

        const encryptedResponsePayload = this.session.encrypt(encodedResponse)
        const responseFrame = encodeSessionFrame(encryptedResponsePayload)

        this.state = 'COMPLETED'

        if (!authResult.isAuthorized) {
          this.session.destroy()
          return {
            mode: 'reconnect',
            status: 'rejected',
            responseFrame
          }
        }

        return {
          mode: 'reconnect',
          status: 'authorized',
          responseFrame,
          member: authResult.member
        }
      } else {
        throw new AdmissionError('ADMISSION_MESSAGE_TYPE_UNSUPPORTED')
      }
    } catch (error) {
      this.state = 'FAILED'
      this.session.destroy()
      if (
        error instanceof AdmissionError ||
        error instanceof ProtocolError ||
        error instanceof SessionError
      ) {
        throw error
      }
      throw new AdmissionError('ADMISSION_FAILED')
    }
  }

  getState(): string {
    return this.state
  }
}

// Canonical Encoders / Decoders
export function encodeAdmissionRequest(request: AdmissionRequest): Buffer {
  const inviteBuffer = Buffer.from(request.invite, 'ascii')
  const totalLength = 1 + 1 + 2 + inviteBuffer.length

  if (totalLength > MAX_ADMISSION_REQUEST_BYTES) {
    throw new AdmissionError('ADMISSION_REQUEST_TOO_LARGE')
  }

  const buffer = Buffer.allocUnsafe(totalLength)
  let offset = 0

  buffer.writeUInt8(request.version, offset++)
  buffer.writeUInt8(request.messageType, offset++)

  buffer.writeUInt16BE(inviteBuffer.length, offset)
  offset += 2

  inviteBuffer.copy(buffer, offset)
  return buffer
}

export function decodeAdmissionRequest(buffer: Buffer): AdmissionRequest {
  if (buffer.length < 4 || buffer.length > MAX_ADMISSION_REQUEST_BYTES) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  let offset = 0
  const version = buffer.readUInt8(offset++)
  if (version !== ADMISSION_PROTOCOL_VERSION) {
    throw new AdmissionError('ADMISSION_VERSION_UNSUPPORTED')
  }

  const messageType = buffer.readUInt8(offset++)
  if (messageType !== AdmissionMessageType.ADMISSION_REQUEST) {
    throw new AdmissionError('ADMISSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  const inviteLen = buffer.readUInt16BE(offset)
  offset += 2

  if (
    inviteLen === 0 ||
    inviteLen > MAX_INVITE_TOKEN_BYTES ||
    offset + inviteLen !== buffer.length
  ) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  const invite = buffer.subarray(offset, offset + inviteLen).toString('ascii')

  if (!invite.startsWith('MQR1.') || !/^[A-Za-z0-9._-]+$/.test(invite)) {
    throw new AdmissionError('ADMISSION_INVITE_INVALID')
  }

  return {
    version,
    messageType: AdmissionMessageType.ADMISSION_REQUEST,
    invite
  }
}

export function encodeAdmissionResponse(response: AdmissionResponse): Buffer {
  const buffer = Buffer.allocUnsafe(3)
  buffer.writeUInt8(response.version, 0)
  buffer.writeUInt8(response.messageType, 1)
  buffer.writeUInt8(response.status, 2)
  return buffer
}

export function decodeAdmissionResponse(buffer: Buffer): AdmissionResponse {
  if (buffer.length !== 3) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  const version = buffer.readUInt8(0)
  if (version !== ADMISSION_PROTOCOL_VERSION) {
    throw new AdmissionError('ADMISSION_VERSION_UNSUPPORTED')
  }

  const messageType = buffer.readUInt8(1)
  if (messageType !== AdmissionMessageType.ADMISSION_RESPONSE) {
    throw new AdmissionError('ADMISSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  const status = buffer.readUInt8(2)
  if (
    status !== AdmissionResponseStatus.SUCCESS &&
    status !== AdmissionResponseStatus.REJECTED &&
    status !== AdmissionResponseStatus.ALREADY_MEMBER
  ) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  return {
    version,
    messageType: AdmissionMessageType.ADMISSION_RESPONSE,
    status
  }
}

export function encodeMemberReconnectRequest(
  request: MemberReconnectRequest = {
    version: ADMISSION_PROTOCOL_VERSION,
    messageType: AdmissionMessageType.MEMBER_RECONNECT_REQUEST
  }
): Buffer {
  const buffer = Buffer.allocUnsafe(2)
  buffer.writeUInt8(request.version, 0)
  buffer.writeUInt8(request.messageType, 1)
  return buffer
}

export function decodeMemberReconnectRequest(buffer: Buffer): MemberReconnectRequest {
  if (buffer.length !== 2) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  const version = buffer.readUInt8(0)
  if (version !== ADMISSION_PROTOCOL_VERSION) {
    throw new AdmissionError('ADMISSION_VERSION_UNSUPPORTED')
  }

  const messageType = buffer.readUInt8(1)
  if (messageType !== AdmissionMessageType.MEMBER_RECONNECT_REQUEST) {
    throw new AdmissionError('ADMISSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  return {
    version,
    messageType: AdmissionMessageType.MEMBER_RECONNECT_REQUEST
  }
}

export function encodeMemberReconnectResponse(response: MemberReconnectResponse): Buffer {
  const buffer = Buffer.allocUnsafe(3)
  buffer.writeUInt8(response.version, 0)
  buffer.writeUInt8(response.messageType, 1)
  buffer.writeUInt8(response.status, 2)
  return buffer
}

export function decodeMemberReconnectResponse(buffer: Buffer): MemberReconnectResponse {
  if (buffer.length !== 3) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  const version = buffer.readUInt8(0)
  if (version !== ADMISSION_PROTOCOL_VERSION) {
    throw new AdmissionError('ADMISSION_VERSION_UNSUPPORTED')
  }

  const messageType = buffer.readUInt8(1)
  if (messageType !== AdmissionMessageType.MEMBER_RECONNECT_RESPONSE) {
    throw new AdmissionError('ADMISSION_MESSAGE_TYPE_UNSUPPORTED')
  }

  const status = buffer.readUInt8(2)
  if (
    status !== MemberReconnectResponseStatus.AUTHORIZED &&
    status !== MemberReconnectResponseStatus.REJECTED
  ) {
    throw new AdmissionError('ADMISSION_MESSAGE_INVALID')
  }

  return {
    version,
    messageType: AdmissionMessageType.MEMBER_RECONNECT_RESPONSE,
    status
  }
}
