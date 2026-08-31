import { createServer, createConnection, type Server, type Socket } from 'node:net'
import { type KeyObject } from 'node:crypto'

import {
  type EstablishedClientHandshakeContext,
  type EstablishedServerHandshakeContext
} from '../security/authenticated-candidate'
import {
  type LocalServerStorage
} from '../servers/local-server-storage'
import {
  ClientAdmissionFlow,
  ClientMemberReconnectFlow,
  ServerAuthorizationRouter
} from './p2p-admission'
import {
  ClientHandshake,
  ServerHandshake
} from './p2p-handshake'
import {
  ClientSessionSetup,
  encodeSessionFrame,
  SecureSession,
  ServerSessionSetup
} from './p2p-session'
import {
  encodeProtocolFrame,
  ProtocolFrameDecoder,
  ProtocolFrameType,
  type ProtocolFrame
} from './protocol-frame'
import { classifyNetworkAddress } from './network-interfaces'
import {
  isMasqueradaTransportStream,
  type MasqueradaTransportStream
} from './masquerada-transport-stream'

export const DEFAULT_LOOPBACK_HOST = '127.0.0.1'
export const ALLOWED_LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost'])

export const HANDSHAKE_TIMEOUT_MS = 5000
export const SESSION_SETUP_TIMEOUT_MS = 5000
export const ADMISSION_TIMEOUT_MS = 5000
export const IDLE_TIMEOUT_MS = 30000

export const MAX_INBOUND_CONNECTIONS = 64
export const MAX_CONNECTIONS_PER_IP = 16
export const MAX_PENDING_WRITE_BYTES = 1024 * 1024 // 1 MB

export type TcpTransportErrorCode =
  | 'TCP_INVALID_HOST'
  | 'TCP_INVALID_PORT'
  | 'TCP_CONNECTION_LIMIT_EXCEEDED'
  | 'TCP_IP_CONNECTION_LIMIT_EXCEEDED'
  | 'TCP_TIMEOUT'
  | 'TCP_PROTOCOL_VIOLATION'
  | 'TCP_WRONG_FRAME_TYPE'
  | 'TCP_BACKPRESSURE_OVERFLOW'
  | 'TCP_CONNECTION_CLOSED'
  | 'TCP_CONNECTION_FAILED'
  | 'TCP_LISTENER_FAILED'
  | 'TCP_ADMISSION_REJECTED'
  | 'TCP_BIND_ADDRESS_IN_USE'
  | 'TCP_BIND_ADDRESS_UNAVAILABLE'
  | 'TCP_BIND_PERMISSION_DENIED'
  | 'TCP_ENDPOINT_INVALID'
  | 'TCP_CONNECT_TIMEOUT'
  | 'TCP_WILDCARD_PROHIBITED'
  | 'TCP_GLOBAL_ADDRESS_PROHIBITED'

const ERROR_MESSAGES: Record<TcpTransportErrorCode, string> = {
  TCP_INVALID_HOST: 'O endereço de host fornecido é inválido ou não permitido.',
  TCP_INVALID_PORT: 'A porta fornecida é inválida.',
  TCP_CONNECTION_LIMIT_EXCEEDED: 'O limite máximo de conexões simultâneas foi atingido.',
  TCP_IP_CONNECTION_LIMIT_EXCEEDED: 'O limite de conexões simultâneas para este endereço IP foi atingido.',
  TCP_TIMEOUT: 'A operação de rede excedeu o tempo limite permitido.',
  TCP_PROTOCOL_VIOLATION: 'Violação de protocolo detectada no stream TCP.',
  TCP_WRONG_FRAME_TYPE: 'Tipo de frame inesperado recebido para o estado atual da conexão.',
  TCP_BACKPRESSURE_OVERFLOW: 'A fila de escrita do socket excedeu o limite máximo de bytes pendentes.',
  TCP_CONNECTION_CLOSED: 'A conexão TCP foi encerrada.',
  TCP_CONNECTION_FAILED: 'Falha ao estabelecer ou manter a conexão TCP.',
  TCP_LISTENER_FAILED: 'Falha ao inicializar o listener TCP.',
  TCP_ADMISSION_REJECTED: 'A admissão do membro foi rejeitada pelo host do servidor.',
  TCP_BIND_ADDRESS_IN_USE: 'O endereço ou porta solicitado já está em uso pelo sistema operacional.',
  TCP_BIND_ADDRESS_UNAVAILABLE: 'O endereço de bind solicitado não está atribuído ou disponível nas interfaces locais.',
  TCP_BIND_PERMISSION_DENIED: 'Permissão negada pelo sistema operacional para realizar o bind no endereço/porta especificado.',
  TCP_ENDPOINT_INVALID: 'O endpoint fornecido é inválido ou não é um IP numérico suportado.',
  TCP_CONNECT_TIMEOUT: 'A tentativa de conexão TCP ao endpoint excedeu o tempo limite (CONNECT_TIMEOUT_MS).',
  TCP_WILDCARD_PROHIBITED: 'O uso de endereços wildcard (0.0.0.0 ou ::) é expressamente proibido no Masquerada.',
  TCP_GLOBAL_ADDRESS_PROHIBITED: 'Endereços IP publicamente roteáveis (WAN/Global) não são permitidos nesta etapa de LAN.'
}

export class TcpTransportError extends Error {
  readonly code: TcpTransportErrorCode

  constructor(code: TcpTransportErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'TcpTransportError'
    this.code = code
  }
}

export type ClientConnectionState =
  | 'CONNECTING'
  | 'HANDSHAKE'
  | 'SESSION_SETUP'
  | 'SECURE_UNAUTHORIZED'
  | 'ADMISSION'
  | 'MEMBER_CONNECTED'
  | 'FAILED'
  | 'CLOSED'

export type ServerConnectionState =
  | 'CONNECTED'
  | 'HANDSHAKE'
  | 'SESSION_SETUP'
  | 'SECURE_UNADMITTED'
  | 'ADMISSION'
  | 'MEMBER_CONNECTED'
  | 'FAILED'
  | 'CLOSED'

export function assertValidHost(host: string): void {
  if (
    typeof host !== 'string' ||
    host.length === 0 ||
    host.length > 255
  ) {
    throw new TcpTransportError('TCP_INVALID_HOST')
  }

  for (let i = 0; i < host.length; i++) {
    const code = host.charCodeAt(i)
    if (code < 32 || code === 127) {
      throw new TcpTransportError('TCP_INVALID_HOST')
    }
  }

  if (!ALLOWED_LOOPBACK_HOSTS.has(host.toLowerCase())) {
    throw new TcpTransportError('TCP_INVALID_HOST')
  }
}

export function assertValidPort(port: number, allowZero = false): void {
  if (
    typeof port !== 'number' ||
    !Number.isInteger(port) ||
    Number.isNaN(port) ||
    (allowZero ? port < 0 : port < 1) ||
    port > 65535
  ) {
    throw new TcpTransportError('TCP_INVALID_PORT')
  }
}

export interface StartTcpServerOptions {
  readonly host?: string
  readonly port?: number
  readonly storage: LocalServerStorage
  readonly localStorageId: string
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverPrivateKey: KeyObject
  readonly maxConnections?: number
  readonly maxConnectionsPerIp?: number
  readonly handshakeTimeoutMs?: number
  readonly sessionSetupTimeoutMs?: number
  readonly admissionTimeoutMs?: number
  readonly idleTimeoutMs?: number
  readonly maxPendingWriteBytes?: number
  readonly onMemberConnected?: (connection: ServerTcpPeerConnection) => void
  readonly onConnectionClosed?: (connection: ServerTcpPeerConnection) => void
}

export interface TcpServerHandle {
  readonly host: string
  readonly port: number
  readonly close: () => Promise<void>
  readonly getActiveConnectionCount: () => number
  readonly getIpConnectionCount: (ip: string) => number
}

export interface ServerTcpPeerConnectionOptions {
  socket: Socket | MasqueradaTransportStream
  storage: LocalServerStorage
  localStorageId: string
  serverId: string
  serverPublicKey: Buffer
  serverPrivateKey: KeyObject
  handshakeTimeoutMs?: number
  sessionSetupTimeoutMs?: number
  admissionTimeoutMs?: number
  idleTimeoutMs?: number
  maxPendingWriteBytes?: number
  onClose?: (conn: ServerTcpPeerConnection) => void
  onMemberConnected?: (conn: ServerTcpPeerConnection) => void
}

const AUTHORIZED_CHANNEL_TOKEN = Symbol('AuthorizedPeerChannel')
const authorizedPeerChannels = new WeakSet<object>()

export type AuthorizedPeerMessageHandler = (plaintext: Buffer) => void | Promise<void>

/** Runtime capability for post-authorization SecureSession application messages. */
export class AuthorizedPeerChannel {
  private messageHandler?: AuthorizedPeerMessageHandler
  private readonly typedMessageHandlers = new Map<number, AuthorizedPeerMessageHandler>()
  private readonly closeHandlers = new Set<() => void>()
  private closed = false

  constructor(
    token: symbol,
    private readonly sendPlaintext: (plaintext: Buffer) => Promise<void>,
    private readonly binding: {
      readonly serverId?: string
      readonly peerDeviceFingerprint?: string
    } = {}
  ) {
    if (token !== AUTHORIZED_CHANNEL_TOKEN) throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    authorizedPeerChannels.add(this)
  }

  async send(plaintext: Buffer): Promise<void> {
    if (!authorizedPeerChannels.has(this) || this.closed || !Buffer.isBuffer(plaintext)) {
      throw new TcpTransportError('TCP_CONNECTION_CLOSED')
    }
    await this.sendPlaintext(Buffer.from(plaintext))
  }

  setMessageHandler(handler: AuthorizedPeerMessageHandler): void {
    if (this.closed || this.messageHandler || this.typedMessageHandlers.size > 0 || typeof handler !== 'function') {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
    this.messageHandler = handler
  }

  registerMessageHandler(
    messageTypes: readonly number[],
    handler: AuthorizedPeerMessageHandler
  ): () => void {
    if (
      this.closed || this.messageHandler || typeof handler !== 'function' || messageTypes.length === 0 ||
      messageTypes.some((type) => !Number.isInteger(type) || type < 0 || type > 255 || this.typedMessageHandlers.has(type))
    ) throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    for (const type of messageTypes) this.typedMessageHandlers.set(type, handler)
    let removed = false
    return () => {
      if (removed) return
      removed = true
      for (const type of messageTypes) {
        if (this.typedMessageHandlers.get(type) === handler) this.typedMessageHandlers.delete(type)
      }
    }
  }

  onClose(handler: () => void): () => void {
    if (this.closed) {
      handler()
      return () => {}
    }
    this.closeHandlers.add(handler)
    return () => this.closeHandlers.delete(handler)
  }

  async dispatch(token: symbol, plaintext: Buffer): Promise<void> {
    if (token !== AUTHORIZED_CHANNEL_TOKEN || this.closed) {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
    const handler = this.messageHandler ?? (plaintext.length >= 2
      ? this.typedMessageHandlers.get(plaintext.readUInt8(1))
      : undefined)
    if (!handler) throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    await handler(Buffer.from(plaintext))
  }

  close(token: symbol): void {
    if (token !== AUTHORIZED_CHANNEL_TOKEN || this.closed) return
    this.closed = true
    this.messageHandler = undefined
    this.typedMessageHandlers.clear()
    for (const handler of this.closeHandlers) handler()
    this.closeHandlers.clear()
  }

  isClosed(): boolean {
    return this.closed
  }

  /** Immutable facts derived from the authenticated outer connection. */
  getAuthorizationBinding(): Readonly<{
    serverId?: string
    peerDeviceFingerprint?: string
  }> {
    return Object.freeze({ ...this.binding })
  }
}

export function isAuthorizedPeerChannel(value: unknown): value is AuthorizedPeerChannel {
  return typeof value === 'object' && value !== null && authorizedPeerChannels.has(value)
}

export class ServerTcpPeerConnection {
  private state: ServerConnectionState = 'CONNECTED'
  private readonly socket: Socket | MasqueradaTransportStream
  private readonly decoder = new ProtocolFrameDecoder()
  private currentTimer: NodeJS.Timeout | null = null
  private session: SecureSession | null = null
  private isDestroyed = false
  private authorizedChannel: AuthorizedPeerChannel | null = null

  private readonly storage: LocalServerStorage
  private readonly localStorageId: string
  private readonly serverId: string
  private readonly serverPublicKey: Buffer
  private readonly serverPrivateKey: KeyObject

  private readonly handshakeTimeoutMs: number
  private readonly sessionSetupTimeoutMs: number
  private readonly admissionTimeoutMs: number
  private readonly idleTimeoutMs: number
  private readonly maxPendingWriteBytes: number

  private serverHandshake: ServerHandshake | null = null
  private serverSessionSetup: ServerSessionSetup | null = null
  private serverAuthorizationRouter: ServerAuthorizationRouter | null = null
  private establishedContext: EstablishedServerHandshakeContext | null = null

  private readonly onCloseCallback?: (conn: ServerTcpPeerConnection) => void
  private readonly onMemberConnectedCallback?: (conn: ServerTcpPeerConnection) => void

  constructor(options: ServerTcpPeerConnectionOptions) {
    this.socket = options.socket
    this.storage = options.storage
    this.localStorageId = options.localStorageId
    this.serverId = options.serverId
    this.serverPublicKey = options.serverPublicKey
    this.serverPrivateKey = options.serverPrivateKey
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS
    this.sessionSetupTimeoutMs = options.sessionSetupTimeoutMs ?? SESSION_SETUP_TIMEOUT_MS
    this.admissionTimeoutMs = options.admissionTimeoutMs ?? ADMISSION_TIMEOUT_MS
    this.idleTimeoutMs = options.idleTimeoutMs ?? IDLE_TIMEOUT_MS
    this.maxPendingWriteBytes = options.maxPendingWriteBytes ?? MAX_PENDING_WRITE_BYTES
    this.onCloseCallback = options.onClose
    this.onMemberConnectedCallback = options.onMemberConnected

    if (!isMasqueradaTransportStream(this.socket)) {
      this.socket.setNoDelay(true)
      this.socket.setKeepAlive(true, 10000)
    }

    this.setupSocketEvents()
    this.startHandshakeState()
  }

  private setupSocketEvents(): void {
    this.socket.on('data', (chunk: Buffer) => {
      this.handleData(chunk)
    })

    this.socket.on('end', () => {
      try {
        this.decoder.finish()
      } catch {
        // Frame truncado
      }
      this.destroy()
    })

    this.socket.on('error', () => {
      this.destroy()
    })

    this.socket.on('close', () => {
      this.destroy()
    })
  }

  private setTimer(ms: number, onTimeout: () => void): void {
    this.clearTimer()
    this.currentTimer = setTimeout(() => {
      onTimeout()
    }, ms)
  }

  private clearTimer(): void {
    if (this.currentTimer !== null) {
      clearTimeout(this.currentTimer)
      this.currentTimer = null
    }
  }

  private startHandshakeState(): void {
    this.state = 'HANDSHAKE'
    this.serverHandshake = new ServerHandshake({
      serverId: this.serverId,
      serverPublicKey: this.serverPublicKey,
      serverPrivateKey: this.serverPrivateKey
    })

    this.setTimer(this.handshakeTimeoutMs, () => {
      this.destroy()
    })
  }

  private readonly frameQueue: ProtocolFrame[] = []
  private isProcessingFrames = false

  private handleData(chunk: Buffer): void {
    if (this.isDestroyed) return

    let frames: ProtocolFrame[]
    try {
      frames = this.decoder.push(chunk)
    } catch {
      this.destroy()
      return
    }

    for (const frame of frames) {
      this.frameQueue.push(frame)
    }

    void this.drainFrameQueue()
  }

  private async drainFrameQueue(): Promise<void> {
    if (this.isProcessingFrames || this.isDestroyed) return
    this.isProcessingFrames = true

    try {
      while (this.frameQueue.length > 0 && !this.isDestroyed) {
        const frame = this.frameQueue.shift()!
        await this.processFrame(frame)
      }
    } finally {
      this.isProcessingFrames = false
    }
  }

  private async processFrame(frame: ProtocolFrame): Promise<void> {
    try {
      switch (this.state) {
        case 'HANDSHAKE':
          await this.handleHandshakeFrame(frame)
          break
        case 'SESSION_SETUP':
          await this.handleSessionSetupFrame(frame)
          break
        case 'SECURE_UNADMITTED':
        case 'ADMISSION':
          await this.handleAdmissionFrame(frame)
          break
        case 'MEMBER_CONNECTED':
          await this.handleAuthorizedFrame(frame)
          break
        default:
          this.destroy()
          break
      }
    } catch {
      this.destroy()
    }
  }

  private async handleHandshakeFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.HANDSHAKE || !this.serverHandshake) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }

    const handshakeState = this.serverHandshake.getState()
    if (handshakeState === 'INITIAL') {
      const serverProof = this.serverHandshake.processClientHello(frame.payload)
      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.HANDSHAKE,
          payload: serverProof
        })
      )
    } else if (handshakeState === 'WAITING_CLIENT_PROOF') {
      const { finishMessage } = this.serverHandshake.processClientProof(frame.payload)
      this.establishedContext = this.serverHandshake.getEstablishedContext()

      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.HANDSHAKE,
          payload: finishMessage
        })
      )

      // Transição para SESSION_SETUP
      this.state = 'SESSION_SETUP'
      this.serverSessionSetup = new ServerSessionSetup(this.establishedContext)
      this.setTimer(this.sessionSetupTimeoutMs, () => {
        this.destroy()
      })
    } else {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
  }

  private async handleSessionSetupFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.KEY_EXCHANGE || !this.serverSessionSetup) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }

    const setupState = this.serverSessionSetup.getState()
    if (setupState === 'INITIAL') {
      const serverShare = this.serverSessionSetup.processClientKeyShare(frame.payload)
      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.KEY_EXCHANGE,
          payload: serverShare
        })
      )
    } else if (setupState === 'WAITING_CLIENT_KEY_CONFIRM') {
      const { serverKeyConfirm, session } =
        this.serverSessionSetup.processClientKeyConfirm(frame.payload)
      this.session = session

      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.KEY_EXCHANGE,
          payload: serverKeyConfirm
        })
      )

      // Transição para SECURE_UNADMITTED / ADMISSION
      this.state = 'SECURE_UNADMITTED'
      if (!this.establishedContext) {
        throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
      }

      this.serverAuthorizationRouter = new ServerAuthorizationRouter({
        storage: this.storage,
        localStorageId: this.localStorageId,
        serverContext: this.establishedContext,
        session: this.session
      })

      this.setTimer(this.admissionTimeoutMs, () => {
        this.destroy()
      })
    } else {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
  }

  private async handleAdmissionFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.SESSION || !this.serverAuthorizationRouter) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }

    this.state = 'ADMISSION'
    const fullFrameBuffer = encodeSessionFrame(frame.payload)
    const result = await this.serverAuthorizationRouter.processEncryptedAuthorizationRequest(
      fullFrameBuffer
    )

    await this.writeRawBuffer(result.responseFrame)

    if (result.status === 'admitted' || result.status === 'already_member' || result.status === 'authorized') {
      this.clearTimer()
      this.state = 'MEMBER_CONNECTED'
      this.authorizedChannel = new AuthorizedPeerChannel(
        AUTHORIZED_CHANNEL_TOKEN,
        async (plaintext) => this.writeAuthorizedPlaintext(plaintext),
        {
          serverId: this.serverId,
          peerDeviceFingerprint: this.establishedContext!.candidate.fingerprint
        }
      )
      this.setTimer(this.idleTimeoutMs, () => {
        // Idle timeout após autorização sem tráfego adicional
        this.destroy()
      })
      this.onMemberConnectedCallback?.(this)
    } else {
      // Rejeitado: encerra a conexão após envio da resposta
      this.socket.end(() => {
        this.destroy()
      })
    }
  }

  private async handleAuthorizedFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.SESSION || !this.session || !this.authorizedChannel) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }
    const plaintext = this.session.decrypt(frame.payload)
    await this.authorizedChannel.dispatch(AUTHORIZED_CHANNEL_TOKEN, plaintext)
  }

  private async writeAuthorizedPlaintext(plaintext: Buffer): Promise<void> {
    if (this.state !== 'MEMBER_CONNECTED' || !this.session || !this.authorizedChannel) {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
    await this.writeRawBuffer(encodeSessionFrame(this.session.encrypt(plaintext)))
  }

  async writeFrame(frame: Buffer): Promise<void> {
    await this.writeRawBuffer(frame)
  }

  private async writeRawBuffer(buffer: Buffer): Promise<void> {
    if (this.isDestroyed) {
      throw new TcpTransportError('TCP_CONNECTION_CLOSED')
    }

    if (this.socket.writableLength + buffer.length > this.maxPendingWriteBytes) {
      this.destroy()
      throw new TcpTransportError('TCP_BACKPRESSURE_OVERFLOW')
    }

    const canWriteMore = this.socket.write(buffer)
    if (!canWriteMore) {
      await new Promise<void>((resolve, reject) => {
        const onDrain = (): void => {
          cleanup()
          resolve()
        }
        const onCloseOrError = (): void => {
          cleanup()
          reject(new TcpTransportError('TCP_CONNECTION_CLOSED'))
        }
        const cleanup = (): void => {
          this.socket.off('drain', onDrain)
          this.socket.off('close', onCloseOrError)
          this.socket.off('error', onCloseOrError)
          this.socket.off('end', onCloseOrError)
        }
        this.socket.on('drain', onDrain)
        this.socket.once('close', onCloseOrError)
        this.socket.once('error', onCloseOrError)
        this.socket.once('end', onCloseOrError)
      })
    }
  }

  getState(): ServerConnectionState {
    return this.state
  }

  getSession(): SecureSession | null {
    return this.session
  }

  getEstablishedContext(): EstablishedServerHandshakeContext | null {
    return this.establishedContext
  }

  getAuthorizedChannel(): AuthorizedPeerChannel | null {
    return this.authorizedChannel
  }

  destroy(): void {
    if (this.isDestroyed) return
    this.isDestroyed = true
    this.state = 'CLOSED'
    this.clearTimer()
    this.frameQueue.length = 0
    this.authorizedChannel?.close(AUTHORIZED_CHANNEL_TOKEN)
    this.authorizedChannel = null

    if (this.session && !this.session.isDestroyed()) {
      this.session.destroy()
    }
    this.session = null

    try {
      this.socket.destroy()
    } catch {
      // Ignora erro ao destruir socket
    }

    this.onCloseCallback?.(this)
  }
}

export async function startTcpServer(
  options: StartTcpServerOptions
): Promise<TcpServerHandle> {
  const host = options.host ?? DEFAULT_LOOPBACK_HOST
  assertValidHost(host)

  const port = options.port ?? 0
  assertValidPort(port, true)

  const maxConnections = options.maxConnections ?? MAX_INBOUND_CONNECTIONS
  const maxConnectionsPerIp = options.maxConnectionsPerIp ?? MAX_CONNECTIONS_PER_IP

  const connections = new Set<ServerTcpPeerConnection>()
  const ipCounts = new Map<string, number>()

  const server: Server = createServer({ allowHalfOpen: false })

  server.on('connection', (socket: Socket) => {
    const remoteIp = socket.remoteAddress ?? 'unknown'

    if (connections.size >= maxConnections) {
      socket.destroy()
      return
    }

    const currentIpCount = ipCounts.get(remoteIp) ?? 0
    if (currentIpCount >= maxConnectionsPerIp) {
      socket.destroy()
      return
    }

    ipCounts.set(remoteIp, currentIpCount + 1)

    const connection = new ServerTcpPeerConnection({
      socket,
      storage: options.storage,
      localStorageId: options.localStorageId,
      serverId: options.serverId,
      serverPublicKey: options.serverPublicKey,
      serverPrivateKey: options.serverPrivateKey,
      handshakeTimeoutMs: options.handshakeTimeoutMs,
      sessionSetupTimeoutMs: options.sessionSetupTimeoutMs,
      admissionTimeoutMs: options.admissionTimeoutMs,
      idleTimeoutMs: options.idleTimeoutMs,
      maxPendingWriteBytes: options.maxPendingWriteBytes,
      onMemberConnected: (conn) => {
        options.onMemberConnected?.(conn)
      },
      onClose: (conn) => {
        connections.delete(conn)
        const count = ipCounts.get(remoteIp) ?? 1
        if (count <= 1) {
          ipCounts.delete(remoteIp)
        } else {
          ipCounts.set(remoteIp, count - 1)
        }
        options.onConnectionClosed?.(conn)
      }
    })

    connections.add(connection)
  })

  server.on('error', () => {
    // Tratamento de erro do server listener
  })

  await new Promise<void>((resolve, reject) => {
    server.listen(port, host, () => {
      resolve()
    })
    server.once('error', (err) => {
      reject(err)
    })
  })

  const address = server.address()
  const actualPort = typeof address === 'object' && address !== null ? address.port : port

  return {
    host,
    port: actualPort,
    getActiveConnectionCount: () => connections.size,
    getIpConnectionCount: (ip: string) => ipCounts.get(ip) ?? 0,
    close: async () => {
      for (const conn of Array.from(connections)) {
        conn.destroy()
      }
      connections.clear()
      ipCounts.clear()

      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      })
    }
  }
}

export interface ConnectAndAdmitPeerOptions {
  readonly host?: string
  readonly port?: number
  readonly socket?: Socket | MasqueradaTransportStream
  readonly expectedServerId: string
  readonly expectedServerPublicKey?: Buffer
  readonly deviceFingerprint: string
  readonly devicePublicKey: Buffer
  readonly devicePrivateKey: KeyObject
  readonly invite?: string
  readonly authorizationMode?: 'admission' | 'reconnect'
  readonly handshakeTimeoutMs?: number
  readonly sessionSetupTimeoutMs?: number
  readonly admissionTimeoutMs?: number
  readonly idleTimeoutMs?: number
  readonly maxPendingWriteBytes?: number
  readonly onMemberConnected?: (conn: ClientTcpPeerConnection) => void
  readonly onClose?: (client: ClientTcpPeerConnection) => void
  readonly deferAuthorization?: boolean
  readonly signal?: AbortSignal
}

const SECURE_PRE_AUTH_TOKEN = Symbol('ClientSecurePreAuthorizationConnection')
const securePreAuthorizationConnections = new WeakSet<object>()
const authorizationStartedConnections = new WeakSet<object>()

/** Runtime capability proving that Server Identity and key confirmation completed. */
export class ClientSecurePreAuthorizationConnection {
  readonly expectedServerId: string

  constructor(
    token: symbol,
    private readonly client: ClientTcpPeerConnection,
    expectedServerId: string
  ) {
    if (token !== SECURE_PRE_AUTH_TOKEN) {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
    this.expectedServerId = expectedServerId
    securePreAuthorizationConnections.add(this)
    Object.freeze(this)
  }

  async authorizeWithInvite(invite: string): Promise<{
    readonly connection: ClientTcpPeerConnection
    readonly status: 'admitted' | 'already_member'
  }> {
    if (authorizationStartedConnections.has(this)) throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    authorizationStartedConnections.add(this)
    const result = await this.client.beginAuthorization('admission', invite)
    if (result.status === 'authorized') throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    return { connection: this.client, status: result.status }
  }

  async authorizeExistingMember(): Promise<{
    readonly connection: ClientTcpPeerConnection
    readonly status: 'authorized'
  }> {
    if (authorizationStartedConnections.has(this)) throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    authorizationStartedConnections.add(this)
    const result = await this.client.beginAuthorization('reconnect')
    if (result.status !== 'authorized') throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    return { connection: this.client, status: result.status }
  }

  destroy(): void {
    this.client.destroy()
  }

  isDestroyed(): boolean {
    return this.client.isConnectionDestroyed()
  }
}

export function isClientSecurePreAuthorizationConnection(
  value: unknown
): value is ClientSecurePreAuthorizationConnection {
  return typeof value === 'object' && value !== null && securePreAuthorizationConnections.has(value)
}

/** Deliberately isolated seam for deterministic state-machine tests. */
export const tcpTransportTestOnly = Object.freeze({
  createSecurePreAuthorizationConnection(options: {
    readonly expectedServerId: string
    readonly onAuthorize?: (mode: 'admission' | 'reconnect', invite?: string) =>
      Promise<{ status: 'admitted' | 'already_member' | 'authorized' }>
    readonly onDestroy?: () => void
  }): ClientSecurePreAuthorizationConnection {
    let destroyed = false
    const client = {
      beginAuthorization: options.onAuthorize ?? (async (mode: 'admission' | 'reconnect') => ({
        status: mode === 'reconnect' ? 'authorized' as const : 'admitted' as const
      })),
      destroy: () => {
        destroyed = true
        options.onDestroy?.()
      },
      isConnectionDestroyed: () => destroyed
    } as unknown as ClientTcpPeerConnection
    return new ClientSecurePreAuthorizationConnection(
      SECURE_PRE_AUTH_TOKEN,
      client,
      options.expectedServerId
    )
  },
  createAuthorizedPeerChannel(options: {
    readonly onSend: (plaintext: Buffer) => void | Promise<void>
    readonly serverId?: string
    readonly peerDeviceFingerprint?: string
  }): {
    readonly channel: AuthorizedPeerChannel
    readonly deliver: (plaintext: Buffer) => Promise<void>
    readonly close: () => void
  } {
    const channel = new AuthorizedPeerChannel(
      AUTHORIZED_CHANNEL_TOKEN,
      async (plaintext) => options.onSend(Buffer.from(plaintext)),
      {
        serverId: options.serverId,
        peerDeviceFingerprint: options.peerDeviceFingerprint
      }
    )
    return Object.freeze({
      channel,
      deliver: async (plaintext: Buffer) => channel.dispatch(AUTHORIZED_CHANNEL_TOKEN, plaintext),
      close: () => channel.close(AUTHORIZED_CHANNEL_TOKEN)
    })
  }
})

export class ClientTcpPeerConnection {
  private state: ClientConnectionState = 'CONNECTING'
  private readonly socket: Socket | MasqueradaTransportStream
  private readonly decoder = new ProtocolFrameDecoder()
  private currentTimer: NodeJS.Timeout | null = null
  private session: SecureSession | null = null
  private isDestroyed = false
  private authorizedChannel: AuthorizedPeerChannel | null = null

  private readonly expectedServerId: string
  private readonly expectedServerPublicKey?: Buffer
  private readonly deviceFingerprint: string
  private readonly devicePublicKey: Buffer
  private readonly devicePrivateKey: KeyObject
  private readonly invite?: string
  private readonly authorizationMode: 'admission' | 'reconnect'
  private activeAuthorizationMode: 'admission' | 'reconnect'
  private readonly deferAuthorization: boolean
  private authorizationStarted = false

  private readonly handshakeTimeoutMs: number
  private readonly sessionSetupTimeoutMs: number
  private readonly admissionTimeoutMs: number
  private readonly idleTimeoutMs: number
  private readonly maxPendingWriteBytes: number

  private clientHandshake: ClientHandshake | null = null
  private clientSessionSetup: ClientSessionSetup | null = null
  private clientAdmissionFlow: ClientAdmissionFlow | null = null
  private clientReconnectFlow: ClientMemberReconnectFlow | null = null
  private establishedContext: EstablishedClientHandshakeContext | null = null

  private readonly completionPromise: Promise<{ status: 'admitted' | 'already_member' | 'authorized' }>
  private resolveCompletion!: (value: { status: 'admitted' | 'already_member' | 'authorized' }) => void
  private rejectCompletion!: (reason: unknown) => void
  private readonly securePromise: Promise<ClientSecurePreAuthorizationConnection>
  private resolveSecure!: (value: ClientSecurePreAuthorizationConnection) => void
  private rejectSecure!: (reason: unknown) => void
  private readonly callerSignal?: AbortSignal
  private readonly onCallerAbort: () => void

  constructor(options: ConnectAndAdmitPeerOptions) {
    this.expectedServerId = options.expectedServerId
    this.expectedServerPublicKey = options.expectedServerPublicKey
    this.deviceFingerprint = options.deviceFingerprint
    this.devicePublicKey = options.devicePublicKey
    this.devicePrivateKey = options.devicePrivateKey
    this.invite = options.invite
    this.deferAuthorization = options.deferAuthorization ?? false
    this.callerSignal = options.signal
    this.onCallerAbort = () => this.destroy()

    if (options.authorizationMode === 'reconnect' || (options.invite === undefined && options.authorizationMode !== 'admission')) {
      this.authorizationMode = 'reconnect'
    } else {
      this.authorizationMode = 'admission'
    }
    this.activeAuthorizationMode = this.authorizationMode

    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS
    this.sessionSetupTimeoutMs = options.sessionSetupTimeoutMs ?? SESSION_SETUP_TIMEOUT_MS
    this.admissionTimeoutMs = options.admissionTimeoutMs ?? ADMISSION_TIMEOUT_MS
    this.idleTimeoutMs = options.idleTimeoutMs ?? IDLE_TIMEOUT_MS
    this.maxPendingWriteBytes = options.maxPendingWriteBytes ?? MAX_PENDING_WRITE_BYTES

    this.completionPromise = new Promise((resolve, reject) => {
      this.resolveCompletion = resolve
      this.rejectCompletion = reject
    })
    this.completionPromise.catch(() => {})
    this.securePromise = new Promise((resolve, reject) => {
      this.resolveSecure = resolve
      this.rejectSecure = reject
    })
    this.securePromise.catch(() => {})

    if (options.socket) {
      this.socket = options.socket
    } else {
      if (!options.host) {
        throw new TcpTransportError('TCP_INVALID_HOST')
      }
      assertValidHost(options.host)
      if (options.port === undefined) {
        throw new TcpTransportError('TCP_INVALID_PORT')
      }
      assertValidPort(options.port, false)

      this.socket = createConnection({
        host: options.host,
        port: options.port,
        allowHalfOpen: false
      })
    }

    if (!isMasqueradaTransportStream(this.socket)) {
      this.socket.setNoDelay(true)
      this.socket.setKeepAlive(true, 10000)
    }

    this.setupSocketEvents()
    if (isMasqueradaTransportStream(this.socket)) {
      queueMicrotask(() => {
        void this.startHandshake().catch((err) => this.failAndDestroy(err))
      })
    }
    if (this.callerSignal?.aborted) {
      this.destroy()
    } else {
      this.callerSignal?.addEventListener('abort', this.onCallerAbort, { once: true })
    }
  }

  private setupSocketEvents(): void {
    this.setTimer(this.handshakeTimeoutMs, () => {
      this.failAndDestroy(new TcpTransportError('TCP_TIMEOUT'))
    })

    if (!isMasqueradaTransportStream(this.socket)) {
      this.socket.on('connect', async () => {
        try {
          await this.startHandshake()
        } catch (err) {
          this.failAndDestroy(err)
        }
      })
    }

    this.socket.on('data', (chunk: Buffer) => {
      this.handleData(chunk)
    })

    this.socket.on('end', () => {
      try {
        this.decoder.finish()
      } catch {
        // Frame truncado
      }
      this.failAndDestroy(new TcpTransportError('TCP_CONNECTION_CLOSED'))
    })

    this.socket.on('error', (err) => {
      this.failAndDestroy(err)
    })

    this.socket.on('close', () => {
      this.failAndDestroy(new TcpTransportError('TCP_CONNECTION_CLOSED'))
    })
  }

  private setTimer(ms: number, onTimeout: () => void): void {
    this.clearTimer()
    this.currentTimer = setTimeout(() => {
      onTimeout()
    }, ms)
  }

  private clearTimer(): void {
    if (this.currentTimer !== null) {
      clearTimeout(this.currentTimer)
      this.currentTimer = null
    }
  }

  private async startHandshake(): Promise<void> {
    this.state = 'HANDSHAKE'
    this.clientHandshake = new ClientHandshake({
      expectedServerId: this.expectedServerId,
      expectedServerPublicKey: this.expectedServerPublicKey,
      deviceFingerprint: this.deviceFingerprint,
      devicePublicKey: this.devicePublicKey,
      devicePrivateKey: this.devicePrivateKey
    })

    const clientHello = this.clientHandshake.createClientHello()
    await this.writeFrame(
      encodeProtocolFrame({
        type: ProtocolFrameType.HANDSHAKE,
        payload: clientHello
      })
    )
  }

  private readonly frameQueue: ProtocolFrame[] = []
  private isProcessingFrames = false

  private handleData(chunk: Buffer): void {
    if (this.isDestroyed) return

    let frames: ProtocolFrame[]
    try {
      frames = this.decoder.push(chunk)
    } catch (err) {
      this.failAndDestroy(err)
      return
    }

    for (const frame of frames) {
      this.frameQueue.push(frame)
    }

    void this.drainFrameQueue()
  }

  private async drainFrameQueue(): Promise<void> {
    if (this.isProcessingFrames || this.isDestroyed) return
    this.isProcessingFrames = true

    try {
      while (this.frameQueue.length > 0 && !this.isDestroyed) {
        const frame = this.frameQueue.shift()!
        await this.processFrame(frame)
      }
    } finally {
      this.isProcessingFrames = false
    }
  }

  private async processFrame(frame: ProtocolFrame): Promise<void> {
    try {
      switch (this.state) {
        case 'HANDSHAKE':
          await this.handleHandshakeFrame(frame)
          break
        case 'SESSION_SETUP':
          await this.handleSessionSetupFrame(frame)
          break
        case 'ADMISSION':
          await this.handleAdmissionFrame(frame)
          break
        case 'MEMBER_CONNECTED':
          await this.handleAuthorizedFrame(frame)
          break
        default:
          this.failAndDestroy(new TcpTransportError('TCP_PROTOCOL_VIOLATION'))
          break
      }
    } catch (err) {
      this.failAndDestroy(err)
    }
  }

  private async handleHandshakeFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.HANDSHAKE || !this.clientHandshake) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }

    const handshakeState = this.clientHandshake.getState()
    if (handshakeState === 'WAITING_SERVER_PROOF') {
      const clientProof = this.clientHandshake.processServerProof(frame.payload)
      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.HANDSHAKE,
          payload: clientProof
        })
      )
    } else if (handshakeState === 'WAITING_SERVER_FINISH') {
      this.clientHandshake.processServerFinish(frame.payload)
      this.establishedContext = this.clientHandshake.getEstablishedContext()

      // Transição para SESSION_SETUP
      this.state = 'SESSION_SETUP'
      this.clientSessionSetup = new ClientSessionSetup(this.establishedContext)
      this.setTimer(this.sessionSetupTimeoutMs, () => {
        this.failAndDestroy(new TcpTransportError('TCP_TIMEOUT'))
      })

      const clientKeyShare = this.clientSessionSetup.createClientKeyShare()
      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.KEY_EXCHANGE,
          payload: clientKeyShare
        })
      )
    } else {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
  }

  private async handleSessionSetupFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.KEY_EXCHANGE || !this.clientSessionSetup) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }

    const setupState = this.clientSessionSetup.getState()
    if (setupState === 'WAITING_SERVER_KEY_SHARE') {
      const clientKeyConfirm = this.clientSessionSetup.processServerKeyShare(frame.payload)
      await this.writeFrame(
        encodeProtocolFrame({
          type: ProtocolFrameType.KEY_EXCHANGE,
          payload: clientKeyConfirm
        })
      )
    } else if (setupState === 'WAITING_SERVER_KEY_CONFIRM') {
      this.session = this.clientSessionSetup.processServerKeyConfirm(frame.payload)

      // Transição para ADMISSION
      this.state = 'SECURE_UNAUTHORIZED'
      if (!this.establishedContext) {
        throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
      }

      this.clearTimer()
      this.resolveSecure(new ClientSecurePreAuthorizationConnection(
        SECURE_PRE_AUTH_TOKEN,
        this,
        this.expectedServerId
      ))
      if (!this.deferAuthorization) await this.startAuthorization(this.authorizationMode, this.invite)
    } else {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
  }

  private async handleAdmissionFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.SESSION) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }

    const fullFrameBuffer = encodeSessionFrame(frame.payload)

    if (this.activeAuthorizationMode === 'reconnect') {
      if (!this.clientReconnectFlow) {
        throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
      }

      const result = this.clientReconnectFlow.processEncryptedReconnectResponse(fullFrameBuffer)
      if (result.status === 'authorized') {
        this.clearTimer()
        this.state = 'MEMBER_CONNECTED'
        this.authorizedChannel = new AuthorizedPeerChannel(
          AUTHORIZED_CHANNEL_TOKEN,
          async (plaintext) => this.writeAuthorizedPlaintext(plaintext),
          { serverId: this.expectedServerId }
        )
        this.setTimer(this.idleTimeoutMs, () => {
          this.destroy()
        })
        this.resolveCompletion({ status: 'authorized' })
      } else {
        this.failAndDestroy(new TcpTransportError('TCP_ADMISSION_REJECTED'))
      }
    } else {
      if (!this.clientAdmissionFlow) {
        throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
      }

      const result = this.clientAdmissionFlow.processEncryptedAdmissionResponse(fullFrameBuffer)

      if (result.status === 'admitted' || result.status === 'already_member') {
        this.clearTimer()
        this.state = 'MEMBER_CONNECTED'
        this.authorizedChannel = new AuthorizedPeerChannel(
          AUTHORIZED_CHANNEL_TOKEN,
          async (plaintext) => this.writeAuthorizedPlaintext(plaintext),
          { serverId: this.expectedServerId }
        )
        this.setTimer(this.idleTimeoutMs, () => {
          this.destroy()
        })
        this.resolveCompletion({ status: result.status })
      } else {
        this.failAndDestroy(new TcpTransportError('TCP_ADMISSION_REJECTED'))
      }
    }
  }

  private async handleAuthorizedFrame(frame: ProtocolFrame): Promise<void> {
    if (frame.type !== ProtocolFrameType.SESSION || !this.session || !this.authorizedChannel) {
      throw new TcpTransportError('TCP_WRONG_FRAME_TYPE')
    }
    const plaintext = this.session.decrypt(frame.payload)
    await this.authorizedChannel.dispatch(AUTHORIZED_CHANNEL_TOKEN, plaintext)
  }

  private async writeAuthorizedPlaintext(plaintext: Buffer): Promise<void> {
    if (this.state !== 'MEMBER_CONNECTED' || !this.session || !this.authorizedChannel) {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
    await this.writeRawBuffer(encodeSessionFrame(this.session.encrypt(plaintext)))
  }

  async writeFrame(frame: Buffer): Promise<void> {
    await this.writeRawBuffer(frame)
  }

  private async writeRawBuffer(buffer: Buffer): Promise<void> {
    if (this.isDestroyed) {
      throw new TcpTransportError('TCP_CONNECTION_CLOSED')
    }

    if (this.socket.writableLength + buffer.length > this.maxPendingWriteBytes) {
      this.failAndDestroy(new TcpTransportError('TCP_BACKPRESSURE_OVERFLOW'))
      throw new TcpTransportError('TCP_BACKPRESSURE_OVERFLOW')
    }

    const canWriteMore = this.socket.write(buffer)
    if (!canWriteMore) {
      await new Promise<void>((resolve, reject) => {
        const onDrain = (): void => {
          cleanup()
          resolve()
        }
        const onCloseOrError = (): void => {
          cleanup()
          reject(new TcpTransportError('TCP_CONNECTION_CLOSED'))
        }
        const cleanup = (): void => {
          this.socket.off('drain', onDrain)
          this.socket.off('close', onCloseOrError)
          this.socket.off('error', onCloseOrError)
          this.socket.off('end', onCloseOrError)
        }
        this.socket.on('drain', onDrain)
        this.socket.once('close', onCloseOrError)
        this.socket.once('error', onCloseOrError)
        this.socket.once('end', onCloseOrError)
      })
    }
  }

  waitForAdmission(): Promise<{ status: 'admitted' | 'already_member' | 'authorized' }> {
    return this.completionPromise
  }

  waitForSecureConnection(): Promise<ClientSecurePreAuthorizationConnection> {
    return this.securePromise
  }

  async beginAuthorization(
    mode: 'admission' | 'reconnect',
    invite?: string
  ): Promise<{ status: 'admitted' | 'already_member' | 'authorized' }> {
    await this.startAuthorization(mode, invite)
    return this.completionPromise
  }

  private async startAuthorization(mode: 'admission' | 'reconnect', invite?: string): Promise<void> {
    if (this.state !== 'SECURE_UNAUTHORIZED' || !this.session || !this.establishedContext || this.authorizationStarted) {
      throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    }
    this.authorizationStarted = true
    this.activeAuthorizationMode = mode
    this.state = 'ADMISSION'
    this.setTimer(this.admissionTimeoutMs, () => {
      this.failAndDestroy(new TcpTransportError('TCP_TIMEOUT'))
    })
    if (mode === 'reconnect') {
      this.clientReconnectFlow = new ClientMemberReconnectFlow({
        context: this.establishedContext,
        session: this.session
      })
      await this.writeRawBuffer(this.clientReconnectFlow.createEncryptedReconnectRequest())
      return
    }
    if (!invite) throw new TcpTransportError('TCP_PROTOCOL_VIOLATION')
    this.clientAdmissionFlow = new ClientAdmissionFlow({
      context: this.establishedContext,
      session: this.session,
      invite
    })
    await this.writeRawBuffer(this.clientAdmissionFlow.createEncryptedAdmissionRequest())
  }

  waitForAuthorization(): Promise<{ status: 'admitted' | 'already_member' | 'authorized' }> {
    return this.completionPromise
  }

  getState(): ClientConnectionState {
    return this.state
  }

  getSession(): SecureSession | null {
    return this.session
  }

  getEstablishedContext(): EstablishedClientHandshakeContext | null {
    return this.establishedContext
  }

  getAuthorizedChannel(): AuthorizedPeerChannel | null {
    return this.authorizedChannel
  }

  isConnectionDestroyed(): boolean {
    return this.isDestroyed
  }

  private failAndDestroy(err: unknown): void {
    if (this.isDestroyed) return
    this.isDestroyed = true
    this.state = 'FAILED'
    this.clearTimer()
    this.callerSignal?.removeEventListener('abort', this.onCallerAbort)
    this.frameQueue.length = 0
    this.authorizedChannel?.close(AUTHORIZED_CHANNEL_TOKEN)
    this.authorizedChannel = null

    if (this.session && !this.session.isDestroyed()) {
      this.session.destroy()
    }
    this.session = null

    try {
      this.socket.destroy()
    } catch {
      // Ignora erro ao destruir socket
    }

    this.rejectCompletion(err)
    this.rejectSecure(err)
  }

  destroy(): void {
    if (this.isDestroyed) return
    this.isDestroyed = true
    this.state = 'CLOSED'
    this.clearTimer()
    this.callerSignal?.removeEventListener('abort', this.onCallerAbort)
    this.frameQueue.length = 0
    this.authorizedChannel?.close(AUTHORIZED_CHANNEL_TOKEN)
    this.authorizedChannel = null

    if (this.session && !this.session.isDestroyed()) {
      this.session.destroy()
    }
    this.session = null

    try {
      this.socket.destroy()
    } catch {
      // Ignora erro ao destruir socket
    }

    this.rejectCompletion(new TcpTransportError('TCP_CONNECTION_CLOSED'))
    this.rejectSecure(new TcpTransportError('TCP_CONNECTION_CLOSED'))
  }
}

export function connectAndAdmitTcpPeer(
  options: ConnectAndAdmitPeerOptions
): ClientTcpPeerConnection {
  return new ClientTcpPeerConnection(options)
}

export interface EstablishSecureServerConnectionOptions {
  readonly endpoint: {
    readonly family: 4 | 6
    readonly address: string
    readonly port: number
    readonly scopeId?: number
  }
  readonly expectedServerId: string
  readonly expectedServerPublicKey: Buffer
  readonly deviceFingerprint: string
  readonly devicePublicKey: Buffer
  readonly devicePrivateKey: KeyObject
  readonly handshakeTimeoutMs?: number
  readonly sessionSetupTimeoutMs?: number
  readonly signal?: AbortSignal
}

/** Opens an IP-literal path and stops only after authenticated key confirmation. */
export function establishSecureServerConnection(
  options: EstablishSecureServerConnectionOptions
): Promise<ClientSecurePreAuthorizationConnection> {
  const { endpoint } = options
  const classification = classifyNetworkAddress(endpoint.address, endpoint.scopeId)
  if (
    classification.family !== (endpoint.family === 4 ? 'IPv4' : 'IPv6') ||
    classification.normalizedAddress !== endpoint.address ||
    endpoint.address.includes('%')
  ) {
    return Promise.reject(new TcpTransportError('TCP_ENDPOINT_INVALID'))
  }
  assertValidPort(endpoint.port)
  const host = endpoint.family === 6 && endpoint.scopeId !== undefined
    ? `${endpoint.address}%${endpoint.scopeId}`
    : endpoint.address
  const socket = createConnection({ host, port: endpoint.port, allowHalfOpen: false })
  const client = new ClientTcpPeerConnection({
    socket,
    expectedServerId: options.expectedServerId,
    expectedServerPublicKey: options.expectedServerPublicKey,
    deviceFingerprint: options.deviceFingerprint,
    devicePublicKey: options.devicePublicKey,
    devicePrivateKey: options.devicePrivateKey,
    handshakeTimeoutMs: options.handshakeTimeoutMs,
    sessionSetupTimeoutMs: options.sessionSetupTimeoutMs,
    deferAuthorization: true,
    signal: options.signal
  })
  return client.waitForSecureConnection()
}

export type EstablishSecureServerConnectionOverTransportOptions = Omit<
  EstablishSecureServerConnectionOptions,
  'endpoint'
> & { readonly transport: MasqueradaTransportStream }

/** Runs the unchanged client identity/session pipeline over a branded virtual byte stream. */
export function establishSecureServerConnectionOverTransport(
  options: EstablishSecureServerConnectionOverTransportOptions
): Promise<ClientSecurePreAuthorizationConnection> {
  if (!isMasqueradaTransportStream(options.transport)) {
    return Promise.reject(new TcpTransportError('TCP_ENDPOINT_INVALID'))
  }
  const client = new ClientTcpPeerConnection({
    socket: options.transport,
    expectedServerId: options.expectedServerId,
    expectedServerPublicKey: options.expectedServerPublicKey,
    deviceFingerprint: options.deviceFingerprint,
    devicePublicKey: options.devicePublicKey,
    devicePrivateKey: options.devicePrivateKey,
    handshakeTimeoutMs: options.handshakeTimeoutMs,
    sessionSetupTimeoutMs: options.sessionSetupTimeoutMs,
    deferAuthorization: true,
    signal: options.signal
  })
  return client.waitForSecureConnection()
}

export interface AcceptRelayServerTransportOptions extends Omit<ServerTcpPeerConnectionOptions, 'socket'> {
  readonly transport: MasqueradaTransportStream
}

/** Runs the unchanged server handshake/session/authorization pipeline over a relay stream. */
export function acceptRelayServerTransport(
  options: AcceptRelayServerTransportOptions
): ServerTcpPeerConnection {
  if (!isMasqueradaTransportStream(options.transport)) {
    throw new TcpTransportError('TCP_ENDPOINT_INVALID')
  }
  return new ServerTcpPeerConnection({ ...options, socket: options.transport })
}
