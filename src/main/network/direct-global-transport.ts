import { type KeyObject } from 'node:crypto'
import {
  createServer,
  isIP,
  type AddressInfo,
  type ListenOptions,
  type Server,
  type Socket
} from 'node:net'

import { type LocalServerStorage } from '../servers/local-server-storage'
import { type DirectTcpEndpoint } from './lan-transport'
import {
  classifyNetworkAddress,
  findAssignedGlobalIpv6Address,
  type NetworkInterfaceProvider
} from './network-interfaces'
import {
  assertValidPort,
  MAX_CONNECTIONS_PER_IP,
  MAX_INBOUND_CONNECTIONS,
  ServerTcpPeerConnection
} from './tcp-transport'

const MAX_DIRECT_GLOBAL_ADDRESS_LENGTH = 128
const CONSTRUCTOR_TOKEN = Symbol('ActiveDirectGlobalListener')
const legitimateDirectGlobalListeners = new WeakSet<object>()

export type DirectGlobalTransportErrorCode =
  | 'DIRECT_GLOBAL_ADDRESS_INVALID'
  | 'DIRECT_GLOBAL_ADDRESS_NOT_GLOBAL'
  | 'DIRECT_GLOBAL_ADDRESS_NOT_LOCAL'
  | 'DIRECT_GLOBAL_PORT_INVALID'
  | 'DIRECT_GLOBAL_BIND_FAILED'
  | 'DIRECT_GLOBAL_ADDRESS_LOST'
  | 'DIRECT_GLOBAL_LISTENER_CLOSED'
  | 'DIRECT_GLOBAL_CAPABILITY_INVALID'
  | 'DIRECT_GLOBAL_ABORTED'

const ERROR_MESSAGES: Record<DirectGlobalTransportErrorCode, string> = {
  DIRECT_GLOBAL_ADDRESS_INVALID: 'O endereço Direct Global fornecido é inválido.',
  DIRECT_GLOBAL_ADDRESS_NOT_GLOBAL: 'O endereço selecionado não é um IPv6 global elegível.',
  DIRECT_GLOBAL_ADDRESS_NOT_LOCAL: 'O endereço selecionado não está atribuído de forma elegível ao host.',
  DIRECT_GLOBAL_PORT_INVALID: 'A porta Direct Global solicitada é inválida.',
  DIRECT_GLOBAL_BIND_FAILED: 'Não foi possível iniciar o listener Direct Global solicitado.',
  DIRECT_GLOBAL_ADDRESS_LOST: 'O endereço Direct Global selecionado deixou de estar disponível.',
  DIRECT_GLOBAL_LISTENER_CLOSED: 'O listener Direct Global está encerrado.',
  DIRECT_GLOBAL_CAPABILITY_INVALID: 'A capability Direct Global é inválida.',
  DIRECT_GLOBAL_ABORTED: 'A criação do listener Direct Global foi cancelada.'
}

export class DirectGlobalTransportError extends Error {
  readonly code: DirectGlobalTransportErrorCode

  constructor(code: DirectGlobalTransportErrorCode, options?: ErrorOptions) {
    super(ERROR_MESSAGES[code], options)
    this.name = 'DirectGlobalTransportError'
    this.code = code
  }
}

export interface StartDirectGlobalTcpServerOptions {
  readonly localAddress: string
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
  readonly signal?: AbortSignal
  readonly onMemberConnected?: (connection: ServerTcpPeerConnection) => void
}

interface DirectGlobalTestSeams {
  readonly interfaceProvider?: NetworkInterfaceProvider
  readonly serverFactory?: () => Server
}

type ListenerState = 'ACTIVE' | 'CLOSING' | 'CLOSED' | 'INVALIDATED'

function validateSelectedAddress(rawAddress: unknown): string {
  if (
    typeof rawAddress !== 'string' ||
    rawAddress.length === 0 ||
    rawAddress.length > MAX_DIRECT_GLOBAL_ADDRESS_LENGTH ||
    rawAddress !== rawAddress.trim() ||
    rawAddress.includes('%') ||
    isIP(rawAddress) !== 6
  ) {
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_ADDRESS_INVALID')
  }

  const classification = classifyNetworkAddress(rawAddress)
  if (
    classification.family !== 'IPv6' ||
    classification.scope !== 'GLOBAL' ||
    !classification.isGloballyRoutableWan ||
    classification.normalizedAddress.startsWith('::ffff:')
  ) {
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_ADDRESS_NOT_GLOBAL')
  }

  return classification.normalizedAddress
}

function requireCurrentLocalAssignment(
  address: string,
  provider?: NetworkInterfaceProvider
): void {
  if (!findAssignedGlobalIpv6Address(address, provider)) {
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_ADDRESS_NOT_LOCAL')
  }
}

function normalizeInboundIpv6(rawAddress: string | undefined): string | null {
  if (!rawAddress || rawAddress.includes('%') || isIP(rawAddress) !== 6) return null
  const classification = classifyNetworkAddress(rawAddress)
  if (
    classification.family !== 'IPv6' ||
    classification.normalizedAddress.startsWith('::ffff:')
  ) {
    return null
  }
  return classification.normalizedAddress
}

function readExactBoundEndpoint(server: Server, selectedAddress: string): DirectTcpEndpoint | null {
  const raw = server.address()
  if (!raw || typeof raw === 'string') return null
  const classification = classifyNetworkAddress(raw.address)
  const family = (raw as AddressInfo).family
  if (
    family !== 'IPv6' ||
    classification.family !== 'IPv6' ||
    classification.normalizedAddress !== selectedAddress ||
    classification.normalizedAddress === '::' ||
    !Number.isInteger(raw.port) ||
    raw.port < 1 ||
    raw.port > 65535
  ) {
    return null
  }
  return Object.freeze({ family: 6, address: selectedAddress, port: raw.port })
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => {
    try {
      server.close(() => resolve())
    } catch {
      resolve()
    }
  })
}

export class ActiveDirectGlobalListener {
  private state: ListenerState = 'ACTIVE'
  private cleanupPromise: Promise<void> | null = null

  constructor(
    token: symbol,
    private readonly server: Server,
    private readonly selectedAddress: string,
    private readonly interfaceProvider: NetworkInterfaceProvider | undefined,
    private readonly connections: Set<ServerTcpPeerConnection>,
    private readonly ipCounts: Map<string, number>
  ) {
    if (token !== CONSTRUCTOR_TOKEN) {
      throw new DirectGlobalTransportError('DIRECT_GLOBAL_CAPABILITY_INVALID')
    }
    legitimateDirectGlobalListeners.add(this)
  }

  isActive(): boolean {
    if (!legitimateDirectGlobalListeners.has(this) || this.state !== 'ACTIVE') return false
    if (!this.server.listening || !readExactBoundEndpoint(this.server, this.selectedAddress)) {
      this.invalidate()
      return false
    }
    if (!findAssignedGlobalIpv6Address(this.selectedAddress, this.interfaceProvider)) {
      this.invalidate()
      return false
    }
    return true
  }

  getBoundEndpoint(): DirectTcpEndpoint {
    if (!this.isActive()) {
      throw new DirectGlobalTransportError('DIRECT_GLOBAL_LISTENER_CLOSED')
    }
    const endpoint = readExactBoundEndpoint(this.server, this.selectedAddress)
    if (!endpoint) {
      this.invalidate()
      throw new DirectGlobalTransportError('DIRECT_GLOBAL_ADDRESS_LOST')
    }
    return endpoint
  }

  getActiveConnectionCount(): number {
    return this.state === 'ACTIVE' ? this.connections.size : 0
  }

  getIpConnectionCount(address: string): number {
    if (this.state !== 'ACTIVE') return 0
    const normalized = normalizeInboundIpv6(address)
    return normalized ? (this.ipCounts.get(normalized) ?? 0) : 0
  }

  getState(): ListenerState {
    return this.state
  }

  async close(): Promise<void> {
    if (this.state === 'CLOSED') return
    if (this.state !== 'INVALIDATED') this.state = 'CLOSING'
    await this.startCleanup()
    this.state = 'CLOSED'
    legitimateDirectGlobalListeners.delete(this)
  }

  private invalidate(): void {
    if (this.state !== 'ACTIVE') return
    this.state = 'INVALIDATED'
    void this.startCleanup()
  }

  private startCleanup(): Promise<void> {
    if (this.cleanupPromise) return this.cleanupPromise
    this.cleanupPromise = (async () => {
      for (const connection of Array.from(this.connections)) connection.destroy()
      this.connections.clear()
      this.ipCounts.clear()
      await closeServer(this.server)
    })()
    return this.cleanupPromise
  }
}

export function isLegitimateActiveDirectGlobalListener(
  value: unknown
): value is ActiveDirectGlobalListener {
  return typeof value === 'object' && value !== null && legitimateDirectGlobalListeners.has(value)
}

async function startDirectGlobalTcpServerInternal(
  options: StartDirectGlobalTcpServerOptions,
  testSeams: DirectGlobalTestSeams = {}
): Promise<ActiveDirectGlobalListener> {
  if (options.signal?.aborted) {
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_ABORTED')
  }

  const selectedAddress = validateSelectedAddress(options.localAddress)
  requireCurrentLocalAssignment(selectedAddress, testSeams.interfaceProvider)

  const port = options.port ?? 0
  try {
    assertValidPort(port, true)
  } catch (cause) {
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_PORT_INVALID', { cause })
  }

  const maxConnections = options.maxConnections ?? MAX_INBOUND_CONNECTIONS
  const maxConnectionsPerIp = options.maxConnectionsPerIp ?? MAX_CONNECTIONS_PER_IP
  const connections = new Set<ServerTcpPeerConnection>()
  const ipCounts = new Map<string, number>()
  const server = testSeams.serverFactory?.() ?? createServer({ allowHalfOpen: false })

  server.on('connection', (socket: Socket) => {
    const remoteIp = normalizeInboundIpv6(socket.remoteAddress)
    if (!remoteIp) {
      socket.destroy()
      return
    }
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
      onMemberConnected: (connected) => options.onMemberConnected?.(connected),
      onClose: (closed) => {
        connections.delete(closed)
        const remaining = (ipCounts.get(remoteIp) ?? 1) - 1
        if (remaining <= 0) ipCounts.delete(remoteIp)
        else ipCounts.set(remoteIp, remaining)
      }
    })
    connections.add(connection)
  })

  // Prevents an operational listener error from becoming an uncaught process error.
  server.on('error', () => undefined)

  const listenOptions: ListenOptions = {
    host: selectedAddress,
    port,
    ipv6Only: true
  }

  try {
    await new Promise<void>((resolve, reject) => {
      let settled = false
      const cleanup = (): void => {
        server.off('error', onOpeningError)
        options.signal?.removeEventListener('abort', onAbort)
      }
      const fail = (error: DirectGlobalTransportError): void => {
        if (settled) return
        settled = true
        cleanup()
        reject(error)
      }
      const onOpeningError = (cause: NodeJS.ErrnoException): void => {
        fail(new DirectGlobalTransportError('DIRECT_GLOBAL_BIND_FAILED', { cause }))
      }
      const onAbort = (): void => fail(new DirectGlobalTransportError('DIRECT_GLOBAL_ABORTED'))

      server.once('error', onOpeningError)
      options.signal?.addEventListener('abort', onAbort, { once: true })
      server.listen(listenOptions, () => {
        if (settled) return
        settled = true
        cleanup()
        resolve()
      })
    })
  } catch (error) {
    await closeServer(server)
    throw error
  }

  const boundEndpoint = readExactBoundEndpoint(server, selectedAddress)
  if (!boundEndpoint) {
    await closeServer(server)
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_BIND_FAILED')
  }

  try {
    requireCurrentLocalAssignment(selectedAddress, testSeams.interfaceProvider)
  } catch (cause) {
    await closeServer(server)
    throw new DirectGlobalTransportError('DIRECT_GLOBAL_ADDRESS_LOST', { cause })
  }

  return new ActiveDirectGlobalListener(
    CONSTRUCTOR_TOKEN,
    server,
    selectedAddress,
    testSeams.interfaceProvider,
    connections,
    ipCounts
  )
}

/** Inicia explicitamente um listener Masquerada no IPv6 global selecionado. */
export function startDirectGlobalTcpServer(
  options: StartDirectGlobalTcpServerOptions
): Promise<ActiveDirectGlobalListener> {
  return startDirectGlobalTcpServerInternal(options)
}

/** @internal Seam determinístico; não é ligado a IPC, renderer ou startup. */
export const directGlobalTransportTestOnly = Object.freeze({
  start: startDirectGlobalTcpServerInternal
})
