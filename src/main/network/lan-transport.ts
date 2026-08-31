import { type KeyObject } from 'node:crypto'
import { isIP } from 'node:net'
import { createConnection, createServer, type AddressInfo, type Server, type Socket } from 'node:net'

import { type LocalServerStorage } from '../servers/local-server-storage'
import {
  classifyNetworkAddress,
  listLocalNetworkInterfaces,
  type NetworkInterfaceProvider
} from './network-interfaces'
import {
  assertValidPort,
  ClientTcpPeerConnection,
  MAX_CONNECTIONS_PER_IP,
  MAX_INBOUND_CONNECTIONS,
  ServerTcpPeerConnection,
  TcpTransportError
} from './tcp-transport'

export const CONNECT_TIMEOUT_MS = 5000

export interface DirectTcpEndpoint {
  readonly family: 4 | 6
  readonly address: string
  readonly port: number
  readonly scopeId?: number
}

export interface BoundTcpEndpoint {
  readonly address: string
  readonly port: number
  readonly family: 4 | 6
  readonly interfaceName?: string
  readonly scopeId?: number
}

export interface LanTcpServerHandle {
  readonly endpoint: BoundTcpEndpoint
  readonly host: string
  readonly port: number
  readonly isClosed: () => boolean
  readonly close: () => Promise<void>
  readonly getActiveConnectionCount: () => number
  readonly getIpConnectionCount: (ip: string) => number
}

const activeServerHandles = new WeakSet<object>()
const serverCloseListeners = new WeakMap<object, Set<() => void>>()

export function isLegitimateActiveServerHandle(handle: unknown): handle is LanTcpServerHandle {
  if (!handle || typeof handle !== 'object') return false
  return activeServerHandles.has(handle)
}

/** Registra cleanup local vinculado ao lifecycle de um listener legítimo. */
export function registerLanTcpServerCloseListener(
  handle: LanTcpServerHandle,
  listener: () => void
): () => void {
  if (!isLegitimateActiveServerHandle(handle) || handle.isClosed()) return () => undefined
  let listeners = serverCloseListeners.get(handle)
  if (!listeners) {
    listeners = new Set()
    serverCloseListeners.set(handle, listeners)
  }
  listeners.add(listener)
  return () => listeners?.delete(listener)
}

export interface StartLanTcpServerOptions {
  readonly bindAddress: string
  readonly port?: number
  readonly storage: LocalServerStorage
  readonly localStorageId: string
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverPrivateKey: KeyObject
  readonly maxConnections?: number
  readonly maxConnectionsPerIp?: number
  readonly interfaceProvider?: NetworkInterfaceProvider
  readonly handshakeTimeoutMs?: number
  readonly sessionSetupTimeoutMs?: number
  readonly admissionTimeoutMs?: number
  readonly idleTimeoutMs?: number
  readonly maxPendingWriteBytes?: number
  readonly onMemberConnected?: (conn: ServerTcpPeerConnection) => void
}

export interface ConnectLanTcpPeerOptions {
  readonly endpoint: DirectTcpEndpoint
  readonly expectedServerId: string
  readonly deviceFingerprint: string
  readonly devicePublicKey: Buffer
  readonly devicePrivateKey: KeyObject
  readonly invite?: string
  readonly authorizationMode?: 'admission' | 'reconnect'
  readonly connectTimeoutMs?: number
  readonly handshakeTimeoutMs?: number
  readonly sessionSetupTimeoutMs?: number
  readonly admissionTimeoutMs?: number
  readonly idleTimeoutMs?: number
  readonly maxPendingWriteBytes?: number
  readonly onMemberConnected?: (conn: ClientTcpPeerConnection) => void
}

function normalizeRemoteIp(rawIp: string | undefined): string {
  if (!rawIp) return 'unknown'
  if (rawIp.startsWith('::ffff:')) {
    return rawIp.slice(7)
  }
  return rawIp.toLowerCase()
}

/**
 * Inicia um listener TCP vinculado exclusivamente a um endereço IP de interface local permitida.
 * Rejeita expressamente wildcards (0.0.0.0 e ::) e endereços públicos/globais.
 */
export async function startLanTcpServer(
  options: StartLanTcpServerOptions
): Promise<LanTcpServerHandle> {
  const rawBind = options.bindAddress
  if (typeof rawBind !== 'string' || rawBind.trim().length === 0) {
    throw new TcpTransportError('TCP_BIND_ADDRESS_UNAVAILABLE')
  }

  const bindAddress = rawBind.trim()

  // 1. Rejeição explícita de wildcards
  if (bindAddress === '0.0.0.0' || bindAddress === '::' || bindAddress === '[::]') {
    throw new TcpTransportError('TCP_WILDCARD_PROHIBITED')
  }

  // 2. Classificação do endereço solicitado
  const classification = classifyNetworkAddress(bindAddress)
  if (classification.scope === 'UNSPECIFIED') {
    throw new TcpTransportError('TCP_WILDCARD_PROHIBITED')
  }
  if (
    classification.scope === 'GLOBAL' ||
    classification.scope === 'CGNAT' ||
    classification.scope === 'DOCUMENTATION' ||
    classification.scope === 'BENCHMARK'
  ) {
    throw new TcpTransportError('TCP_GLOBAL_ADDRESS_PROHIBITED')
  }
  if (
    classification.scope === 'MULTICAST' ||
    classification.scope === 'UNSUPPORTED' ||
    classification.scope === 'RESERVED'
  ) {
    throw new TcpTransportError('TCP_BIND_ADDRESS_UNAVAILABLE')
  }

  // 3. Revalidação no momento do bind contra interfaces atualmente atribuídas
  const localInterfaces = listLocalNetworkInterfaces(options.interfaceProvider)
  const matchingInterface = localInterfaces.find(
    (iface) => iface.address.toLowerCase() === classification.normalizedAddress.toLowerCase()
  )

  if (!matchingInterface) {
    throw new TcpTransportError('TCP_BIND_ADDRESS_UNAVAILABLE')
  }

  if (!matchingInterface.isSelectableForLan && matchingInterface.scope !== 'LOOPBACK') {
    throw new TcpTransportError('TCP_BIND_ADDRESS_UNAVAILABLE')
  }

  const port = options.port ?? 0
  assertValidPort(port, true)

  const maxConnections = options.maxConnections ?? MAX_INBOUND_CONNECTIONS
  const maxConnectionsPerIp = options.maxConnectionsPerIp ?? MAX_CONNECTIONS_PER_IP

  const connections = new Set<ServerTcpPeerConnection>()
  const ipCounts = new Map<string, number>()

  const server: Server = createServer({ allowHalfOpen: false })

  server.on('connection', (socket: Socket) => {
    const remoteIp = normalizeRemoteIp(socket.remoteAddress)

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
        const updatedCount = (ipCounts.get(remoteIp) ?? 1) - 1
        if (updatedCount <= 0) {
          ipCounts.delete(remoteIp)
        } else {
          ipCounts.set(remoteIp, updatedCount)
        }
      }
    })

    connections.add(connection)
  })

  const isIpv6 = classification.family === 'IPv6'

  await new Promise<void>((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException) => {
      server.off('error', onError)
      if (err.code === 'EADDRINUSE') {
        reject(new TcpTransportError('TCP_BIND_ADDRESS_IN_USE'))
      } else if (err.code === 'EADDRNOTAVAIL') {
        reject(new TcpTransportError('TCP_BIND_ADDRESS_UNAVAILABLE'))
      } else if (err.code === 'EACCES') {
        reject(new TcpTransportError('TCP_BIND_PERMISSION_DENIED'))
      } else {
        reject(new TcpTransportError('TCP_LISTENER_FAILED'))
      }
    }

    server.once('error', onError)

    server.listen(
      {
        host: classification.normalizedAddress,
        port,
        ipv6Only: isIpv6 ? true : undefined
      },
      () => {
        server.off('error', onError)
        resolve()
      }
    )
  })

  const boundAddressInfo = server.address() as AddressInfo | null
  if (!boundAddressInfo) {
    server.close()
    throw new TcpTransportError('TCP_LISTENER_FAILED')
  }

  // Verificação pós-bind: confirma que o sistema operacional não fez fallback para wildcard
  const actualBoundAddress = boundAddressInfo.address
  if (actualBoundAddress === '0.0.0.0' || actualBoundAddress === '::') {
    server.close()
    throw new TcpTransportError('TCP_WILDCARD_PROHIBITED')
  }

  const endpoint: BoundTcpEndpoint = {
    address: classification.normalizedAddress,
    port: boundAddressInfo.port,
    family: classification.family === 'IPv6' ? 6 : 4,
    interfaceName: matchingInterface.interfaceName,
    scopeId: matchingInterface.scopeId
  }

  let isClosed = false
  const handle: LanTcpServerHandle = {
    endpoint,
    host: endpoint.address,
    port: endpoint.port,
    isClosed: () => isClosed,
    getActiveConnectionCount: () => (isClosed ? 0 : connections.size),
    getIpConnectionCount: (ip: string) => (isClosed ? 0 : ipCounts.get(normalizeRemoteIp(ip)) ?? 0),
    close: async () => {
      if (isClosed) return
      isClosed = true
      const closeListeners = serverCloseListeners.get(handle)
      serverCloseListeners.delete(handle)
      for (const closeListener of closeListeners ?? []) {
        try {
          closeListener()
        } catch {
          // Cleanup observers cannot prevent listener shutdown.
        }
      }
      activeServerHandles.delete(handle)
      for (const conn of Array.from(connections)) {
        conn.destroy()
      }
      connections.clear()
      ipCounts.clear()

      await new Promise<void>((resolve) => {
        server.close(() => resolve())
      })
    }
  }

  activeServerHandles.add(handle)
  return handle
}

/**
 * Conecta diretamente a um DirectTcpEndpoint numérico validado.
 * Rejeita hostnames de DNS, wildcards e destinos públicos nesta etapa.
 */
export function connectLanTcpPeer(
  options: ConnectLanTcpPeerOptions
): ClientTcpPeerConnection {
  const { endpoint } = options
  if (!endpoint || typeof endpoint.address !== 'string' || typeof endpoint.port !== 'number') {
    throw new TcpTransportError('TCP_ENDPOINT_INVALID')
  }

  const trimmedAddress = endpoint.address.trim()

  // Rejeição de DNS / Hostnames (isIP deve retornar 4 ou 6)
  const ipVer = isIP(trimmedAddress)
  if (ipVer !== 4 && ipVer !== 6) {
    throw new TcpTransportError('TCP_ENDPOINT_INVALID')
  }

  if (endpoint.family !== ipVer) {
    throw new TcpTransportError('TCP_ENDPOINT_INVALID')
  }

  // Classificação do destino
  const classification = classifyNetworkAddress(trimmedAddress, endpoint.scopeId)
  if (
    classification.scope === 'GLOBAL' ||
    classification.scope === 'CGNAT' ||
    classification.scope === 'DOCUMENTATION' ||
    classification.scope === 'BENCHMARK'
  ) {
    throw new TcpTransportError('TCP_GLOBAL_ADDRESS_PROHIBITED')
  }
  if (
    classification.scope === 'UNSPECIFIED'
  ) {
    throw new TcpTransportError('TCP_WILDCARD_PROHIBITED')
  }
  if (
    classification.scope === 'MULTICAST' ||
    classification.scope === 'UNSUPPORTED' ||
    classification.scope === 'RESERVED'
  ) {
    throw new TcpTransportError('TCP_ENDPOINT_INVALID')
  }
  if (classification.scope === 'LINK_LOCAL' && ipVer === 6 && endpoint.scopeId === undefined) {
    throw new TcpTransportError('TCP_ENDPOINT_INVALID')
  }

  assertValidPort(endpoint.port, false)

  const connectTimeoutMs = options.connectTimeoutMs ?? CONNECT_TIMEOUT_MS

  const socket: Socket = createConnection({
    host: classification.normalizedAddress,
    port: endpoint.port
  })

  let clientConn: ClientTcpPeerConnection | null = null

  clientConn = new ClientTcpPeerConnection({
    socket,
    expectedServerId: options.expectedServerId,
    deviceFingerprint: options.deviceFingerprint,
    devicePublicKey: options.devicePublicKey,
    devicePrivateKey: options.devicePrivateKey,
    invite: options.invite,
    authorizationMode: options.authorizationMode,
    handshakeTimeoutMs: options.handshakeTimeoutMs,
    sessionSetupTimeoutMs: options.sessionSetupTimeoutMs,
    admissionTimeoutMs: options.admissionTimeoutMs,
    idleTimeoutMs: options.idleTimeoutMs,
    maxPendingWriteBytes: options.maxPendingWriteBytes,
    onMemberConnected: options.onMemberConnected
  })

  // Timer de connect timeout
  const connectTimer = setTimeout(() => {
    if (clientConn && clientConn.getState() === 'CONNECTING') {
      try {
        socket.destroy(new TcpTransportError('TCP_CONNECT_TIMEOUT'))
      } catch {
        // Ignora
      }
      clientConn.destroy()
    }
  }, connectTimeoutMs)

  socket.once('connect', () => {
    clearTimeout(connectTimer)
  })

  socket.once('error', () => {
    clearTimeout(connectTimer)
  })

  socket.once('close', () => {
    clearTimeout(connectTimer)
  })

  return clientConn
}
