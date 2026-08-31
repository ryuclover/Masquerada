import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'
import { createSocket, type Socket as DgramSocket, type RemoteInfo } from 'node:dgram'

import {
  classifyNetworkAddress,
  listLocalNetworkInterfaces,
  type NetworkInterfaceProvider
} from './network-interfaces'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  type VerifiedConnectivityDescriptor
} from './connectivity-descriptor'
import {
  isLegitimateActiveServerHandle,
  type DirectTcpEndpoint,
  type LanTcpServerHandle
} from './lan-transport'
import {
  isNetworkEnvironmentGeneration,
  type NetworkEnvironmentGeneration
} from './network-environment'
import {
  defaultConnectivityResourceGovernor,
  type ConnectivityResourceGovernor
} from './connectivity-resource-governor'
import type { ConnectivitySubsystem } from './connectivity-subsystem'

export const LAN_DISCOVERY_MAGIC = 'MQDL' // 4 bytes ASCII
export const LAN_DISCOVERY_VERSION = 1
export const LAN_DISCOVERY_DEFAULT_PORT = 45543
export const LAN_DISCOVERY_IPV4_MULTICAST = '239.255.45.43'
export const LAN_DISCOVERY_IPV6_MULTICAST = 'ff02::4543'
export const LAN_DISCOVERY_DOMAIN = 'Masquerada/lan-discovery-response/v1'

export const MAX_DISCOVERY_DATAGRAM_BYTES = 1200
export const DISCOVERY_NONCE_BYTES = 32
export const LAN_DISCOVERY_DEFAULT_TIMEOUT_MS = 2000

export const MAX_DISCOVERY_QUERIES_PER_WINDOW = 60 // Limite global por janela de 10s
export const MAX_DISCOVERY_QUERIES_PER_SOURCE = 10 // Limite por IP por janela de 10s
export const DISCOVERY_RATE_WINDOW_MS = 10000 // 10s
export const MAX_DISCOVERY_REPLAY_ENTRIES = 256 // Capacidade máxima do cache de replay

export enum LanDiscoveryMessageType {
  QUERY = 0x01,
  RESPONSE = 0x02
}

export type LanDiscoveryErrorCode =
  | 'DISCOVERY_TIMEOUT'
  | 'DISCOVERY_ABORTED'
  | 'DISCOVERY_INVALID_DATAGRAM'
  | 'DISCOVERY_MAGIC_MISMATCH'
  | 'DISCOVERY_UNSUPPORTED_VERSION'
  | 'DISCOVERY_WRONG_MESSAGE_TYPE'
  | 'DISCOVERY_FLAGS_NON_ZERO'
  | 'DISCOVERY_NONCE_MISMATCH'
  | 'DISCOVERY_SERVER_ID_MISMATCH'
  | 'DISCOVERY_SIGNATURE_INVALID'
  | 'DISCOVERY_DATAGRAM_OVERSIZED'
  | 'DISCOVERY_INTERFACE_UNAVAILABLE'
  | 'DISCOVERY_PORT_IN_USE'
  | 'DISCOVERY_NO_ACTIVE_LISTENERS'
  | 'DISCOVERY_CLOSED'
  | 'DISCOVERY_SOCKET_ERROR'

const ERROR_MESSAGES: Record<LanDiscoveryErrorCode, string> = {
  DISCOVERY_TIMEOUT: 'A descoberta LAN excedeu o tempo limite sem resposta da Server Identity esperada.',
  DISCOVERY_ABORTED: 'A operação de descoberta LAN foi cancelada pelo chamador.',
  DISCOVERY_INVALID_DATAGRAM: 'Datagrama UDP de descoberta malformado ou truncado.',
  DISCOVERY_MAGIC_MISMATCH: 'Magic header do datagrama de descoberta inválido.',
  DISCOVERY_UNSUPPORTED_VERSION: 'Versão do protocolo de descoberta não suportada.',
  DISCOVERY_WRONG_MESSAGE_TYPE: 'Tipo de mensagem de descoberta inválido ou inesperado.',
  DISCOVERY_FLAGS_NON_ZERO: 'Flags de cabeçalho de descoberta não suportadas ou não-zero.',
  DISCOVERY_NONCE_MISMATCH: 'O nonce retornado na resposta não corresponde ao nonce da query atual.',
  DISCOVERY_SERVER_ID_MISMATCH: 'A Server Identity retornada não corresponde ao expectedServerId fornecido.',
  DISCOVERY_SIGNATURE_INVALID: 'A assinatura criptográfica Ed25519 da resposta de descoberta é inválida.',
  DISCOVERY_DATAGRAM_OVERSIZED: 'O datagrama de descoberta excede o tamanho máximo seguro de 1200 bytes.',
  DISCOVERY_INTERFACE_UNAVAILABLE: 'A interface de rede local selecionada para descoberta não está disponível.',
  DISCOVERY_PORT_IN_USE: 'A porta UDP de descoberta já está em uso ou não pôde ser aberta.',
  DISCOVERY_NO_ACTIVE_LISTENERS: 'Nenhum listener TCP ativo válido fornecido para anúncio em descoberta.',
  DISCOVERY_CLOSED: 'O responder de descoberta LAN já foi encerrado.',
  DISCOVERY_SOCKET_ERROR: 'Ocorreu um erro no socket UDP de descoberta LAN.'
}

export class LanDiscoveryError extends Error {
  readonly code: LanDiscoveryErrorCode

  constructor(code: LanDiscoveryErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'LanDiscoveryError'
    this.code = code
  }
}

/**
 * Codifica uma DISCOVERY_QUERY direcionada para expectedServerId com queryNonce CSPRNG.
 */
export function encodeDiscoveryQuery(expectedServerId: string, queryNonce: Buffer): Buffer {
  if (typeof expectedServerId !== 'string' || expectedServerId.trim().length === 0) {
    throw new LanDiscoveryError('DISCOVERY_SERVER_ID_MISMATCH')
  }
  if (!Buffer.isBuffer(queryNonce) || queryNonce.length !== DISCOVERY_NONCE_BYTES) {
    throw new LanDiscoveryError('DISCOVERY_NONCE_MISMATCH')
  }

  const trimmedId = expectedServerId.trim()
  const idBuf = Buffer.from(trimmedId, 'utf8')
  if (idBuf.length > 255) {
    throw new LanDiscoveryError('DISCOVERY_DATAGRAM_OVERSIZED')
  }

  const magicBuf = Buffer.from(LAN_DISCOVERY_MAGIC, 'ascii')
  const totalLen = 4 + 1 + 1 + 2 + DISCOVERY_NONCE_BYTES + 1 + idBuf.length

  const buf = Buffer.alloc(totalLen)
  let offset = 0

  magicBuf.copy(buf, offset)
  offset += 4

  buf.writeUInt8(LAN_DISCOVERY_VERSION, offset++)
  buf.writeUInt8(LanDiscoveryMessageType.QUERY, offset++)
  buf.writeUInt16BE(0, offset) // Flags = 0
  offset += 2

  queryNonce.copy(buf, offset)
  offset += DISCOVERY_NONCE_BYTES

  buf.writeUInt8(idBuf.length, offset++)
  idBuf.copy(buf, offset)

  return buf
}

/**
 * Decodifica estritamente uma DISCOVERY_QUERY. Retorna null se inválida.
 */
export function parseDiscoveryQuery(
  buf: Buffer
): { queryNonce: Buffer; expectedServerId: string } | null {
  if (!Buffer.isBuffer(buf) || buf.length < 41 || buf.length > MAX_DISCOVERY_DATAGRAM_BYTES) {
    return null
  }

  let offset = 0
  const magic = buf.subarray(offset, offset + 4).toString('ascii')
  offset += 4
  if (magic !== LAN_DISCOVERY_MAGIC) return null

  const version = buf.readUInt8(offset++)
  if (version !== LAN_DISCOVERY_VERSION) return null

  const msgType = buf.readUInt8(offset++)
  if (msgType !== LanDiscoveryMessageType.QUERY) return null

  const flags = buf.readUInt16BE(offset)
  offset += 2
  if (flags !== 0) return null

  const queryNonce = Buffer.from(buf.subarray(offset, offset + DISCOVERY_NONCE_BYTES))
  offset += DISCOVERY_NONCE_BYTES

  const idLen = buf.readUInt8(offset++)
  if (offset + idLen !== buf.length) return null

  const expectedServerId = buf.subarray(offset, offset + idLen).toString('utf8')
  if (!expectedServerId.startsWith('sha256:')) return null

  return { queryNonce, expectedServerId }
}

/**
 * Constrói o payload canônico para assinatura da Discovery Response vinculada ao nonce e descriptor.
 */
export function buildCanonicalResponseSigningPayload(
  version: number,
  messageType: number,
  queryNonce: Buffer,
  serverId: string,
  descriptorHash: Buffer
): Buffer {
  const domainBuf = Buffer.from(LAN_DISCOVERY_DOMAIN, 'utf8')
  const serverIdBuf = Buffer.from(serverId, 'utf8')

  const chunks: Buffer[] = []

  // 1. Domain prefix
  const dHeader = Buffer.alloc(1 + domainBuf.length)
  dHeader.writeUInt8(domainBuf.length, 0)
  domainBuf.copy(dHeader, 1)
  chunks.push(dHeader)

  // 2. Version + MessageType
  const verType = Buffer.alloc(2)
  verType.writeUInt8(version, 0)
  verType.writeUInt8(messageType, 1)
  chunks.push(verType)

  // 3. QueryNonce (32 bytes)
  chunks.push(Buffer.from(queryNonce))

  // 4. ServerId (1 byte length + UTF-8)
  const idHeader = Buffer.alloc(1 + serverIdBuf.length)
  idHeader.writeUInt8(serverIdBuf.length, 0)
  serverIdBuf.copy(idHeader, 1)
  chunks.push(idHeader)

  // 5. DescriptorHash (32 bytes SHA-256)
  chunks.push(Buffer.from(descriptorHash))

  return Buffer.concat(chunks)
}

/**
 * Codifica e assina uma DISCOVERY_RESPONSE unicast vinculada criptograficamente ao queryNonce.
 */
export function encodeDiscoveryResponse(
  queryNonce: Buffer,
  serverId: string,
  serverPrivateKey: KeyObject,
  signedDescriptor: Buffer
): Buffer {
  if (!Buffer.isBuffer(queryNonce) || queryNonce.length !== DISCOVERY_NONCE_BYTES) {
    throw new LanDiscoveryError('DISCOVERY_NONCE_MISMATCH')
  }
  if (!Buffer.isBuffer(signedDescriptor) || signedDescriptor.length === 0) {
    throw new LanDiscoveryError('DISCOVERY_INVALID_DATAGRAM')
  }

  const descriptorHash = createHash('sha256').update(signedDescriptor).digest()
  const canonicalPayload = buildCanonicalResponseSigningPayload(
    LAN_DISCOVERY_VERSION,
    LanDiscoveryMessageType.RESPONSE,
    queryNonce,
    serverId,
    descriptorHash
  )

  const signature = sign(null, canonicalPayload, serverPrivateKey)
  if (signature.length !== 64) {
    throw new LanDiscoveryError('DISCOVERY_SIGNATURE_INVALID')
  }

  const magicBuf = Buffer.from(LAN_DISCOVERY_MAGIC, 'ascii')
  const headerLen = 4 + 1 + 1 + 2 + DISCOVERY_NONCE_BYTES + 2
  const totalLen = headerLen + signedDescriptor.length + 64

  if (totalLen > MAX_DISCOVERY_DATAGRAM_BYTES) {
    throw new LanDiscoveryError('DISCOVERY_DATAGRAM_OVERSIZED')
  }

  const buf = Buffer.alloc(totalLen)
  let offset = 0

  magicBuf.copy(buf, offset)
  offset += 4

  buf.writeUInt8(LAN_DISCOVERY_VERSION, offset++)
  buf.writeUInt8(LanDiscoveryMessageType.RESPONSE, offset++)
  buf.writeUInt16BE(0, offset) // Flags = 0
  offset += 2

  queryNonce.copy(buf, offset)
  offset += DISCOVERY_NONCE_BYTES

  buf.writeUInt16BE(signedDescriptor.length, offset)
  offset += 2

  signedDescriptor.copy(buf, offset)
  offset += signedDescriptor.length

  signature.copy(buf, offset)

  return buf
}

export interface VerifiedDiscoveryResponse {
  readonly queryNonce: Buffer
  readonly descriptor: VerifiedConnectivityDescriptor
}

/**
 * Decodifica, revalida e verifica uma DISCOVERY_RESPONSE.
 */
export function parseAndVerifyDiscoveryResponse(
  buf: Buffer,
  expectedServerId: string,
  expectedNonce: Buffer,
  nowSeconds?: number,
  allowLoopbackForTesting = false
): VerifiedDiscoveryResponse {
  if (!Buffer.isBuffer(buf) || buf.length < 100 || buf.length > MAX_DISCOVERY_DATAGRAM_BYTES) {
    throw new LanDiscoveryError('DISCOVERY_INVALID_DATAGRAM')
  }

  let offset = 0
  const magic = buf.subarray(offset, offset + 4).toString('ascii')
  offset += 4
  if (magic !== LAN_DISCOVERY_MAGIC) {
    throw new LanDiscoveryError('DISCOVERY_MAGIC_MISMATCH')
  }

  const version = buf.readUInt8(offset++)
  if (version !== LAN_DISCOVERY_VERSION) {
    throw new LanDiscoveryError('DISCOVERY_UNSUPPORTED_VERSION')
  }

  const msgType = buf.readUInt8(offset++)
  if (msgType !== LanDiscoveryMessageType.RESPONSE) {
    throw new LanDiscoveryError('DISCOVERY_WRONG_MESSAGE_TYPE')
  }

  const flags = buf.readUInt16BE(offset)
  offset += 2
  if (flags !== 0) {
    throw new LanDiscoveryError('DISCOVERY_FLAGS_NON_ZERO')
  }

  const queryNonce = Buffer.from(buf.subarray(offset, offset + DISCOVERY_NONCE_BYTES))
  offset += DISCOVERY_NONCE_BYTES

  if (!queryNonce.equals(expectedNonce)) {
    throw new LanDiscoveryError('DISCOVERY_NONCE_MISMATCH')
  }

  const descLen = buf.readUInt16BE(offset)
  offset += 2

  if (offset + descLen + 64 !== buf.length) {
    throw new LanDiscoveryError('DISCOVERY_INVALID_DATAGRAM')
  }

  const signedDescriptorBytes = buf.subarray(offset, offset + descLen)
  offset += descLen

  const signature = buf.subarray(offset, offset + 64)

  // 1. Verifica o SignedConnectivityDescriptor
  const verifiedDescriptor = verifySignedConnectivityDescriptor({
    encodedDescriptor: signedDescriptorBytes,
    expectedServerId,
    nowSeconds,
    allowLoopbackForTesting
  })

  // Defesa em profundidade: LAN Discovery v1 aceita estritamente LAN_TCP
  for (const c of verifiedDescriptor.candidates) {
    if (c.candidateType !== ConnectivityCandidateType.LAN_TCP) {
      throw new LanDiscoveryError('DISCOVERY_INVALID_DATAGRAM')
    }
  }

  // 2. Verifica a assinatura da Discovery Response
  const descriptorHash = createHash('sha256').update(signedDescriptorBytes).digest()
  const canonicalPayload = buildCanonicalResponseSigningPayload(
    version,
    msgType,
    queryNonce,
    verifiedDescriptor.serverId,
    descriptorHash
  )

  const pubKey = createPublicKey({
    key: verifiedDescriptor.serverPublicKey,
    format: 'der',
    type: 'spki'
  })

  const isValid = verify(null, canonicalPayload, pubKey, signature)
  if (!isValid) {
    throw new LanDiscoveryError('DISCOVERY_SIGNATURE_INVALID')
  }

  return {
    queryNonce,
    descriptor: verifiedDescriptor
  }
}

export interface StartLanDiscoveryResponderOptions {
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverPrivateKey: KeyObject
  readonly boundHandles: readonly LanTcpServerHandle[]
  readonly bindAddress: string
  readonly port?: number
  readonly multicastGroup?: string
  readonly interfaceProvider?: NetworkInterfaceProvider
  readonly maxQueriesPerWindow?: number
  readonly maxQueriesPerSource?: number
  readonly rateWindowMs?: number
  readonly maxReplayEntries?: number
  readonly allowLoopbackForTesting?: boolean
}

export interface LanDiscoveryResponder {
  readonly isClosed: () => boolean
  readonly close: () => Promise<void>
  readonly getProcessedQueryCount: () => number
}

/**
 * Inicia o responder de descoberta LAN UDP para uma Server Identity e interface específicas.
 */
export async function startLanDiscoveryResponder(
  options: StartLanDiscoveryResponderOptions
): Promise<LanDiscoveryResponder> {
  if (!options.boundHandles || options.boundHandles.length === 0) {
    throw new LanDiscoveryError('DISCOVERY_NO_ACTIVE_LISTENERS')
  }

  // Confirma que todos os handles são legítimos e estão abertos
  for (const h of options.boundHandles) {
    if (!isLegitimateActiveServerHandle(h) || (typeof h.isClosed === 'function' && h.isClosed())) {
      throw new LanDiscoveryError('DISCOVERY_NO_ACTIVE_LISTENERS')
    }
  }

  const classification = classifyNetworkAddress(options.bindAddress)
  if (
    classification.scope === 'GLOBAL' ||
    classification.scope === 'UNSPECIFIED' ||
    classification.scope === 'MULTICAST' ||
    classification.scope === 'UNSUPPORTED'
  ) {
    throw new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE')
  }

  if (classification.scope === 'LOOPBACK' && !options.allowLoopbackForTesting) {
    throw new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE')
  }

  const isIpv6 = classification.family === 'IPv6'
  const port = options.port ?? LAN_DISCOVERY_DEFAULT_PORT
  const multicastGroup =
    options.multicastGroup ??
    (isIpv6 ? LAN_DISCOVERY_IPV6_MULTICAST : LAN_DISCOVERY_IPV4_MULTICAST)

  const maxQueriesPerWindow = options.maxQueriesPerWindow ?? MAX_DISCOVERY_QUERIES_PER_WINDOW
  const maxQueriesPerSource = options.maxQueriesPerSource ?? MAX_DISCOVERY_QUERIES_PER_SOURCE
  const rateWindowMs = options.rateWindowMs ?? DISCOVERY_RATE_WINDOW_MS
  const maxReplayEntries = options.maxReplayEntries ?? MAX_DISCOVERY_REPLAY_ENTRIES

  // Rate limiter & Replay cache state
  let globalQueryCount = 0
  let windowStart = Date.now()
  const sourceQueryCounts = new Map<string, number>()
  const replayEntries = new Map<string, number>() // key -> timestamp
  let totalProcessedQueries = 0
  let isClosed = false

  const socket: DgramSocket = createSocket({
    type: isIpv6 ? 'udp6' : 'udp4',
    reuseAddr: true
  })

  // Tratamento de erro seguro
  socket.on('error', () => {
    // Não derruba o processo
  })

  await new Promise<void>((resolve, reject) => {
    const onError = () => {
      socket.close()
      reject(new LanDiscoveryError('DISCOVERY_PORT_IN_USE'))
    }
    socket.once('error', onError)

    socket.bind(port, classification.normalizedAddress, () => {
      socket.off('error', onError)
      try {
        if (classification.scope !== 'LOOPBACK') {
          socket.addMembership(multicastGroup, classification.normalizedAddress)
          socket.setMulticastTTL(1)
        }
        resolve()
      } catch {
        socket.close()
        reject(new LanDiscoveryError('DISCOVERY_SOCKET_ERROR'))
      }
    })
  })

  socket.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
    if (isClosed) return

    // 1. Parse query estrito
    const query = parseDiscoveryQuery(msg)
    if (!query) return

    // 2. Filtro exato de expectedServerId (ignora silenciosamente serverId divergente)
    if (query.expectedServerId !== options.serverId) return

    // 3. Valida rinfo.address
    const srcClass = classifyNetworkAddress(rinfo.address)
    if (
      srcClass.scope === 'UNSPECIFIED' ||
      srcClass.scope === 'MULTICAST' ||
      srcClass.scope === 'UNSUPPORTED'
    ) {
      return
    }

    // 4. Rate Limiting & Replay Cache
    const now = Date.now()
    if (now - windowStart > rateWindowMs) {
      windowStart = now
      globalQueryCount = 0
      sourceQueryCounts.clear()
    }

    // Limpa entradas expiradas do replay cache se necessário
    if (replayEntries.size > maxReplayEntries) {
      for (const [k, ts] of Array.from(replayEntries)) {
        if (now - ts > rateWindowMs) {
          replayEntries.delete(k)
        }
      }
      if (replayEntries.size > maxReplayEntries) {
        // Remove as mais antigas se ainda estiver cheio
        const oldestKey = replayEntries.keys().next().value
        if (oldestKey) replayEntries.delete(oldestKey)
      }
    }

    const normalizedSource = srcClass.normalizedAddress
    const replayKey = `${normalizedSource}|${query.queryNonce.toString('hex')}|${query.expectedServerId}`

    if (replayEntries.has(replayKey)) {
      return // Replay detectado: silêncio
    }
    replayEntries.set(replayKey, now)

    if (globalQueryCount >= maxQueriesPerWindow) return
    const srcCount = sourceQueryCounts.get(normalizedSource) ?? 0
    if (srcCount >= maxQueriesPerSource) return

    globalQueryCount++
    sourceQueryCounts.set(normalizedSource, srcCount + 1)
    totalProcessedQueries++

    // 5. Verifica se há listeners ativos abertos
    const activeHandles = options.boundHandles.filter(
      (h) => isLegitimateActiveServerHandle(h) && (typeof h.isClosed !== 'function' || !h.isClosed())
    )
    if (activeHandles.length === 0) return

    // 6. Gera SignedConnectivityDescriptor
    let signedDescriptor: Buffer
    try {
      signedDescriptor = createSignedConnectivityDescriptor({
        serverId: options.serverId,
        serverPublicKey: options.serverPublicKey,
        serverPrivateKey: options.serverPrivateKey,
        candidates: activeHandles,
        allowLoopbackForTesting: options.allowLoopbackForTesting
      })
    } catch {
      return
    }

    // 7. Codifica e assina a Discovery Response
    let responseBuf: Buffer
    try {
      responseBuf = encodeDiscoveryResponse(
        query.queryNonce,
        options.serverId,
        options.serverPrivateKey,
        signedDescriptor
      )
    } catch {
      return
    }

    // 8. Envia unicast response para o cliente
    socket.send(responseBuf, rinfo.port, rinfo.address, () => {
      // Ignora erros de envio
    })
  })

  return {
    isClosed: () => isClosed,
    getProcessedQueryCount: () => totalProcessedQueries,
    close: async () => {
      if (isClosed) return
      isClosed = true
      replayEntries.clear()
      sourceQueryCounts.clear()
      await new Promise<void>((resolve) => {
        try {
          if (classification.scope !== 'LOOPBACK') {
            socket.dropMembership(multicastGroup, classification.normalizedAddress)
          }
        } catch {
          // Ignora erro ao sair do grupo
        }
        socket.close(() => resolve())
      })
    }
  }
}

export interface DiscoverLanServerOptions {
  readonly expectedServerId: string
  readonly localInterfaceAddress: string
  readonly port?: number
  readonly multicastGroup?: string
  readonly targetUnicastAddress?: string // Opcional para testes diretos unicast
  readonly timeoutMs?: number
  readonly customNonce?: Buffer
  readonly signal?: AbortSignal
  readonly allowLoopbackForTesting?: boolean
  readonly nowSeconds?: number
  readonly interfaceProvider?: NetworkInterfaceProvider
  readonly networkGeneration?: NetworkEnvironmentGeneration
  readonly resourceGovernor?: ConnectivityResourceGovernor
  readonly subsystem?: ConnectivitySubsystem
}

export interface DiscoveredLanServer {
  readonly serverId: string
  readonly descriptor: VerifiedConnectivityDescriptor
  readonly endpoints: readonly DirectTcpEndpoint[]
  readonly responseSourceAddress: string
  readonly localInterfaceAddress: string
  readonly allowLoopbackForTesting: boolean
  readonly networkGeneration?: NetworkEnvironmentGeneration
}

const legitimateDiscoveredLanServers = new WeakSet<object>()

export function isLegitimateDiscoveredLanServer(value: unknown): value is DiscoveredLanServer {
  return typeof value === 'object' && value !== null && legitimateDiscoveredLanServers.has(value)
}

/**
 * Realiza descoberta LAN direcionada enviando DISCOVERY_QUERY e aguardando DISCOVERY_RESPONSE válida.
 * A API NÃO inicia conexões TCP automaticamente.
 */
export async function discoverLanServer(
  options: DiscoverLanServerOptions
): Promise<DiscoveredLanServer> {
  const work = options.subsystem?.beginWork(options.signal)
  const signal = work?.signal ?? options.signal
  let udpReservation
  try {
  udpReservation = (options.resourceGovernor ?? options.subsystem?.governor ?? defaultConnectivityResourceGovernor).reserve('UDP_OPERATION')
  if (options.networkGeneration !== undefined && !isNetworkEnvironmentGeneration(options.networkGeneration)) {
    throw new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE')
  }
  if (typeof options.expectedServerId !== 'string' || !options.expectedServerId.startsWith('sha256:')) {
    throw new LanDiscoveryError('DISCOVERY_SERVER_ID_MISMATCH')
  }

  const classification = classifyNetworkAddress(options.localInterfaceAddress)
  if (
    classification.scope === 'GLOBAL' ||
    classification.scope === 'UNSPECIFIED' ||
    classification.scope === 'MULTICAST' ||
    classification.scope === 'UNSUPPORTED'
  ) {
    throw new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE')
  }

  if (classification.scope === 'LOOPBACK' && !options.allowLoopbackForTesting) {
    throw new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE')
  }

  const interfaces = listLocalNetworkInterfaces(options.interfaceProvider)
  const matchingInterface = interfaces.find(
    (iface) => iface.address === classification.normalizedAddress
  )
  if (!matchingInterface) {
    throw new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE')
  }

  const isIpv6 = classification.family === 'IPv6'
  const port = options.port ?? LAN_DISCOVERY_DEFAULT_PORT
  const destinationAddress =
    options.targetUnicastAddress ??
    options.multicastGroup ??
    (isIpv6 ? LAN_DISCOVERY_IPV6_MULTICAST : LAN_DISCOVERY_IPV4_MULTICAST)

  const timeoutMs = options.timeoutMs ?? LAN_DISCOVERY_DEFAULT_TIMEOUT_MS
  const queryNonce = options.customNonce ?? randomBytes(DISCOVERY_NONCE_BYTES)

  const queryBuf = encodeDiscoveryQuery(options.expectedServerId, queryNonce)

  const clientSocket: DgramSocket = createSocket({
    type: isIpv6 ? 'udp6' : 'udp4',
    reuseAddr: true
  })

  return await new Promise<DiscoveredLanServer>((resolve, reject) => {
    let isFinished = false
    let timer: NodeJS.Timeout | null = null

    const cleanup = (): void => {
      if (timer !== null) {
        clearTimeout(timer)
        timer = null
      }
      signal?.removeEventListener('abort', onAbort)
      if (!isFinished) {
        isFinished = true
        try {
          clientSocket.close()
        } catch {
          // Ignora
        }
      }
    }

    const onAbort = (): void => {
      cleanup()
      reject(new LanDiscoveryError('DISCOVERY_ABORTED'))
    }

    if (signal?.aborted) {
      onAbort()
      return
    }

    signal?.addEventListener('abort', onAbort)

    clientSocket.on('error', () => {
      cleanup()
      reject(new LanDiscoveryError('DISCOVERY_SOCKET_ERROR'))
    })

    clientSocket.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
      if (isFinished) return

      try {
        const verified = parseAndVerifyDiscoveryResponse(
          msg,
          options.expectedServerId,
          queryNonce,
          options.nowSeconds,
          options.allowLoopbackForTesting
        )

        const responseSource = classifyNetworkAddress(rinfo.address)
        if (
          responseSource.family !== classification.family ||
          responseSource.normalizedAddress.length === 0
        ) {
          return
        }

        // Resolução dos candidates com base no contexto da interface local selecionada
        const resolvedEndpoints: DirectTcpEndpoint[] = []
        for (const cand of verified.descriptor.candidates) {
          if (cand.candidateType !== ConnectivityCandidateType.LAN_TCP) {
            continue
          }
          if (cand.address !== responseSource.normalizedAddress) continue
          if (cand.family === 6 && cand.scope === 'LINK_LOCAL') {
            const scopeId = matchingInterface?.scopeId
            if (typeof scopeId !== 'number' || scopeId < 0) {
              // Sem scopeId na interface local -> descarta candidate link-local
              continue
            }
            resolvedEndpoints.push({
              family: 6,
              address: cand.address,
              port: cand.port,
              scopeId
            })
          } else {
            resolvedEndpoints.push({
              family: cand.family,
              address: cand.address,
              port: cand.port
            })
          }
        }

        if (resolvedEndpoints.length === 0) return

        const result: DiscoveredLanServer = Object.freeze({
          serverId: verified.descriptor.serverId,
          descriptor: verified.descriptor,
          endpoints: Object.freeze(resolvedEndpoints),
          responseSourceAddress: responseSource.normalizedAddress,
          localInterfaceAddress: classification.normalizedAddress,
          allowLoopbackForTesting: options.allowLoopbackForTesting === true,
          networkGeneration: options.networkGeneration
        })
        legitimateDiscoveredLanServers.add(result)
        cleanup()
        resolve(result)
      } catch {
        // Datagrama hostil ou malformado é ignorado silenciosamente e continua aguardando
      }
    })

    clientSocket.bind(0, classification.normalizedAddress, () => {
      try {
        if (classification.scope !== 'LOOPBACK') {
          clientSocket.setMulticastTTL(1)
        }

        clientSocket.send(queryBuf, port, destinationAddress, (err) => {
          if (err) {
            cleanup()
            reject(new LanDiscoveryError('DISCOVERY_SOCKET_ERROR'))
            return
          }

          timer = setTimeout(() => {
            cleanup()
            reject(new LanDiscoveryError('DISCOVERY_TIMEOUT'))
          }, timeoutMs)
        })
      } catch {
        cleanup()
        reject(new LanDiscoveryError('DISCOVERY_SOCKET_ERROR'))
      }
    })
  })
  } finally {
    udpReservation?.release()
    work?.finish()
  }
}
