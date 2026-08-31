import { createSocket, type Socket as DgramSocket, type RemoteInfo } from 'node:dgram'
import { randomBytes } from 'node:crypto'
import { isIP } from 'node:net'

import {
  classifyNetworkAddress
} from './network-interfaces'
import {
  isLegitimateActiveServerHandle,
  type BoundTcpEndpoint,
  type DirectTcpEndpoint,
  type LanTcpServerHandle
} from './lan-transport'
import { assertValidPort } from './tcp-transport'
import {
  ActivePortMappingSource,
  isLegitimateActivePortMapping,
  MIN_MAPPING_REMAINING_FOR_DESCRIPTOR_SECONDS
} from './active-port-mapping'
import {
  createDefaultPortMappingGatewayProvider,
  type PortMappingGatewayProvider
} from './port-mapping-gateway'

export { isLegitimateActivePortMapping, MIN_MAPPING_REMAINING_FOR_DESCRIPTOR_SECONDS }

export const PCP_VERSION = 2
export const PCP_MAP_OPCODE = 1
export const PCP_SERVER_PORT = 5351
export const IP_PROTOCOL_TCP = 6

export const PCP_DEFAULT_MAPPING_LIFETIME_SECONDS = 3600 // 1 hora default
export const PCP_MIN_MAPPING_LIFETIME_SECONDS = 60 // 1 minuto mínimo
export const PCP_MAX_MAPPING_LIFETIME_SECONDS = 7200 // 2 horas máximo

export const PCP_NONCE_BYTES = 12
export const PCP_COMMON_HEADER_BYTES = 24
export const PCP_MAP_PAYLOAD_BYTES = 36
export const PCP_PACKET_BYTES = PCP_COMMON_HEADER_BYTES + PCP_MAP_PAYLOAD_BYTES // 60 bytes

export const PCP_INITIAL_TIMEOUT_MS = 1000
export const PCP_MAX_RETRANSMISSIONS = 3
export const PCP_CLOSE_TIMEOUT_MS = 2000

export enum PcpResultCode {
  SUCCESS = 0,
  UNSUPP_VERSION = 1,
  NOT_AUTHORIZED = 2,
  MALFORMED_REQUEST = 3,
  UNSUPP_OPCODE = 4,
  UNSUPP_OPTION = 5,
  MALFORMED_OPTION = 6,
  NETWORK_FAILURE = 7,
  NO_RESOURCES = 8,
  UNSUPP_PROTOCOL = 9,
  USER_EX_QUOTA = 10,
  CANNOT_PROVIDE_EXTERNAL = 11,
  ADDRESS_MISMATCH = 12,
  EXCESSIVE_REMOTE_PEERS = 13
}

export type PcpErrorCode =
  | 'PCP_LISTENER_INVALID'
  | 'PCP_LISTENER_CLOSED'
  | 'PCP_GATEWAY_NOT_FOUND'
  | 'PCP_GATEWAY_INVALID'
  | 'PCP_GATEWAY_DISCOVERY_UNSUPPORTED'
  | 'PCP_REQUEST_INVALID'
  | 'PCP_TIMEOUT'
  | 'PCP_RESPONSE_INVALID'
  | 'PCP_RESPONSE_SOURCE_INVALID'
  | 'PCP_UNSUPPORTED_VERSION'
  | 'PCP_UNSUPPORTED_RESPONSE_OPTIONS'
  | 'PCP_NONCE_MISMATCH'
  | 'PCP_SERVER_ERROR'
  | 'PCP_EXTERNAL_ADDRESS_NOT_GLOBAL'
  | 'PCP_MAPPING_EXPIRED'
  | 'PCP_MAPPING_CLOSED'
  | 'PCP_EPOCH_RESET'

const ERROR_MESSAGES: Record<PcpErrorCode, string> = {
  PCP_LISTENER_INVALID: 'O listener TCP fornecido para mapeamento PCP é inválido ou ilegítimo.',
  PCP_LISTENER_CLOSED: 'O listener TCP associado ao mapeamento PCP foi encerrado.',
  PCP_GATEWAY_NOT_FOUND: 'Nenhum gateway PCP válido foi encontrado para a interface local.',
  PCP_GATEWAY_INVALID: 'O endereço do gateway PCP é inválido ou incompatível.',
  PCP_GATEWAY_DISCOVERY_UNSUPPORTED: 'A descoberta automática de gateway não é suportada nesta plataforma.',
  PCP_REQUEST_INVALID: 'Os parâmetros da requisição PCP são inválidos.',
  PCP_TIMEOUT: 'Tempo limite esgotado aguardando resposta do gateway PCP.',
  PCP_RESPONSE_INVALID: 'A resposta recebida do gateway PCP é malformada ou inválida.',
  PCP_RESPONSE_SOURCE_INVALID: 'A resposta recebida não originou do gateway PCP esperado.',
  PCP_UNSUPPORTED_VERSION: 'O gateway esperado respondeu que não suporta PCP Version 2.',
  PCP_UNSUPPORTED_RESPONSE_OPTIONS: 'A resposta do gateway PCP contém opções não suportadas.',
  PCP_NONCE_MISMATCH: 'O nonce da resposta PCP não coincide com a transação de mapeamento.',
  PCP_SERVER_ERROR: 'O servidor PCP retornou erro ao processar o mapeamento.',
  PCP_EXTERNAL_ADDRESS_NOT_GLOBAL: 'O endereço externo atribuído pelo PCP não é globalmente roteável.',
  PCP_MAPPING_EXPIRED: 'A lease do mapeamento PCP expirou.',
  PCP_MAPPING_CLOSED: 'O mapeamento PCP foi encerrado.',
  PCP_EPOCH_RESET: 'O servidor PCP reiniciou ou perdeu seu estado de epoch.'
}

export class PcpError extends Error {
  readonly code: PcpErrorCode
  readonly resultCode?: PcpResultCode

  constructor(code: PcpErrorCode, resultCode?: PcpResultCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'PcpError'
    this.code = code
    this.resultCode = resultCode
  }
}

export interface PcpMapRequestOptions {
  readonly requestedLifetimeSeconds: number
  readonly clientIpAddress: string
  readonly mappingNonce: Buffer
  readonly internalPort: number
  readonly suggestedExternalPort?: number
  readonly suggestedExternalIp?: string
}

export interface PcpMapResponse {
  readonly version: number
  readonly resultCode: PcpResultCode
  readonly lifetimeSeconds: number
  readonly epochTime: number
  readonly mappingNonce: Buffer
  readonly internalPort: number
  readonly assignedExternalPort: number
  readonly assignedExternalAddress: string
}

/**
 * Codifica endereço IPv4 no formato de 16 bytes IPv4-mapped IPv6 (::ffff:a.b.c.d).
 */
export function encodeIpv4ToMappedIpv6(ipv4: string): Buffer {
  const parts = ipv4.split('.')
  if (parts.length !== 4) {
    throw new PcpError('PCP_REQUEST_INVALID')
  }

  const buf = Buffer.alloc(16, 0)
  buf.writeUInt16BE(0xffff, 10)
  for (let i = 0; i < 4; i++) {
    const octet = Number(parts[i])
    if (isNaN(octet) || octet < 0 || octet > 255) {
      throw new PcpError('PCP_REQUEST_INVALID')
    }
    buf.writeUInt8(octet, 12 + i)
  }
  return buf
}

/**
 * Decodifica endereço de 16 bytes do PCP para IPv4 canônico.
 */
export function decodeMappedIpv6ToIpv4(buf: Buffer): string | null {
  if (buf.length !== 16) return null

  // Verifica se é ::ffff:a.b.c.d
  for (let i = 0; i < 10; i++) {
    if (buf[i] !== 0) return null
  }
  if (buf.readUInt16BE(10) !== 0xffff) return null

  const p1 = buf[12]
  const p2 = buf[13]
  const p3 = buf[14]
  const p4 = buf[15]
  return `${p1}.${p2}.${p3}.${p4}`
}

/**
 * Codifica uma requisição binária canônica PCP MAP v2 (exatamente 60 bytes).
 */
export function encodePcpMapRequest(options: PcpMapRequestOptions): Buffer {
  if (!options.mappingNonce || options.mappingNonce.length !== PCP_NONCE_BYTES) {
    throw new PcpError('PCP_REQUEST_INVALID')
  }
  assertValidPort(options.internalPort, false)

  const buf = Buffer.alloc(PCP_PACKET_BYTES, 0)
  let offset = 0

  // 1. Common Request Header (24 bytes)
  buf.writeUInt8(PCP_VERSION, offset++) // Version = 2
  buf.writeUInt8(PCP_MAP_OPCODE & 0x7f, offset++) // R=0, Opcode=1 (MAP)
  buf.writeUInt16BE(0, offset) // Reserved = 0
  offset += 2
  buf.writeUInt32BE(options.requestedLifetimeSeconds >>> 0, offset)
  offset += 4

  const clientIpBuf = encodeIpv4ToMappedIpv6(options.clientIpAddress)
  clientIpBuf.copy(buf, offset)
  offset += 16

  // 2. MAP Request Payload (36 bytes)
  options.mappingNonce.copy(buf, offset)
  offset += PCP_NONCE_BYTES

  buf.writeUInt8(IP_PROTOCOL_TCP, offset++) // Protocol = 6 (TCP)
  buf.writeUInt8(0, offset++) // Reserved
  buf.writeUInt8(0, offset++)
  buf.writeUInt8(0, offset++)

  buf.writeUInt16BE(options.internalPort, offset)
  offset += 2

  const suggestedPort = options.suggestedExternalPort ?? 0
  buf.writeUInt16BE(suggestedPort, offset)
  offset += 2

  if (options.suggestedExternalIp) {
    const extIpBuf = encodeIpv4ToMappedIpv6(options.suggestedExternalIp)
    extIpBuf.copy(buf, offset)
  } else {
    buf.fill(0, offset, offset + 16)
  }

  return buf
}

/**
 * Decodifica e valida estritamente uma resposta binária PCP MAP v2.
 */
export function decodePcpMapResponse(buf: Buffer): PcpMapResponse {
  if (!Buffer.isBuffer(buf) || buf.length < PCP_PACKET_BYTES) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  if (buf.length > PCP_PACKET_BYTES) {
    // Rejeita respostas com options não suportadas nesta versão
    throw new PcpError('PCP_UNSUPPORTED_RESPONSE_OPTIONS')
  }

  let offset = 0

  // 1. Common Response Header (24 bytes)
  const version = buf.readUInt8(offset++)
  if (version !== PCP_VERSION) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  const rOpcode = buf.readUInt8(offset++)
  const isResponse = (rOpcode & 0x80) !== 0
  const opcode = rOpcode & 0x7f

  if (!isResponse || opcode !== PCP_MAP_OPCODE) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  offset++ // Reserved byte
  const resultCode = buf.readUInt8(offset++) as PcpResultCode
  const lifetimeSeconds = buf.readUInt32BE(offset)
  offset += 4
  const epochTime = buf.readUInt32BE(offset)
  offset += 4

  offset += 12 // 96 bits reserved

  // 2. MAP Response Payload (36 bytes)
  const mappingNonce = Buffer.from(buf.subarray(offset, offset + PCP_NONCE_BYTES))
  offset += PCP_NONCE_BYTES

  const protocol = buf.readUInt8(offset++)
  if (protocol !== IP_PROTOCOL_TCP) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  offset += 3 // Reserved 3 bytes
  const internalPort = buf.readUInt16BE(offset)
  offset += 2
  const assignedExternalPort = buf.readUInt16BE(offset)
  offset += 2

  const rawAssignedIp = buf.subarray(offset, offset + 16)
  const assignedExternalAddress = decodeMappedIpv6ToIpv4(rawAssignedIp)

  if (!assignedExternalAddress) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  return {
    version,
    resultCode,
    lifetimeSeconds,
    epochTime,
    mappingNonce,
    internalPort,
    assignedExternalPort,
    assignedExternalAddress
  }
}

export interface PcpUnsupportedVersionResponse {
  readonly version: 0
  readonly opcode: 0
  readonly resultCode: 1
  readonly epochTime: number
}

/** Resposta NAT-PMP mínima (8 bytes) de incompatibilidade com PCP v2. */
export function decodePcpUnsupportedVersionResponse(
  buf: Buffer
): PcpUnsupportedVersionResponse {
  if (!Buffer.isBuffer(buf) || buf.length !== 8) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }
  if (buf.readUInt8(0) !== 0 || buf.readUInt8(1) !== 0 || buf.readUInt16BE(2) !== 1) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  return {
    version: 0,
    opcode: 0,
    resultCode: 1,
    epochTime: buf.readUInt32BE(4)
  }
}

export type PcpGatewayProvider = PortMappingGatewayProvider

/**
 * Provedor padrão de gateway consultando rotas locais de forma segura.
 */
export function createDefaultPcpGatewayProvider(): PcpGatewayProvider {
  return createDefaultPortMappingGatewayProvider()
}

export type PcpEpochValidationResult = 'VALID' | 'STATE_LOSS_SUSPECTED'

export interface PcpEpochState {
  readonly prevServerEpoch: number
  readonly prevClientMonotonicSeconds: number
}

export type MonotonicClockProvider = () => number

export function defaultMonotonicSecondsProvider(): number {
  return Math.floor(Number(process.hrtime.bigint() / 1_000_000_000n))
}

/**
 * Valida a transição de Epoch do servidor PCP segundo RFC 6887 §8.5.
 *
 * Regras:
 * 1. Primeira resposta: aceita como baseline.
 * 2. Relógio monotônico do cliente: clientDelta = currClient - prevClient >= 0.
 * 3. Retrocesso aparente <= 1s: tolerado para reordenação de pacotes.
 * 4. Retrocesso > 1s: detecta provável perda de estado / reboot.
 * 5. Comparação de Skew (tolerância de 1/16 + 2 segundos inteiros):
 *    - Se (clientDelta + 2 < serverDelta - floor(serverDelta / 16)) -> STATE_LOSS_SUSPECTED
 *    - Se (serverDelta + 2 < clientDelta - floor(clientDelta / 16)) -> STATE_LOSS_SUSPECTED
 *    Caso contrário -> VALID.
 */
export function validatePcpEpochTransition(
  state: PcpEpochState | null,
  currServerEpoch: number,
  currClientMonotonicSeconds: number
): { result: PcpEpochValidationResult; nextState: PcpEpochState | null } {
  if (
    typeof currServerEpoch !== 'number' ||
    !Number.isInteger(currServerEpoch) ||
    currServerEpoch < 0 ||
    currServerEpoch > 0xffffffff
  ) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }

  if (
    typeof currClientMonotonicSeconds !== 'number' ||
    !Number.isFinite(currClientMonotonicSeconds)
  ) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }

  // 1. Primeira resposta: baseline inicial
  if (!state) {
    return {
      result: 'VALID',
      nextState: {
        prevServerEpoch: currServerEpoch,
        prevClientMonotonicSeconds: currClientMonotonicSeconds
      }
    }
  }

  // 2. Relógio monotônico do cliente não pode retroceder
  const clientDelta = currClientMonotonicSeconds - state.prevClientMonotonicSeconds
  if (clientDelta < 0) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }

  // 3. Verificação de retrocesso do Epoch do servidor
  if (currServerEpoch < state.prevServerEpoch) {
    const apparentRetrocession = state.prevServerEpoch - currServerEpoch
    if (apparentRetrocession > 1) {
      return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
    }
  }

  // 4. Cálculo de serverDelta (clamp para retrocesso de 1s de reordenação)
  const serverDelta = Math.max(0, currServerEpoch - state.prevServerEpoch)

  // 5. Tolerância do RFC 6887 §8.5 usando aritmética estritamente inteira:
  const serverDeltaTolerance = Math.floor(serverDelta / 16)
  const clientDeltaTolerance = Math.floor(clientDelta / 16)

  if (clientDelta + 2 < serverDelta - serverDeltaTolerance) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }

  if (serverDelta + 2 < clientDelta - clientDeltaTolerance) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }

  return {
    result: 'VALID',
    nextState: {
      prevServerEpoch: currServerEpoch,
      prevClientMonotonicSeconds: currClientMonotonicSeconds
    }
  }
}

export interface CreatePcpPortMappingOptions {
  readonly listener: LanTcpServerHandle
  readonly requestedLifetimeSeconds?: number
  readonly gatewayProvider?: PcpGatewayProvider
  readonly customGatewayAddress?: string // Apenas para testes unitários controlados
  readonly customGatewayPort?: number // Apenas para testes unitários controlados
  readonly timeoutMs?: number
  readonly maxRetransmissions?: number
  readonly monotonicClock?: MonotonicClockProvider
  /** Uso interno da PortMappingStrategy; APIs low-level mantêm auto-renew por default. */
  readonly autoRenew?: boolean
}

const PCP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN = Symbol('pcp-active-mapping')

export class ActivePortMapping extends ActivePortMappingSource {
  private isMappingActive = true
  private renewalTimer: NodeJS.Timeout | null = null

  private readonly listener: LanTcpServerHandle
  private readonly gateway: string
  private readonly gatewayPort: number
  private readonly mappingNonce: Buffer
  private readonly internalAddress: string
  private readonly internalPort: number
  private readonly monotonicClock: MonotonicClockProvider
  private readonly autoRenew: boolean

  private externalAddress: string
  private externalPort: number
  private grantedLifetimeSeconds: number
  private expiresAtUnixSeconds: number
  private monotonicDeadlineSeconds: number
  private lastMonotonicSeconds: number
  private epochState: PcpEpochState | null = null

  constructor(options: {
    constructionToken: typeof PCP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN
    listener: LanTcpServerHandle
    gateway: string
    gatewayPort: number
    mappingNonce: Buffer
    internalAddress: string
    internalPort: number
    externalAddress: string
    externalPort: number
    grantedLifetimeSeconds: number
    epochTime: number
    monotonicClock?: MonotonicClockProvider
    autoRenew?: boolean
  }) {
    if (options.constructionToken !== PCP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN) {
      throw new PcpError('PCP_REQUEST_INVALID')
    }
    super()
    this.listener = options.listener
    this.gateway = options.gateway
    this.gatewayPort = options.gatewayPort
    this.mappingNonce = options.mappingNonce
    this.internalAddress = options.internalAddress
    this.internalPort = options.internalPort
    this.externalAddress = options.externalAddress
    this.externalPort = options.externalPort
    this.grantedLifetimeSeconds = options.grantedLifetimeSeconds
    this.monotonicClock = options.monotonicClock ?? defaultMonotonicSecondsProvider
    this.autoRenew = options.autoRenew !== false

    const nowMonotonic = this.monotonicClock()
    if (!Number.isFinite(nowMonotonic)) throw new PcpError('PCP_REQUEST_INVALID')
    this.lastMonotonicSeconds = nowMonotonic
    const epochInit = validatePcpEpochTransition(null, options.epochTime, nowMonotonic)
    this.epochState = epochInit.nextState

    const nowSeconds = Math.floor(Date.now() / 1000)
    this.expiresAtUnixSeconds = nowSeconds + options.grantedLifetimeSeconds
    this.monotonicDeadlineSeconds = nowMonotonic + options.grantedLifetimeSeconds

    this.scheduleRenewal()
  }

  isActive(): boolean {
    if (!this.isMappingActive) return false
    if (this.listener.isClosed()) {
      this.isMappingActive = false
      return false
    }
    let nowMonotonic: number
    try { nowMonotonic = this.readMonotonicSeconds() } catch { return false }
    if (nowMonotonic >= this.monotonicDeadlineSeconds) {
      this.isMappingActive = false
      return false
    }
    return true
  }

  getExternalEndpoint(): DirectTcpEndpoint {
    return {
      family: 4,
      address: this.externalAddress,
      port: this.externalPort
    }
  }

  getExpiresAt(): number {
    return this.expiresAtUnixSeconds
  }

  getGrantedLifetime(): number {
    return this.grantedLifetimeSeconds
  }

  getInternalEndpoint(): BoundTcpEndpoint {
    return this.listener.endpoint
  }

  getGateway(): string {
    return this.gateway
  }

  getEpochState(): PcpEpochState | null {
    return this.epochState
  }

  async executeRenewalForTesting(): Promise<void> {
    await this.executeRenewal()
  }

  async renewForManagedStrategy(): Promise<void> {
    await this.executeRenewal()
  }

  private readMonotonicSeconds(): number {
    const current = this.monotonicClock()
    if (!Number.isFinite(current) || current < this.lastMonotonicSeconds) {
      this.isMappingActive = false
      if (this.renewalTimer) clearTimeout(this.renewalTimer)
      throw new PcpError('PCP_RESPONSE_INVALID')
    }
    this.lastMonotonicSeconds = current
    return current
  }

  private scheduleRenewal(): void {
    if (this.renewalTimer) {
      clearTimeout(this.renewalTimer)
      this.renewalTimer = null
    }

    if (!this.isMappingActive || !this.autoRenew) return

    // Renova em ~50% do tempo de lease
    const renewalDelayMs = Math.max(1000, Math.floor((this.grantedLifetimeSeconds * 1000) / 2))

    this.renewalTimer = setTimeout(() => {
      void this.executeRenewal()
    }, renewalDelayMs)
  }

  private async executeRenewal(): Promise<void> {
    if (!this.isActive()) return

    try {
      const response = await executePcpExchange({
        localIp: this.internalAddress,
        gatewayIp: this.gateway,
        gatewayPort: this.gatewayPort,
        request: {
          requestedLifetimeSeconds: this.grantedLifetimeSeconds,
          clientIpAddress: this.internalAddress,
          mappingNonce: this.mappingNonce,
          internalPort: this.internalPort,
          suggestedExternalPort: this.externalPort,
          suggestedExternalIp: this.externalAddress
        }
      })

      if (response.resultCode !== PcpResultCode.SUCCESS || response.assignedExternalPort === 0) {
        // Se falhar o renewal, continua ativo até a deadline original
        return
      }

      // Validação de Epoch segundo RFC 6887 §8.5
      const nowMonotonic = this.readMonotonicSeconds()
      const epochValidation = validatePcpEpochTransition(
        this.epochState,
        response.epochTime,
        nowMonotonic
      )

      if (epochValidation.result !== 'VALID' || !epochValidation.nextState) {
        // O servidor PCP reiniciou ou perdeu estado; mapeamento invalidado
        this.isMappingActive = false
        if (this.renewalTimer) clearTimeout(this.renewalTimer)
        return
      }

      this.epochState = epochValidation.nextState

      // Validação do novo endereço externo atribuído
      const classification = classifyNetworkAddress(response.assignedExternalAddress)
      if (!classification.isGloballyRoutableWan || classification.scope !== 'GLOBAL') {
        this.isMappingActive = false
        if (this.renewalTimer) clearTimeout(this.renewalTimer)
        return
      }

      // Atualiza estado do mapping com a nova concessão
      this.externalAddress = classification.normalizedAddress
      this.externalPort = response.assignedExternalPort
      this.grantedLifetimeSeconds = response.lifetimeSeconds
      this.expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + response.lifetimeSeconds
      this.monotonicDeadlineSeconds = nowMonotonic + response.lifetimeSeconds

      this.scheduleRenewal()
    } catch {
      // Ignora erro temporário de renewal; tentará novamente ou expirará no deadline
    }
  }

  async close(): Promise<void> {
    if (!this.isMappingActive) return
    this.isMappingActive = false

    if (this.renewalTimer) {
      clearTimeout(this.renewalTimer)
      this.renewalTimer = null
    }

    // Best-effort deletion enviando MAP com Lifetime = 0
    try {
      await executePcpExchange({
        localIp: this.internalAddress,
        gatewayIp: this.gateway,
        gatewayPort: this.gatewayPort,
        timeoutMs: PCP_CLOSE_TIMEOUT_MS,
        maxRetransmissions: 1,
        request: {
          requestedLifetimeSeconds: 0, // 0 = delete
          clientIpAddress: this.internalAddress,
          mappingNonce: this.mappingNonce,
          internalPort: this.internalPort,
          suggestedExternalPort: this.externalPort,
          suggestedExternalIp: this.externalAddress
        }
      })
    } catch {
      // Best-effort deletion
    }
  }
}

interface ExecutePcpExchangeOptions {
  readonly localIp: string
  readonly gatewayIp: string
  readonly gatewayPort?: number
  readonly timeoutMs?: number
  readonly maxRetransmissions?: number
  readonly request: PcpMapRequestOptions
}

/**
 * Executa uma transação PCP UDP cliente com retransmissão controlada e correlação estrita.
 */
async function executePcpExchange(options: ExecutePcpExchangeOptions): Promise<PcpMapResponse> {
  const gatewayPort = options.gatewayPort ?? PCP_SERVER_PORT
  const timeoutMs = options.timeoutMs ?? PCP_INITIAL_TIMEOUT_MS
  const maxRetries = options.maxRetransmissions ?? PCP_MAX_RETRANSMISSIONS

  const requestBuffer = encodePcpMapRequest(options.request)

  const socket: DgramSocket = createSocket('udp4')

  try {
    // Bind estrito no mesmo IP local da interface
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject)
      socket.bind(0, options.localIp, () => {
        socket.off('error', reject)
        resolve()
      })
    })

    return await new Promise<PcpMapResponse>((resolve, reject) => {
      let isDone = false
      let retryCount = 0
      let timer: NodeJS.Timeout | null = null

      const cleanup = (): void => {
        isDone = true
        if (timer) clearTimeout(timer)
        socket.removeAllListeners()
        try {
          socket.close()
        } catch {
          // Ignora erro ao fechar socket
        }
      }

      socket.on('error', (err) => {
        if (isDone) return
        cleanup()
        reject(err)
      })

      socket.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
        if (isDone) return

        // 1. Validação estrita da origem (source gateway e porta)
        if (rinfo.address !== options.gatewayIp || rinfo.port !== gatewayPort) {
          return
        }

        // 2. Parse e correlação
        try {
          if (msg.length === 8) {
            decodePcpUnsupportedVersionResponse(msg)
            cleanup()
            reject(new PcpError('PCP_UNSUPPORTED_VERSION', PcpResultCode.UNSUPP_VERSION))
            return
          }

          const response = decodePcpMapResponse(msg)

          // Validações de correlação RFC 6887
          if (!response.mappingNonce.equals(options.request.mappingNonce)) {
            return
          }

          if (response.internalPort !== options.request.internalPort) {
            return
          }

          cleanup()
          resolve(response)
        } catch (parseErr) {
          cleanup()
          reject(parseErr)
        }
      })

      const sendAttempt = (): void => {
        if (isDone) return

        socket.send(requestBuffer, gatewayPort, options.gatewayIp, (sendErr) => {
          if (sendErr && !isDone) {
            cleanup()
            reject(sendErr)
            return
          }

          if (isDone) return

          // Exponential backoff com jitter simples
          const currentTimeout = timeoutMs * Math.pow(2, retryCount)
          const jitter = Math.floor(Math.random() * 200)

          timer = setTimeout(() => {
            if (isDone) return
            retryCount++
            if (retryCount >= maxRetries) {
              cleanup()
              reject(new PcpError('PCP_TIMEOUT'))
            } else {
              sendAttempt()
            }
          }, currentTimeout + jitter)
        })
      }

      sendAttempt()
    })
  } finally {
    try {
      socket.close()
    } catch {
      // Ignora erro
    }
  }
}

/**
 * Cria um mapeamento de porta PCP seguro associado a um LanTcpServerHandle legítimo.
 */
export async function createPcpPortMapping(
  options: CreatePcpPortMappingOptions
): Promise<ActivePortMapping> {
  const { listener } = options

  // 1. Validação da legitimidade do listener local
  if (listener && typeof listener === 'object' && typeof listener.isClosed === 'function' && listener.isClosed()) {
    throw new PcpError('PCP_LISTENER_CLOSED')
  }

  if (!isLegitimateActiveServerHandle(listener)) {
    throw new PcpError('PCP_LISTENER_INVALID')
  }

  const endpoint = listener.endpoint
  if (endpoint.family !== 4) {
    throw new PcpError('PCP_REQUEST_INVALID')
  }

  const localIp = endpoint.address
  const internalPort = endpoint.port

  // 2. Descoberta e validação do gateway
  const gatewayIp: string | null = options.customGatewayAddress
    ? options.customGatewayAddress
    : await (options.gatewayProvider ?? createDefaultPcpGatewayProvider()).resolveGatewayForLocalAddress(localIp)

  if (!gatewayIp) {
    throw new PcpError('PCP_GATEWAY_NOT_FOUND')
  }

  if (isIP(gatewayIp) !== 4) {
    throw new PcpError('PCP_GATEWAY_INVALID')
  }

  const gatewayClass = classifyNetworkAddress(gatewayIp)
  if (gatewayClass.scope !== 'LAN_PRIVATE' && gatewayClass.scope !== 'LINK_LOCAL' && gatewayClass.scope !== 'LOOPBACK') {
    throw new PcpError('PCP_GATEWAY_INVALID')
  }

  // 3. Preparação dos parâmetros PCP
  const requestedLifetime = Math.min(
    PCP_MAX_MAPPING_LIFETIME_SECONDS,
    Math.max(
      PCP_MIN_MAPPING_LIFETIME_SECONDS,
      options.requestedLifetimeSeconds ?? PCP_DEFAULT_MAPPING_LIFETIME_SECONDS
    )
  )

  const mappingNonce = randomBytes(PCP_NONCE_BYTES)

  // 4. Execução da transação PCP
  const response = await executePcpExchange({
    localIp,
    gatewayIp,
    gatewayPort: options.customGatewayPort,
    timeoutMs: options.timeoutMs,
    maxRetransmissions: options.maxRetransmissions,
    request: {
      requestedLifetimeSeconds: requestedLifetime,
      clientIpAddress: localIp,
      mappingNonce,
      internalPort,
      suggestedExternalPort: 0,
      suggestedExternalIp: undefined
    }
  })

  // 5. Validação do código de resultado
  if (response.resultCode !== PcpResultCode.SUCCESS) {
    throw new PcpError('PCP_SERVER_ERROR', response.resultCode)
  }

  if (response.assignedExternalPort === 0 || response.assignedExternalPort > 65535) {
    throw new PcpError('PCP_RESPONSE_INVALID')
  }

  // 6. Validação estrita do endereço externo retornado
  const extClassification = classifyNetworkAddress(response.assignedExternalAddress)
  if (!extClassification.isGloballyRoutableWan || extClassification.scope !== 'GLOBAL') {
    // Se o router retornou IP privado/CGNAT/inválido: tenta deletar o mapping inútil
    try {
      await executePcpExchange({
        localIp,
        gatewayIp,
        gatewayPort: options.customGatewayPort,
        timeoutMs: PCP_CLOSE_TIMEOUT_MS,
        maxRetransmissions: 1,
        request: {
          requestedLifetimeSeconds: 0,
          clientIpAddress: localIp,
          mappingNonce,
          internalPort,
          suggestedExternalPort: response.assignedExternalPort,
          suggestedExternalIp: response.assignedExternalAddress
        }
      })
    } catch {
      // Ignora erro no cleanup
    }
    throw new PcpError('PCP_EXTERNAL_ADDRESS_NOT_GLOBAL')
  }

  // 7. Criação da runtime capability não-forjável
  return new ActivePortMapping({
    constructionToken: PCP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN,
    listener,
    gateway: gatewayIp,
    gatewayPort: options.customGatewayPort ?? PCP_SERVER_PORT,
    mappingNonce,
    internalAddress: localIp,
    internalPort,
    externalAddress: extClassification.normalizedAddress,
    externalPort: response.assignedExternalPort,
    grantedLifetimeSeconds: response.lifetimeSeconds || requestedLifetime,
    epochTime: response.epochTime,
    monotonicClock: options.monotonicClock,
    autoRenew: options.autoRenew
  })
}
