import { createSocket, type Socket as DgramSocket, type RemoteInfo } from 'node:dgram'
import { isIP } from 'node:net'

import { ActivePortMappingSource } from './active-port-mapping'
import { classifyNetworkAddress } from './network-interfaces'
import {
  isLegitimateActiveServerHandle,
  registerLanTcpServerCloseListener,
  type BoundTcpEndpoint,
  type DirectTcpEndpoint,
  type LanTcpServerHandle
} from './lan-transport'
import {
  createDefaultPortMappingGatewayProvider,
  type PortMappingGatewayProvider
} from './port-mapping-gateway'
import {
  defaultMonotonicSecondsProvider,
  type MonotonicClockProvider
} from './pcp-client'

export const NAT_PMP_VERSION = 0
export const NAT_PMP_PUBLIC_ADDRESS_OPCODE = 0
export const NAT_PMP_MAP_UDP_OPCODE = 1
export const NAT_PMP_MAP_TCP_OPCODE = 2
export const NAT_PMP_SERVER_PORT = 5351
export const NAT_PMP_OP_EXTERNAL_ADDRESS = NAT_PMP_PUBLIC_ADDRESS_OPCODE
export const NAT_PMP_OP_MAP_TCP = NAT_PMP_MAP_TCP_OPCODE

export const NAT_PMP_EXTERNAL_ADDRESS_REQUEST_BYTES = 2
export const NAT_PMP_EXTERNAL_ADDRESS_RESPONSE_BYTES = 12
export const NAT_PMP_TCP_MAPPING_REQUEST_BYTES = 12
export const NAT_PMP_TCP_MAPPING_RESPONSE_BYTES = 16
export const NAT_PMP_DEFAULT_MAPPING_LIFETIME_SECONDS = 7200
export const NAT_PMP_MAX_MAPPING_LIFETIME_SECONDS = 86_400
export const NAT_PMP_INITIAL_TIMEOUT_MS = 250
/** Quatro attempts (250/500/1000/2000 ms); ver threat model para o desvio do RFC. */
export const NAT_PMP_MAX_ATTEMPTS = 4
export const NAT_PMP_MAX_RETRANSMISSIONS = NAT_PMP_MAX_ATTEMPTS
export const NAT_PMP_DELETE_ATTEMPTS = 2

export enum NatPmpResultCode {
  SUCCESS = 0,
  UNSUPP_VERSION = 1,
  NOT_AUTHORIZED = 2,
  NETWORK_FAILURE = 3,
  OUT_OF_RESOURCES = 4,
  UNSUPP_OPCODE = 5
}

export type NatPmpErrorCode =
  | 'NAT_PMP_LISTENER_INVALID'
  | 'NAT_PMP_LISTENER_CLOSED'
  | 'NAT_PMP_GATEWAY_NOT_FOUND'
  | 'NAT_PMP_GATEWAY_INVALID'
  | 'NAT_PMP_REQUEST_INVALID'
  | 'NAT_PMP_TIMEOUT'
  | 'NAT_PMP_RESPONSE_INVALID'
  | 'NAT_PMP_RESPONSE_SOURCE_INVALID'
  | 'NAT_PMP_UNSUPPORTED_VERSION'
  | 'NAT_PMP_NOT_AUTHORIZED'
  | 'NAT_PMP_NETWORK_FAILURE'
  | 'NAT_PMP_OUT_OF_RESOURCES'
  | 'NAT_PMP_UNSUPPORTED_OPCODE'
  | 'NAT_PMP_UNKNOWN_RESULT_CODE'
  | 'NAT_PMP_SERVER_ERROR'
  | 'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL'
  | 'NAT_PMP_MAPPING_EXPIRED'
  | 'NAT_PMP_MAPPING_CLOSED'
  | 'NAT_PMP_EPOCH_STATE_LOSS'

const ERROR_MESSAGES: Record<NatPmpErrorCode, string> = {
  NAT_PMP_LISTENER_INVALID: 'O listener TCP fornecido para NAT-PMP é inválido ou ilegítimo.',
  NAT_PMP_LISTENER_CLOSED: 'O listener TCP associado ao NAT-PMP foi encerrado.',
  NAT_PMP_GATEWAY_NOT_FOUND: 'Nenhum default gateway válido foi encontrado para a interface local.',
  NAT_PMP_GATEWAY_INVALID: 'O endereço do gateway NAT-PMP é inválido.',
  NAT_PMP_REQUEST_INVALID: 'Os parâmetros da requisição NAT-PMP são inválidos.',
  NAT_PMP_TIMEOUT: 'Tempo limite esgotado aguardando o gateway NAT-PMP.',
  NAT_PMP_RESPONSE_INVALID: 'A resposta NAT-PMP é malformada, não correlacionada ou inválida.',
  NAT_PMP_RESPONSE_SOURCE_INVALID: 'A resposta não veio do gateway NAT-PMP esperado.',
  NAT_PMP_UNSUPPORTED_VERSION: 'O gateway não suporta NAT-PMP Version 0.',
  NAT_PMP_NOT_AUTHORIZED: 'O gateway recusou o mapeamento NAT-PMP por policy.',
  NAT_PMP_NETWORK_FAILURE: 'O gateway relatou falha de rede NAT-PMP.',
  NAT_PMP_OUT_OF_RESOURCES: 'O gateway não possui recursos para o mapeamento NAT-PMP.',
  NAT_PMP_UNSUPPORTED_OPCODE: 'O gateway não suporta o opcode NAT-PMP solicitado.',
  NAT_PMP_UNKNOWN_RESULT_CODE: 'O gateway retornou um result code NAT-PMP desconhecido.',
  NAT_PMP_SERVER_ERROR: 'O gateway NAT-PMP recusou a operação.',
  NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL: 'O endereço externo NAT-PMP não é globalmente roteável.',
  NAT_PMP_MAPPING_EXPIRED: 'A lease NAT-PMP expirou.',
  NAT_PMP_MAPPING_CLOSED: 'O mapeamento NAT-PMP foi encerrado.',
  NAT_PMP_EPOCH_STATE_LOSS: 'O epoch NAT-PMP indica possível perda de estado no gateway.'
}

export class NatPmpError extends Error {
  readonly code: NatPmpErrorCode
  readonly resultCode?: number

  constructor(code: NatPmpErrorCode, resultCode?: number) {
    super(ERROR_MESSAGES[code])
    this.name = 'NatPmpError'
    this.code = code
    this.resultCode = resultCode
  }
}

export type NatPmpGatewayProvider = PortMappingGatewayProvider

export function createDefaultNatPmpGatewayProvider(): NatPmpGatewayProvider {
  return createDefaultPortMappingGatewayProvider()
}

export interface NatPmpEpochState {
  readonly previousNatPmpEpoch: number
  readonly previousClientMonotonicSeconds: number
}

export type NatPmpEpochValidationResult = 'VALID' | 'STATE_LOSS_SUSPECTED'

/** RFC 6886 §3.6: progressão conservadora de 7/8, com tolerância de 2s. */
export function validateNatPmpEpochTransition(
  state: NatPmpEpochState | null,
  currentEpoch: number,
  clientMonotonicSeconds: number
): { result: NatPmpEpochValidationResult; nextState: NatPmpEpochState | null } {
  if (!Number.isInteger(currentEpoch) || currentEpoch < 0 || currentEpoch > 0xffffffff) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }
  if (!Number.isFinite(clientMonotonicSeconds)) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }
  if (!state) {
    return {
      result: 'VALID',
      nextState: {
        previousNatPmpEpoch: currentEpoch,
        previousClientMonotonicSeconds: clientMonotonicSeconds
      }
    }
  }
  const elapsed = clientMonotonicSeconds - state.previousClientMonotonicSeconds
  if (elapsed < 0) return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  const conservativeExpectedEpoch = state.previousNatPmpEpoch + Math.floor((7 * elapsed) / 8)
  if (currentEpoch < conservativeExpectedEpoch - 2) {
    return { result: 'STATE_LOSS_SUSPECTED', nextState: null }
  }
  return {
    result: 'VALID',
    nextState: {
      previousNatPmpEpoch: currentEpoch,
      previousClientMonotonicSeconds: clientMonotonicSeconds
    }
  }
}

function throwForResultCode(resultCode: number): never {
  switch (resultCode) {
    case NatPmpResultCode.UNSUPP_VERSION:
      throw new NatPmpError('NAT_PMP_UNSUPPORTED_VERSION', resultCode)
    case NatPmpResultCode.NOT_AUTHORIZED:
      throw new NatPmpError('NAT_PMP_NOT_AUTHORIZED', resultCode)
    case NatPmpResultCode.NETWORK_FAILURE:
      throw new NatPmpError('NAT_PMP_NETWORK_FAILURE', resultCode)
    case NatPmpResultCode.OUT_OF_RESOURCES:
      throw new NatPmpError('NAT_PMP_OUT_OF_RESOURCES', resultCode)
    case NatPmpResultCode.UNSUPP_OPCODE:
      throw new NatPmpError('NAT_PMP_UNSUPPORTED_OPCODE', resultCode)
    default:
      throw new NatPmpError('NAT_PMP_UNKNOWN_RESULT_CODE', resultCode)
  }
}

export function encodeNatPmpExternalAddressRequest(): Buffer {
  return Buffer.from([NAT_PMP_VERSION, NAT_PMP_PUBLIC_ADDRESS_OPCODE])
}

export interface NatPmpExternalAddressResponse {
  readonly resultCode: NatPmpResultCode.SUCCESS
  readonly epochTime: number
  readonly externalAddress: string
}

export function decodeNatPmpExternalAddressResponse(buf: Buffer): NatPmpExternalAddressResponse {
  if (!Buffer.isBuffer(buf) || buf.length !== NAT_PMP_EXTERNAL_ADDRESS_RESPONSE_BYTES) {
    throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
  }
  if (buf.readUInt8(0) !== NAT_PMP_VERSION || buf.readUInt8(1) !== 0x80) {
    throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
  }
  const resultCode = buf.readUInt16BE(2)
  if (resultCode !== NatPmpResultCode.SUCCESS) throwForResultCode(resultCode)
  return {
    resultCode: NatPmpResultCode.SUCCESS,
    epochTime: buf.readUInt32BE(4),
    externalAddress: `${buf[8]}.${buf[9]}.${buf[10]}.${buf[11]}`
  }
}

export interface NatPmpTcpMappingRequestOptions {
  readonly internalPort: number
  readonly suggestedExternalPort?: number
  readonly requestedLifetimeSeconds: number
}

export function encodeNatPmpTcpMappingRequest(options: NatPmpTcpMappingRequestOptions): Buffer {
  if (!Number.isInteger(options.internalPort) || options.internalPort < 1 || options.internalPort > 65535) {
    throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  }
  const suggestedPort = options.suggestedExternalPort ?? 0
  if (!Number.isInteger(suggestedPort) || suggestedPort < 0 || suggestedPort > 65535) {
    throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  }
  if (!Number.isInteger(options.requestedLifetimeSeconds) || options.requestedLifetimeSeconds < 0 || options.requestedLifetimeSeconds > 0xffffffff) {
    throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  }
  const buf = Buffer.alloc(NAT_PMP_TCP_MAPPING_REQUEST_BYTES)
  buf.writeUInt8(NAT_PMP_VERSION, 0)
  buf.writeUInt8(NAT_PMP_MAP_TCP_OPCODE, 1)
  buf.writeUInt16BE(0, 2)
  buf.writeUInt16BE(options.internalPort, 4)
  buf.writeUInt16BE(suggestedPort, 6)
  buf.writeUInt32BE(options.requestedLifetimeSeconds, 8)
  return buf
}

export interface NatPmpTcpMappingResponse {
  readonly resultCode: NatPmpResultCode.SUCCESS
  readonly epochTime: number
  readonly internalPort: number
  readonly assignedExternalPort: number
  readonly assignedLifetimeSeconds: number
}

export function decodeNatPmpTcpMappingResponse(buf: Buffer): NatPmpTcpMappingResponse {
  if (!Buffer.isBuffer(buf) || buf.length !== NAT_PMP_TCP_MAPPING_RESPONSE_BYTES) {
    throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
  }
  if (buf.readUInt8(0) !== NAT_PMP_VERSION || buf.readUInt8(1) !== 0x82) {
    throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
  }
  const resultCode = buf.readUInt16BE(2)
  if (resultCode !== NatPmpResultCode.SUCCESS) throwForResultCode(resultCode)
  return {
    resultCode: NatPmpResultCode.SUCCESS,
    epochTime: buf.readUInt32BE(4),
    internalPort: buf.readUInt16BE(8),
    assignedExternalPort: buf.readUInt16BE(10),
    assignedLifetimeSeconds: buf.readUInt32BE(12)
  }
}

interface ExchangeOptions {
  readonly localIp: string
  readonly gatewayIp: string
  readonly gatewayPort: number
  readonly request: Buffer
  readonly expectedOpcode: 0 | 2
  readonly expectedInternalPort?: number
  readonly initialTimeoutMs: number
  readonly maxAttempts: number
}

type ExchangeResponse = NatPmpExternalAddressResponse | NatPmpTcpMappingResponse

async function executeNatPmpExchange(options: ExchangeOptions): Promise<ExchangeResponse> {
  const socket: DgramSocket = createSocket('udp4')
  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => reject(error)
      socket.once('error', onError)
      socket.bind(0, options.localIp, () => {
        socket.off('error', onError)
        const bound = socket.address()
        if (bound.address === '0.0.0.0' || bound.address !== options.localIp) {
          reject(new NatPmpError('NAT_PMP_REQUEST_INVALID'))
          return
        }
        resolve()
      })
    })

    return await new Promise<ExchangeResponse>((resolve, reject) => {
      let done = false
      let attempts = 0
      let timer: NodeJS.Timeout | null = null
      const finish = (callback: () => void): void => {
        if (done) return
        done = true
        if (timer) clearTimeout(timer)
        socket.removeAllListeners()
        callback()
      }
      socket.on('error', (error) => finish(() => reject(error)))
      socket.on('message', (message: Buffer, rinfo: RemoteInfo) => {
        if (done) return
        if (rinfo.address !== options.gatewayIp || rinfo.port !== options.gatewayPort) return
        if (message.length >= 2 && message.readUInt8(1) !== (0x80 | options.expectedOpcode)) return
        try {
          const response = options.expectedOpcode === NAT_PMP_PUBLIC_ADDRESS_OPCODE
            ? decodeNatPmpExternalAddressResponse(message)
            : decodeNatPmpTcpMappingResponse(message)
          if (
            options.expectedOpcode === NAT_PMP_MAP_TCP_OPCODE &&
            'internalPort' in response &&
            response.internalPort !== options.expectedInternalPort
          ) return
          finish(() => resolve(response))
        } catch (error) {
          finish(() => reject(error))
        }
      })
      const send = (): void => {
        if (done) return
        attempts += 1
        socket.send(options.request, options.gatewayPort, options.gatewayIp, (error) => {
          if (error) {
            finish(() => reject(error))
            return
          }
          const waitMs = options.initialTimeoutMs * (2 ** (attempts - 1))
          timer = setTimeout(() => {
            if (attempts >= options.maxAttempts) finish(() => reject(new NatPmpError('NAT_PMP_TIMEOUT')))
            else send()
          }, waitMs)
        })
      }
      send()
    })
  } finally {
    try { socket.close() } catch { /* socket já encerrado */ }
  }
}

const gatewayQueues = new Map<string, Promise<void>>()

async function withGatewaySerialization<T>(key: string, task: () => Promise<T>): Promise<T> {
  const previous = gatewayQueues.get(key) ?? Promise.resolve()
  let release: () => void = () => undefined
  const gate = new Promise<void>((resolve) => { release = resolve })
  const queued = previous.then(() => gate)
  gatewayQueues.set(key, queued)
  await previous
  try {
    return await task()
  } finally {
    release()
    if (gatewayQueues.get(key) === queued) gatewayQueues.delete(key)
  }
}

export interface CreateNatPmpPortMappingOptions {
  readonly listener: LanTcpServerHandle
  readonly requestedLifetimeSeconds?: number
  readonly gatewayProvider?: NatPmpGatewayProvider
  readonly customGatewayAddress?: string
  readonly customGatewayPort?: number
  readonly initialTimeoutMs?: number
  readonly maxRetransmissions?: number
  readonly monotonicClock?: MonotonicClockProvider
  /** Uso interno da PortMappingStrategy; APIs low-level mantêm auto-renew por default. */
  readonly autoRenew?: boolean
}

interface NatPmpRuntimeOptions {
  readonly constructionToken: typeof NAT_PMP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN
  readonly listener: LanTcpServerHandle
  readonly gateway: string
  readonly gatewayPort: number
  readonly internalAddress: string
  readonly internalPort: number
  readonly externalAddress: string
  readonly externalPort: number
  readonly grantedLifetimeSeconds: number
  readonly epochState: NatPmpEpochState
  readonly monotonicClock: MonotonicClockProvider
  readonly initialTimeoutMs: number
  readonly maxAttempts: number
  readonly autoRenew: boolean
}

const NAT_PMP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN = Symbol('nat-pmp-active-mapping')

export class NatPmpActivePortMapping extends ActivePortMappingSource {
  private active = true
  private advertisable = true
  private renewalTimer: NodeJS.Timeout | null = null
  private deleteStarted = false
  private readonly listener: LanTcpServerHandle
  private readonly gateway: string
  private readonly gatewayPort: number
  private readonly internalAddress: string
  private readonly internalPort: number
  private readonly monotonicClock: MonotonicClockProvider
  private readonly initialTimeoutMs: number
  private readonly maxAttempts: number
  private readonly autoRenew: boolean
  private readonly unregisterListenerClose: () => void
  private externalAddress: string
  private externalPort: number
  private grantedLifetimeSeconds: number
  private epochState: NatPmpEpochState
  private monotonicDeadlineSeconds: number
  private expiresAtUnixSeconds: number

  constructor(options: NatPmpRuntimeOptions) {
    if (options.constructionToken !== NAT_PMP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN) {
      throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
    }
    super()
    this.listener = options.listener
    this.gateway = options.gateway
    this.gatewayPort = options.gatewayPort
    this.internalAddress = options.internalAddress
    this.internalPort = options.internalPort
    this.externalAddress = options.externalAddress
    this.externalPort = options.externalPort
    this.grantedLifetimeSeconds = options.grantedLifetimeSeconds
    this.epochState = options.epochState
    this.monotonicClock = options.monotonicClock
    this.initialTimeoutMs = options.initialTimeoutMs
    this.maxAttempts = options.maxAttempts
    this.autoRenew = options.autoRenew
    const nowMono = this.monotonicClock()
    this.monotonicDeadlineSeconds = nowMono + options.grantedLifetimeSeconds
    this.expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + options.grantedLifetimeSeconds
    this.unregisterListenerClose = registerLanTcpServerCloseListener(this.listener, () => {
      this.deactivate()
      void this.deleteBestEffort()
    })
    this.scheduleRenewal()
  }

  isActive(): boolean {
    if (!this.active || !this.advertisable) return false
    if (this.listener.isClosed()) {
      this.deactivate()
      return false
    }
    if (this.monotonicClock() >= this.monotonicDeadlineSeconds) {
      this.deactivate()
      return false
    }
    return true
  }

  getExternalEndpoint(): DirectTcpEndpoint {
    return { family: 4, address: this.externalAddress, port: this.externalPort }
  }

  getExpiresAt(): number {
    const remaining = Math.max(0, this.monotonicDeadlineSeconds - this.monotonicClock())
    return Math.min(this.expiresAtUnixSeconds, Math.floor(Date.now() / 1000 + remaining))
  }

  getGrantedLifetime(): number { return this.grantedLifetimeSeconds }
  getInternalEndpoint(): BoundTcpEndpoint { return this.listener.endpoint }
  getGateway(): string { return this.gateway }
  getEpochState(): NatPmpEpochState { return this.epochState }
  async executeRenewalForTesting(): Promise<void> { await this.executeRenewal() }
  async renewForManagedStrategy(): Promise<void> { await this.executeRenewal() }

  private exchange(request: Buffer, opcode: 0 | 2, attempts = this.maxAttempts): Promise<ExchangeResponse> {
    return executeNatPmpExchange({
      localIp: this.internalAddress,
      gatewayIp: this.gateway,
      gatewayPort: this.gatewayPort,
      request,
      expectedOpcode: opcode,
      expectedInternalPort: opcode === 2 ? this.internalPort : undefined,
      initialTimeoutMs: this.initialTimeoutMs,
      maxAttempts: attempts
    })
  }

  private validateEpoch(epochTime: number): boolean {
    const validation = validateNatPmpEpochTransition(this.epochState, epochTime, this.monotonicClock())
    if (validation.result !== 'VALID' || !validation.nextState) return false
    this.epochState = validation.nextState
    return true
  }

  private updateLease(response: NatPmpTcpMappingResponse, externalAddress: string): void {
    if (response.assignedExternalPort === 0 || response.assignedLifetimeSeconds === 0) {
      throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
    }
    this.externalAddress = externalAddress
    this.externalPort = response.assignedExternalPort
    this.grantedLifetimeSeconds = response.assignedLifetimeSeconds
    const nowMono = this.monotonicClock()
    this.monotonicDeadlineSeconds = nowMono + response.assignedLifetimeSeconds
    this.expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + response.assignedLifetimeSeconds
  }

  private scheduleRenewal(): void {
    if (this.renewalTimer) clearTimeout(this.renewalTimer)
    if (!this.active || !this.autoRenew) return
    const delay = Math.min(0x7fffffff, Math.max(1, Math.floor(this.grantedLifetimeSeconds * 500)))
    this.renewalTimer = setTimeout(() => { void this.executeRenewal() }, delay)
  }

  private async executeRenewal(): Promise<void> {
    if (!this.isActive()) return
    const key = `${this.gateway}:${this.gatewayPort}`
    try {
      await withGatewaySerialization(key, async () => {
        const response = await this.exchange(
          encodeNatPmpTcpMappingRequest({
            internalPort: this.internalPort,
            suggestedExternalPort: this.externalPort,
            requestedLifetimeSeconds: this.grantedLifetimeSeconds
          }),
          2
        ) as NatPmpTcpMappingResponse
        if (this.validateEpoch(response.epochTime)) {
          this.updateLease(response, this.externalAddress)
          this.advertisable = true
          this.scheduleRenewal()
          return
        }

        this.advertisable = false
        const addressResponse = await this.exchange(encodeNatPmpExternalAddressRequest(), 0) as NatPmpExternalAddressResponse
        const addressClass = classifyNetworkAddress(addressResponse.externalAddress)
        if (addressClass.scope !== 'GLOBAL' || !addressClass.isGloballyRoutableWan) {
          throw new NatPmpError('NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL')
        }
        const baseline = validateNatPmpEpochTransition(null, addressResponse.epochTime, this.monotonicClock())
        if (!baseline.nextState) throw new NatPmpError('NAT_PMP_EPOCH_STATE_LOSS')
        this.epochState = baseline.nextState
        const recovered = await this.exchange(
          encodeNatPmpTcpMappingRequest({
            internalPort: this.internalPort,
            suggestedExternalPort: this.externalPort,
            requestedLifetimeSeconds: this.grantedLifetimeSeconds
          }),
          2
        ) as NatPmpTcpMappingResponse
        if (!this.validateEpoch(recovered.epochTime)) throw new NatPmpError('NAT_PMP_EPOCH_STATE_LOSS')
        this.updateLease(recovered, addressClass.normalizedAddress)
        this.advertisable = true
        this.scheduleRenewal()
      })
    } catch {
      // Nunca estende a lease sem uma resposta SUCCESS válida.
    }
  }

  private deactivate(): void {
    this.active = false
    this.advertisable = false
    if (this.renewalTimer) clearTimeout(this.renewalTimer)
    this.renewalTimer = null
    this.unregisterListenerClose()
  }

  private async deleteBestEffort(): Promise<void> {
    if (this.deleteStarted) return
    this.deleteStarted = true
    const key = `${this.gateway}:${this.gatewayPort}`
    try {
      await withGatewaySerialization(key, async () => {
        const response = await this.exchange(
          encodeNatPmpTcpMappingRequest({
            internalPort: this.internalPort,
            suggestedExternalPort: 0,
            requestedLifetimeSeconds: 0
          }),
          2,
          NAT_PMP_DELETE_ATTEMPTS
        ) as NatPmpTcpMappingResponse
        if (response.assignedExternalPort !== 0 || response.assignedLifetimeSeconds !== 0) {
          throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
        }
      })
    } catch {
      // Delete é advisory e a capability local já está inativa.
    }
  }

  async close(): Promise<void> {
    this.deactivate()
    await this.deleteBestEffort()
  }
}

function validateCreationLifetime(value: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > NAT_PMP_MAX_MAPPING_LIFETIME_SECONDS) {
    throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  }
  return value
}

export async function createNatPmpPortMapping(options: CreateNatPmpPortMappingOptions): Promise<NatPmpActivePortMapping> {
  const { listener } = options
  if (listener && typeof listener === 'object' && typeof listener.isClosed === 'function' && listener.isClosed()) {
    throw new NatPmpError('NAT_PMP_LISTENER_CLOSED')
  }
  if (!isLegitimateActiveServerHandle(listener)) throw new NatPmpError('NAT_PMP_LISTENER_INVALID')
  const endpoint = listener.endpoint
  if (endpoint.family !== 4) throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  const localClass = classifyNetworkAddress(endpoint.address)
  const controlledLoopbackTest = Boolean(options.customGatewayAddress || options.gatewayProvider) && localClass.scope === 'LOOPBACK'
  if (localClass.scope !== 'LAN_PRIVATE' && !controlledLoopbackTest) {
    throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  }

  const gateway = options.customGatewayAddress ?? await (
    options.gatewayProvider ?? createDefaultNatPmpGatewayProvider()
  ).resolveGatewayForLocalAddress(endpoint.address)
  if (!gateway) throw new NatPmpError('NAT_PMP_GATEWAY_NOT_FOUND')
  if (isIP(gateway) !== 4) throw new NatPmpError('NAT_PMP_GATEWAY_INVALID')
  const gatewayClass = classifyNetworkAddress(gateway)
  if (
    gatewayClass.scope !== 'LAN_PRIVATE' && gatewayClass.scope !== 'LINK_LOCAL' &&
    !(controlledLoopbackTest && gatewayClass.scope === 'LOOPBACK')
  ) throw new NatPmpError('NAT_PMP_GATEWAY_INVALID')

  const requestedLifetime = validateCreationLifetime(options.requestedLifetimeSeconds ?? NAT_PMP_DEFAULT_MAPPING_LIFETIME_SECONDS)
  const gatewayPort = options.customGatewayPort ?? NAT_PMP_SERVER_PORT
  if (!Number.isInteger(gatewayPort) || gatewayPort < 1 || gatewayPort > 65535) {
    throw new NatPmpError('NAT_PMP_GATEWAY_INVALID')
  }
  const initialTimeoutMs = options.initialTimeoutMs ?? NAT_PMP_INITIAL_TIMEOUT_MS
  const maxAttempts = options.maxRetransmissions ?? NAT_PMP_MAX_ATTEMPTS
  if (!Number.isInteger(initialTimeoutMs) || initialTimeoutMs <= 0 || !Number.isInteger(maxAttempts) || maxAttempts <= 0 || maxAttempts > NAT_PMP_MAX_ATTEMPTS) {
    throw new NatPmpError('NAT_PMP_REQUEST_INVALID')
  }
  const monotonicClock = options.monotonicClock ?? defaultMonotonicSecondsProvider
  const key = `${gatewayClass.normalizedAddress}:${gatewayPort}`

  return withGatewaySerialization(key, async () => {
    const common = {
      localIp: localClass.normalizedAddress,
      gatewayIp: gatewayClass.normalizedAddress,
      gatewayPort,
      initialTimeoutMs,
      maxAttempts
    }
    const addressResponse = await executeNatPmpExchange({
      ...common,
      request: encodeNatPmpExternalAddressRequest(),
      expectedOpcode: 0
    }) as NatPmpExternalAddressResponse
    const addressClass = classifyNetworkAddress(addressResponse.externalAddress)
    if (addressClass.scope !== 'GLOBAL' || !addressClass.isGloballyRoutableWan) {
      throw new NatPmpError('NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL')
    }
    let epochValidation = validateNatPmpEpochTransition(null, addressResponse.epochTime, monotonicClock())
    if (!epochValidation.nextState) throw new NatPmpError('NAT_PMP_EPOCH_STATE_LOSS')
    const mapResponse = await executeNatPmpExchange({
      ...common,
      request: encodeNatPmpTcpMappingRequest({
        internalPort: endpoint.port,
        suggestedExternalPort: 0,
        requestedLifetimeSeconds: requestedLifetime
      }),
      expectedOpcode: 2,
      expectedInternalPort: endpoint.port
    }) as NatPmpTcpMappingResponse
    epochValidation = validateNatPmpEpochTransition(epochValidation.nextState, mapResponse.epochTime, monotonicClock())
    if (!epochValidation.nextState || epochValidation.result !== 'VALID') {
      throw new NatPmpError('NAT_PMP_EPOCH_STATE_LOSS')
    }
    if (mapResponse.assignedExternalPort === 0 || mapResponse.assignedLifetimeSeconds === 0) {
      throw new NatPmpError('NAT_PMP_RESPONSE_INVALID')
    }
    return new NatPmpActivePortMapping({
      constructionToken: NAT_PMP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN,
      listener,
      gateway: gatewayClass.normalizedAddress,
      gatewayPort,
      internalAddress: localClass.normalizedAddress,
      internalPort: endpoint.port,
      externalAddress: addressClass.normalizedAddress,
      externalPort: mapResponse.assignedExternalPort,
      grantedLifetimeSeconds: mapResponse.assignedLifetimeSeconds,
      epochState: epochValidation.nextState,
      monotonicClock,
      initialTimeoutMs,
      maxAttempts,
      autoRenew: options.autoRenew !== false
    })
  })
}
