import {
  ActivePortMappingSource,
  isLegitimateActivePortMapping
} from './active-port-mapping'
import {
  ActivePortMapping,
  createPcpPortMapping,
  defaultMonotonicSecondsProvider,
  PcpError,
  PcpResultCode,
  type MonotonicClockProvider
} from './pcp-client'
import {
  createNatPmpPortMapping,
  NatPmpActivePortMapping,
  NatPmpError
} from './nat-pmp-client'
import {
  createUpnpPortMapping,
  UpnpActivePortMapping
} from './upnp-client'
import { UpnpError } from './upnp-protocol'
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
  defaultConnectivityResourceGovernor,
  type ConnectivityResourceGovernor
} from './connectivity-resource-governor'
import type { ConnectivitySubsystem } from './connectivity-subsystem'

export type PortMappingBackend = 'PCP' | 'NAT_PMP' | 'UPNP'

export type PortMappingFailureDisposition =
  | 'PROTOCOL_UNSUPPORTED'
  | 'NO_RESPONSE'
  | 'EXPLICIT_DENIAL'
  | 'RESOURCE_FAILURE'
  | 'TOPOLOGY_INVALID'
  | 'LOCAL_CONFIGURATION_FAILURE'
  | 'ABORTED'
  | 'INTERNAL_FAILURE'

export type PortMappingStrategyErrorCode =
  | 'PORT_MAPPING_LISTENER_INVALID'
  | 'PORT_MAPPING_LISTENER_CLOSED'
  | 'PORT_MAPPING_OPERATION_IN_PROGRESS'
  | 'PORT_MAPPING_ALREADY_ACTIVE'
  | 'NO_PORT_MAPPING_AVAILABLE'
  | 'PORT_MAPPING_DENIED'
  | 'PORT_MAPPING_ABORTED'
  | 'PORT_MAPPING_LOCAL_UNSUPPORTED'
  | 'PORT_MAPPING_TOPOLOGY_INVALID'
  | 'PORT_MAPPING_INTERNAL_FAILURE'
  | 'PORT_MAPPING_NOT_ACTIVE'

const ERROR_MESSAGES: Record<PortMappingStrategyErrorCode, string> = {
  PORT_MAPPING_LISTENER_INVALID: 'O listener fornecido para port mapping é inválido ou ilegítimo.',
  PORT_MAPPING_LISTENER_CLOSED: 'O listener associado ao port mapping foi encerrado.',
  PORT_MAPPING_OPERATION_IN_PROGRESS: 'Já existe uma negociação de port mapping em andamento para este listener.',
  PORT_MAPPING_ALREADY_ACTIVE: 'Este listener já possui uma ManagedPortMapping ativa.',
  NO_PORT_MAPPING_AVAILABLE: 'Nenhum port mapping seguro está disponível.',
  PORT_MAPPING_DENIED: 'O gateway negou semanticamente o port mapping.',
  PORT_MAPPING_ABORTED: 'A negociação de port mapping foi cancelada.',
  PORT_MAPPING_LOCAL_UNSUPPORTED: 'A configuração local não permite executar port mapping.',
  PORT_MAPPING_TOPOLOGY_INVALID: 'A topologia retornada pelo gateway não é globalmente roteável.',
  PORT_MAPPING_INTERNAL_FAILURE: 'A negociação de port mapping falhou de modo não classificável.',
  PORT_MAPPING_NOT_ACTIVE: 'A ManagedPortMapping não está ativa.'
}

export class PortMappingStrategyError extends Error {
  readonly code: PortMappingStrategyErrorCode
  readonly attemptedBackends: readonly PortMappingBackend[]
  readonly disposition?: PortMappingFailureDisposition

  constructor(
    code: PortMappingStrategyErrorCode,
    attemptedBackends: readonly PortMappingBackend[] = [],
    disposition?: PortMappingFailureDisposition
  ) {
    super(ERROR_MESSAGES[code])
    this.name = 'PortMappingStrategyError'
    this.code = code
    this.attemptedBackends = Object.freeze([...attemptedBackends])
    this.disposition = disposition
  }
}

export function classifyPortMappingFailure(
  backend: PortMappingBackend,
  error: unknown
): PortMappingFailureDisposition {
  if (error instanceof PortMappingStrategyError && error.code === 'PORT_MAPPING_ABORTED') return 'ABORTED'

  if (backend === 'PCP' && error instanceof PcpError) {
    if (error.code === 'PCP_UNSUPPORTED_VERSION') return 'PROTOCOL_UNSUPPORTED'
    if (error.code === 'PCP_TIMEOUT') return 'NO_RESPONSE'
    if (error.code === 'PCP_EXTERNAL_ADDRESS_NOT_GLOBAL') return 'TOPOLOGY_INVALID'
    if (error.code === 'PCP_LISTENER_CLOSED') return 'ABORTED'
    if (error.code === 'PCP_SERVER_ERROR') {
      if (
        error.resultCode === PcpResultCode.NO_RESOURCES ||
        error.resultCode === PcpResultCode.USER_EX_QUOTA ||
        error.resultCode === PcpResultCode.NETWORK_FAILURE
      ) return 'RESOURCE_FAILURE'
      return 'EXPLICIT_DENIAL'
    }
    if (
      error.code === 'PCP_LISTENER_INVALID' ||
      error.code === 'PCP_GATEWAY_NOT_FOUND' ||
      error.code === 'PCP_GATEWAY_INVALID' ||
      error.code === 'PCP_GATEWAY_DISCOVERY_UNSUPPORTED' ||
      error.code === 'PCP_REQUEST_INVALID'
    ) return 'LOCAL_CONFIGURATION_FAILURE'
    return 'INTERNAL_FAILURE'
  }

  if (backend === 'NAT_PMP' && error instanceof NatPmpError) {
    if (error.code === 'NAT_PMP_TIMEOUT') return 'NO_RESPONSE'
    if (error.code === 'NAT_PMP_UNSUPPORTED_VERSION') return 'PROTOCOL_UNSUPPORTED'
    if (error.code === 'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL') return 'TOPOLOGY_INVALID'
    if (error.code === 'NAT_PMP_LISTENER_CLOSED') return 'ABORTED'
    if (error.code === 'NAT_PMP_NOT_AUTHORIZED') return 'EXPLICIT_DENIAL'
    if (error.code === 'NAT_PMP_NETWORK_FAILURE' || error.code === 'NAT_PMP_OUT_OF_RESOURCES') {
      return 'RESOURCE_FAILURE'
    }
    if (
      error.code === 'NAT_PMP_LISTENER_INVALID' ||
      error.code === 'NAT_PMP_GATEWAY_NOT_FOUND' ||
      error.code === 'NAT_PMP_GATEWAY_INVALID' ||
      error.code === 'NAT_PMP_REQUEST_INVALID'
    ) return 'LOCAL_CONFIGURATION_FAILURE'
    return 'INTERNAL_FAILURE'
  }

  if (backend === 'UPNP' && error instanceof UpnpError) {
    if (error.code === 'UPNP_SSDP_TIMEOUT' || error.code === 'UPNP_HTTP_TIMEOUT') return 'NO_RESPONSE'
    if (error.code === 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL') return 'TOPOLOGY_INVALID'
    if (error.code === 'UPNP_LISTENER_CLOSED') return 'ABORTED'
    if (
      error.code === 'UPNP_MAPPING_CONFLICT' ||
      error.code === 'UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED'
    ) return 'RESOURCE_FAILURE'
    if (error.code === 'UPNP_SOAP_FAULT') return 'EXPLICIT_DENIAL'
    if (
      error.code === 'UPNP_LISTENER_INVALID' ||
      error.code === 'UPNP_GATEWAY_NOT_FOUND' ||
      error.code === 'UPNP_GATEWAY_INVALID' ||
      error.code === 'UPNP_REQUEST_INVALID'
    ) return 'LOCAL_CONFIGURATION_FAILURE'
    return 'INTERNAL_FAILURE'
  }

  return 'INTERNAL_FAILURE'
}

export function decideNextPortMappingBackend(
  attemptedBackend: PortMappingBackend,
  disposition: PortMappingFailureDisposition
): PortMappingBackend | null {
  if (attemptedBackend === 'PCP') {
    if (disposition === 'PROTOCOL_UNSUPPORTED') return 'NAT_PMP'
    if (disposition === 'NO_RESPONSE') return 'UPNP'
  }
  if (attemptedBackend === 'NAT_PMP' && disposition === 'NO_RESPONSE') return 'UPNP'
  return null
}

interface BackendCreationContext {
  readonly listener: LanTcpServerHandle
  readonly gatewayAddress: string
  readonly requestedLifetimeSeconds: number
  readonly signal: AbortSignal
}

export interface PortMappingBackendAdapter {
  create(context: BackendCreationContext): Promise<ActivePortMappingSource>
  renew(mapping: ActivePortMappingSource): Promise<void>
}

interface StrategyScheduler {
  set(callback: () => void, delayMs: number): unknown
  clear(handle: unknown): void
}

export interface PortMappingStrategyTestHooks {
  readonly gatewayProvider?: PortMappingGatewayProvider
  readonly adapters?: Readonly<Record<PortMappingBackend, PortMappingBackendAdapter>>
  readonly scheduler?: StrategyScheduler
  readonly pcpNatPmpGatewayPort?: number
  readonly upnpSsdpDestinationAddress?: string
  readonly upnpSsdpDestinationPort?: number
  readonly allowLoopback?: boolean
}

export interface CreatePreferredPortMappingOptions {
  readonly listener: LanTcpServerHandle
  readonly requestedLifetimeSeconds?: number
  readonly timeoutMs?: number
  readonly maxRetransmissions?: number
  readonly signal?: AbortSignal
  /** Seams determinísticos e não conectados a UI/rede; production deixa ausente. */
  readonly testOnly?: PortMappingStrategyTestHooks
  readonly monotonicClock?: MonotonicClockProvider
  readonly resourceGovernor?: ConnectivityResourceGovernor
  readonly subsystem?: ConnectivitySubsystem
}

const DEFAULT_MANAGED_LIFETIME_SECONDS = 3600
const MIN_MANAGED_LIFETIME_SECONDS = 60
const MAX_MANAGED_LIFETIME_SECONDS = 7200

function createProductionAdapters(
  options: CreatePreferredPortMappingOptions
): Readonly<Record<PortMappingBackend, PortMappingBackendAdapter>> {
  const gatewayPort = options.testOnly?.pcpNatPmpGatewayPort
  const common = {
    requestedLifetimeSeconds: options.requestedLifetimeSeconds,
    monotonicClock: options.monotonicClock,
    autoRenew: false
  }
  return {
    PCP: {
      async create(context) {
        return createPcpPortMapping({
          listener: context.listener,
          customGatewayAddress: context.gatewayAddress,
          customGatewayPort: gatewayPort,
          timeoutMs: options.timeoutMs,
          maxRetransmissions: options.maxRetransmissions,
          ...common
        })
      },
      async renew(mapping) {
        if (!(mapping instanceof ActivePortMapping)) throw new PortMappingStrategyError('PORT_MAPPING_INTERNAL_FAILURE')
        await mapping.renewForManagedStrategy()
      }
    },
    NAT_PMP: {
      async create(context) {
        return createNatPmpPortMapping({
          listener: context.listener,
          customGatewayAddress: context.gatewayAddress,
          customGatewayPort: gatewayPort,
          initialTimeoutMs: options.timeoutMs,
          maxRetransmissions: options.maxRetransmissions,
          ...common
        })
      },
      async renew(mapping) {
        if (!(mapping instanceof NatPmpActivePortMapping)) throw new PortMappingStrategyError('PORT_MAPPING_INTERNAL_FAILURE')
        await mapping.renewForManagedStrategy()
      }
    },
    UPNP: {
      async create(context) {
        return createUpnpPortMapping({
          listener: context.listener,
          requestedLifetimeSeconds: context.requestedLifetimeSeconds,
          gatewayProvider: { resolveGatewayForLocalAddress: async () => context.gatewayAddress },
          monotonicClock: options.monotonicClock,
          httpTimeoutMs: options.timeoutMs,
          autoRenew: false,
          testOnlySsdpDestinationAddress: options.testOnly?.upnpSsdpDestinationAddress,
          testOnlySsdpDestinationPort: options.testOnly?.upnpSsdpDestinationPort,
          testOnlySsdpTimeoutMs: options.timeoutMs,
          testOnlyAllowLoopback: options.testOnly?.allowLoopback
        })
      },
      async renew(mapping) {
        if (!(mapping instanceof UpnpActivePortMapping)) throw new PortMappingStrategyError('PORT_MAPPING_INTERNAL_FAILURE')
        await mapping.renewForManagedStrategy()
      }
    }
  }
}

function strategyErrorForDisposition(
  disposition: PortMappingFailureDisposition,
  attemptedBackends: readonly PortMappingBackend[]
): PortMappingStrategyError {
  switch (disposition) {
    case 'ABORTED':
      return new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, disposition)
    case 'EXPLICIT_DENIAL':
    case 'RESOURCE_FAILURE':
      return new PortMappingStrategyError('PORT_MAPPING_DENIED', attemptedBackends, disposition)
    case 'TOPOLOGY_INVALID':
      return new PortMappingStrategyError('PORT_MAPPING_TOPOLOGY_INVALID', attemptedBackends, disposition)
    case 'LOCAL_CONFIGURATION_FAILURE':
      return new PortMappingStrategyError('PORT_MAPPING_LOCAL_UNSUPPORTED', attemptedBackends, disposition)
    case 'PROTOCOL_UNSUPPORTED':
    case 'NO_RESPONSE':
      return new PortMappingStrategyError('NO_PORT_MAPPING_AVAILABLE', attemptedBackends, disposition)
    case 'INTERNAL_FAILURE':
      return new PortMappingStrategyError('PORT_MAPPING_INTERNAL_FAILURE', attemptedBackends, disposition)
  }
}

async function createWithCancellation(
  adapter: PortMappingBackendAdapter,
  context: BackendCreationContext,
  attemptedBackends: readonly PortMappingBackend[]
): Promise<ActivePortMappingSource> {
  if (context.signal.aborted || context.listener.isClosed()) {
    throw new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
  }
  const creation = adapter.create(context)
  let rejectAbort: ((error: PortMappingStrategyError) => void) | undefined
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = reject
  })
  const onAbort = (): void => rejectAbort?.(
    new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
  )
  context.signal.addEventListener('abort', onAbort, { once: true })
  try {
    const mapping = await Promise.race([creation, aborted])
    if (context.signal.aborted || context.listener.isClosed()) {
      try { await mapping.close() } catch { /* bounded advisory cleanup */ }
      throw new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
    }
    let mappingIsActive = false
    try { mappingIsActive = isLegitimateActivePortMapping(mapping) && mapping.isActive() } catch { /* fail closed */ }
    if (!mappingIsActive) {
      try { await mapping.close() } catch { /* advisory */ }
      throw new PortMappingStrategyError('PORT_MAPPING_INTERNAL_FAILURE', attemptedBackends, 'INTERNAL_FAILURE')
    }
    return mapping
  } catch (error) {
    if (error instanceof PortMappingStrategyError && error.code === 'PORT_MAPPING_ABORTED') {
      try {
        const lateMapping = await creation
        try { await lateMapping.close() } catch { /* advisory */ }
      } catch { /* backend did not create a mapping */ }
    }
    throw error
  } finally {
    context.signal.removeEventListener('abort', onAbort)
  }
}

export type ManagedPortMappingState = 'ACTIVE' | 'MIGRATING' | 'CLOSING' | 'CLOSED' | 'FAILED'

interface CurrentManagedBackend {
  readonly backend: PortMappingBackend
  readonly mapping: ActivePortMappingSource
}

const MANAGED_MAPPING_CONSTRUCTION_TOKEN = Symbol('managed-port-mapping')
const listenerRegistry = new WeakMap<LanTcpServerHandle, 'CREATING' | ManagedPortMapping>()

export class ManagedPortMapping extends ActivePortMappingSource {
  private state: ManagedPortMappingState = 'ACTIVE'
  private current: CurrentManagedBackend
  private renewalTimer: unknown | null = null
  private operation: Promise<void> | null = null
  private closePromise: Promise<void> | null = null
  private monotonicDeadlineSeconds = 0
  private readonly lifecycleAbort = new AbortController()
  private readonly unregisterListenerClose: () => void
  private readonly unregisterSubsystemResource: () => void

  constructor(options: {
    readonly constructionToken: typeof MANAGED_MAPPING_CONSTRUCTION_TOKEN
    readonly listener: LanTcpServerHandle
    readonly current: CurrentManagedBackend
    readonly adapters: Readonly<Record<PortMappingBackend, PortMappingBackendAdapter>>
    readonly gatewayAddress: string
    readonly requestedLifetimeSeconds: number
    readonly scheduler: StrategyScheduler
    readonly monotonicClock: MonotonicClockProvider
    readonly subsystem?: ConnectivitySubsystem
  }) {
    if (options.constructionToken !== MANAGED_MAPPING_CONSTRUCTION_TOKEN) {
      throw new PortMappingStrategyError('PORT_MAPPING_INTERNAL_FAILURE')
    }
    super()
    this.listener = options.listener
    this.current = options.current
    this.adapters = options.adapters
    this.gatewayAddress = options.gatewayAddress
    this.requestedLifetimeSeconds = options.requestedLifetimeSeconds
    this.scheduler = options.scheduler
    this.monotonicClock = options.monotonicClock
    this.refreshMonotonicDeadline()
    this.unregisterListenerClose = registerLanTcpServerCloseListener(this.listener, () => {
      void this.close()
    })
    this.unregisterSubsystemResource = options.subsystem?.registerResource({
      close: () => this.close(),
      forceClose: () => { void this.close() }
    }) ?? (() => {})
    this.scheduleRenewal()
  }

  private readonly listener: LanTcpServerHandle
  private readonly adapters: Readonly<Record<PortMappingBackend, PortMappingBackendAdapter>>
  private readonly gatewayAddress: string
  private readonly requestedLifetimeSeconds: number
  private readonly scheduler: StrategyScheduler
  private readonly monotonicClock: MonotonicClockProvider

  isActive(): boolean {
    const stateAllowsCurrent = this.state === 'ACTIVE' || this.state === 'MIGRATING'
    if (
      !stateAllowsCurrent ||
      this.listener.isClosed() ||
      this.monotonicClock() >= this.monotonicDeadlineSeconds ||
      !isLegitimateActivePortMapping(this.current.mapping) ||
      !this.current.mapping.isActive()
    ) {
      if (stateAllowsCurrent) this.failSynchronously()
      return false
    }
    return true
  }

  getExternalEndpoint(): DirectTcpEndpoint {
    if (!this.isActive()) throw new PortMappingStrategyError('PORT_MAPPING_NOT_ACTIVE')
    return this.current.mapping.getExternalEndpoint()
  }

  getExpiresAt(): number {
    if (!this.isActive()) return 0
    const remaining = Math.max(0, this.monotonicDeadlineSeconds - this.monotonicClock())
    return Math.min(
      this.current.mapping.getExpiresAt(),
      Math.floor(Date.now() / 1000 + remaining)
    )
  }

  getGrantedLifetime(): number {
    if (!this.isActive()) return 0
    return this.current.mapping.getGrantedLifetime()
  }

  getInternalEndpoint(): BoundTcpEndpoint {
    return this.listener.endpoint
  }

  getBackendForTesting(): PortMappingBackend {
    return this.current.backend
  }

  getStateForTesting(): ManagedPortMappingState {
    return this.state
  }

  async executeRenewalForTesting(): Promise<void> {
    await this.startRenewal()
  }

  private failSynchronously(): void {
    this.state = 'FAILED'
    this.clearRenewalTimer()
    this.unregisterListenerClose()
    this.unregisterSubsystemResource()
    if (listenerRegistry.get(this.listener) === this) listenerRegistry.delete(this.listener)
  }

  private clearRenewalTimer(): void {
    if (this.renewalTimer !== null) this.scheduler.clear(this.renewalTimer)
    this.renewalTimer = null
  }

  private scheduleRenewal(): void {
    this.clearRenewalTimer()
    if (this.state !== 'ACTIVE' || !this.current.mapping.isActive()) return
    const remainingSeconds = Math.max(0, this.monotonicDeadlineSeconds - this.monotonicClock())
    if (remainingSeconds <= 0) {
      this.failSynchronously()
      return
    }
    const halfLease = Math.max(1, Math.floor(this.current.mapping.getGrantedLifetime() / 2))
    const halfRemaining = Math.max(1, Math.floor(remainingSeconds / 2))
    const delaySeconds = Math.min(halfLease, halfRemaining)
    const scheduledAt = this.monotonicClock()
    const delayMs = Math.min(0x7fffffff, delaySeconds * 1000)
    this.renewalTimer = this.scheduler.set(() => {
      if (this.monotonicClock() < scheduledAt) {
        this.failSynchronously()
        return
      }
      void this.startRenewal()
    }, delayMs)
  }

  private refreshMonotonicDeadline(): void {
    const backendRemaining = Math.max(
      0,
      this.current.mapping.getExpiresAt() - Math.floor(Date.now() / 1000)
    )
    const effectiveRemaining = Math.min(
      this.current.mapping.getGrantedLifetime(),
      backendRemaining
    )
    this.monotonicDeadlineSeconds = this.monotonicClock() + effectiveRemaining
  }

  private startRenewal(): Promise<void> {
    if (this.operation) return this.operation
    if (!this.isActive()) return Promise.resolve()
    const task = this.executeManagedRenewal()
    this.operation = task
    void task.finally(() => {
      if (this.operation === task) this.operation = null
    })
    return task
  }

  private creationContext(): BackendCreationContext {
    return {
      listener: this.listener,
      gatewayAddress: this.gatewayAddress,
      requestedLifetimeSeconds: this.requestedLifetimeSeconds,
      signal: this.lifecycleAbort.signal
    }
  }

  private async createUpgrade(backend: PortMappingBackend): Promise<ActivePortMappingSource> {
    return createWithCancellation(this.adapters[backend], this.creationContext(), [backend])
  }

  private async executeManagedRenewal(): Promise<void> {
    if (!this.isActive()) return
    this.state = 'MIGRATING'
    const original = this.current
    try {
      if (original.backend === 'PCP') {
        await this.renewCurrent(original)
        return
      }

      let pcpMapping: ActivePortMappingSource
      try {
        pcpMapping = await this.createUpgrade('PCP')
      } catch (error) {
        const disposition = classifyPortMappingFailure('PCP', error)
        if (disposition === 'NO_RESPONSE') {
          await this.renewCurrent(original)
          return
        }
        if (disposition !== 'PROTOCOL_UNSUPPORTED') {
          await this.failAndCloseCurrent()
          return
        }
        if (original.backend === 'NAT_PMP') {
          await this.renewCurrent(original)
          return
        }

        try {
          const natPmpMapping = await this.createUpgrade('NAT_PMP')
          await this.switchCurrent('NAT_PMP', natPmpMapping, original)
          return
        } catch (natError) {
          const natDisposition = classifyPortMappingFailure('NAT_PMP', natError)
          if (natDisposition === 'NO_RESPONSE') {
            await this.renewCurrent(original)
            return
          }
          await this.failAndCloseCurrent()
          return
        }
      }

      await this.switchCurrent('PCP', pcpMapping, original)
    } catch {
      if (this.state === 'MIGRATING') await this.failAndCloseCurrent()
    }
  }

  private async renewCurrent(expected: CurrentManagedBackend): Promise<void> {
    if (this.isClosingOrClosed()) return
    try {
      await this.adapters[expected.backend].renew(expected.mapping)
    } catch (error) {
      const disposition = classifyPortMappingFailure(expected.backend, error)
      if (disposition !== 'NO_RESPONSE') {
        await this.failAndCloseCurrent()
        return
      }
    }
    if (this.isClosingOrClosed()) return
    if (this.current !== expected || !expected.mapping.isActive()) {
      await this.failAndCloseCurrent()
      return
    }
    this.refreshMonotonicDeadline()
    this.state = 'ACTIVE'
    this.scheduleRenewal()
  }

  private isClosingOrClosed(): boolean {
    return this.state === 'CLOSING' || this.state === 'CLOSED'
  }

  private async switchCurrent(
    backend: PortMappingBackend,
    mapping: ActivePortMappingSource,
    expectedOld: CurrentManagedBackend
  ): Promise<void> {
    if (
      this.lifecycleAbort.signal.aborted ||
      this.state === 'CLOSING' ||
      this.state === 'CLOSED' ||
      this.current !== expectedOld
    ) {
      try { await mapping.close() } catch { /* advisory */ }
      return
    }
    if (!isLegitimateActivePortMapping(mapping) || !mapping.isActive()) {
      try { await mapping.close() } catch { /* advisory */ }
      await this.failAndCloseCurrent()
      return
    }
    this.current = Object.freeze({ backend, mapping })
    this.refreshMonotonicDeadline()
    this.state = 'ACTIVE'
    this.scheduleRenewal()
    try { await expectedOld.mapping.close() } catch { /* old cleanup is advisory */ }
  }

  private async failAndCloseCurrent(): Promise<void> {
    if (this.state === 'CLOSING' || this.state === 'CLOSED') return
    this.state = 'FAILED'
    this.clearRenewalTimer()
    this.unregisterListenerClose()
    this.unregisterSubsystemResource()
    try { await this.current.mapping.close() } catch { /* advisory */ }
    if (listenerRegistry.get(this.listener) === this) listenerRegistry.delete(this.listener)
  }

  async close(): Promise<void> {
    if (this.closePromise) return this.closePromise
    const task = this.performClose()
    this.closePromise = task
    return task
  }

  private async performClose(): Promise<void> {
    if (this.state === 'CLOSED') return
    this.state = 'CLOSING'
    this.clearRenewalTimer()
    this.lifecycleAbort.abort()
    this.unregisterListenerClose()
    this.unregisterSubsystemResource()
    const pending = this.operation
    if (pending) await pending
    try { await this.current.mapping.close() } catch { /* advisory */ }
    this.state = 'CLOSED'
    if (listenerRegistry.get(this.listener) === this) listenerRegistry.delete(this.listener)
  }
}

function validateManagedLifetime(value: number): number {
  if (
    !Number.isInteger(value) ||
    value < MIN_MANAGED_LIFETIME_SECONDS ||
    value > MAX_MANAGED_LIFETIME_SECONDS
  ) throw new PortMappingStrategyError('PORT_MAPPING_LOCAL_UNSUPPORTED')
  return value
}

const defaultScheduler: StrategyScheduler = {
  set: (callback, delayMs) => setTimeout(callback, delayMs),
  clear: (handle) => clearTimeout(handle as NodeJS.Timeout)
}

export async function createPreferredPortMapping(
  options: CreatePreferredPortMappingOptions
): Promise<ManagedPortMapping> {
  const { listener } = options
  if (listener && typeof listener === 'object' && typeof listener.isClosed === 'function' && listener.isClosed()) {
    throw new PortMappingStrategyError('PORT_MAPPING_LISTENER_CLOSED')
  }
  if (!isLegitimateActiveServerHandle(listener)) {
    throw new PortMappingStrategyError('PORT_MAPPING_LISTENER_INVALID')
  }
  const existing = listenerRegistry.get(listener)
  if (existing === 'CREATING') throw new PortMappingStrategyError('PORT_MAPPING_OPERATION_IN_PROGRESS')
  if (existing instanceof ManagedPortMapping) {
    if (existing.isActive()) throw new PortMappingStrategyError('PORT_MAPPING_ALREADY_ACTIVE')
    if (listenerRegistry.get(listener) === existing) {
      throw new PortMappingStrategyError('PORT_MAPPING_OPERATION_IN_PROGRESS')
    }
  }
  const work = options.subsystem?.beginWork(options.signal)
  const signal = work?.signal ?? options.signal
  let udpReservation
  try {
    udpReservation = (options.resourceGovernor ?? options.subsystem?.governor ?? defaultConnectivityResourceGovernor).reserve('UDP_OPERATION')
  } catch (cause) {
    work?.finish()
    throw cause
  }
  listenerRegistry.set(listener, 'CREATING')

  const lifecycleAbort = new AbortController()
  const abortFromCaller = (): void => lifecycleAbort.abort()
  signal?.addEventListener('abort', abortFromCaller, { once: true })
  const unregisterCreationClose = registerLanTcpServerCloseListener(listener, () => lifecycleAbort.abort())
  const attemptedBackends: PortMappingBackend[] = []
  let selected: CurrentManagedBackend | null = null
  try {
    if (signal?.aborted || listener.isClosed()) {
      throw new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
    }
    const requestedLifetimeSeconds = validateManagedLifetime(
      options.requestedLifetimeSeconds ?? DEFAULT_MANAGED_LIFETIME_SECONDS
    )
    const gatewayProvider = options.testOnly?.gatewayProvider ?? createDefaultPortMappingGatewayProvider()
    let gatewayAddress: string | null
    try {
      gatewayAddress = await gatewayProvider.resolveGatewayForLocalAddress(listener.endpoint.address)
    } catch {
      gatewayAddress = null
    }
    if (!gatewayAddress) throw new PortMappingStrategyError('PORT_MAPPING_LOCAL_UNSUPPORTED')
    if (lifecycleAbort.signal.aborted || listener.isClosed()) {
      throw new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
    }

    const adapters = options.testOnly?.adapters ?? createProductionAdapters(options)
    let backend: PortMappingBackend = 'PCP'
    while (true) {
      attemptedBackends.push(backend)
      try {
        const mapping = await createWithCancellation(adapters[backend], {
          listener,
          gatewayAddress,
          requestedLifetimeSeconds,
          signal: lifecycleAbort.signal
        }, attemptedBackends)
        selected = Object.freeze({ backend, mapping })
        break
      } catch (error) {
        if (lifecycleAbort.signal.aborted || listener.isClosed()) {
          throw new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
        }
        const disposition = classifyPortMappingFailure(backend, error)
        const next = decideNextPortMappingBackend(backend, disposition)
        if (!next) throw strategyErrorForDisposition(disposition, attemptedBackends)
        backend = next
      }
    }

    if (lifecycleAbort.signal.aborted || listener.isClosed()) {
      try { await selected.mapping.close() } catch { /* advisory */ }
      throw new PortMappingStrategyError('PORT_MAPPING_ABORTED', attemptedBackends, 'ABORTED')
    }
    const managed = new ManagedPortMapping({
      constructionToken: MANAGED_MAPPING_CONSTRUCTION_TOKEN,
      listener,
      current: selected,
      adapters,
      gatewayAddress,
      requestedLifetimeSeconds,
      scheduler: options.testOnly?.scheduler ?? defaultScheduler,
      monotonicClock: options.monotonicClock ?? defaultMonotonicSecondsProvider,
      subsystem: options.subsystem
    })
    listenerRegistry.set(listener, managed)
    return managed
  } catch (error) {
    if (selected) {
      try { await selected.mapping.close() } catch { /* advisory */ }
    }
    listenerRegistry.delete(listener)
    throw error
  } finally {
    unregisterCreationClose()
    signal?.removeEventListener('abort', abortFromCaller)
    udpReservation.release()
    work?.finish()
  }
}
