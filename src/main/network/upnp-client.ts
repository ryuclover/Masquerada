import { randomInt } from 'node:crypto'
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
import { defaultMonotonicSecondsProvider, type MonotonicClockProvider } from './pcp-client'
import {
  assertSoapActionSuccess,
  parseGetExternalIpAddressResponse,
  parseGetSpecificPortMappingEntryResponse,
  parseUpnpDeviceDescription,
  UpnpError,
  type UpnpWanService,
  type VerifiedSpecificMappingEntry
} from './upnp-protocol'
import {
  discoverUpnpLocation,
  getUpnpDeviceDescription,
  requestUpnpAddPortMapping,
  requestUpnpDeletePortMapping,
  requestUpnpExternalIpAddress,
  requestUpnpSpecificPortMapping
} from './upnp-transport'

export const UPNP_DEFAULT_MAPPING_LIFETIME_SECONDS = 3600
export const UPNP_MIN_MAPPING_LIFETIME_SECONDS = 60
export const UPNP_MAX_MAPPING_LIFETIME_SECONDS = 7200
export const UPNP_MAX_EXTERNAL_PORT_ATTEMPTS = 4
export const UPNP_DYNAMIC_PORT_MIN = 49152
export const UPNP_DYNAMIC_PORT_MAX_EXCLUSIVE = 65536

interface CreateUpnpPortMappingOptions {
  readonly listener: LanTcpServerHandle
  readonly requestedLifetimeSeconds?: number
  readonly gatewayProvider?: PortMappingGatewayProvider
  readonly monotonicClock?: MonotonicClockProvider
  readonly httpTimeoutMs?: number
  readonly randomExternalPort?: () => number
  /** Uso interno da PortMappingStrategy; APIs low-level mantêm auto-renew por default. */
  readonly autoRenew?: boolean
  /** Internal deterministic-test seams; production callers leave these unset. */
  readonly testOnlySsdpDestinationAddress?: string
  readonly testOnlySsdpDestinationPort?: number
  readonly testOnlySsdpTimeoutMs?: number
  readonly testOnlyAllowLoopback?: boolean
}

interface UpnpController {
  readonly gatewayAddress: string
  readonly localAddress: string
  readonly internalPort: number
  readonly service: UpnpWanService
  readonly requestedLifetimeSeconds: number
  readonly httpTimeoutMs?: number
}

async function getExternalAddress(controller: UpnpController): Promise<string> {
  const body = await requestUpnpExternalIpAddress({
    controlUrl: controller.service.controlUrl,
    gatewayAddress: controller.gatewayAddress,
    localAddress: controller.localAddress,
    serviceType: controller.service.serviceType,
    timeoutMs: controller.httpTimeoutMs
  })
  const address = parseGetExternalIpAddressResponse(body)
  if (isIP(address) !== 4) throw new UpnpError('UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL')
  const classification = classifyNetworkAddress(address)
  if (classification.scope !== 'GLOBAL' || !classification.isGloballyRoutableWan) {
    throw new UpnpError('UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL')
  }
  return classification.normalizedAddress
}

async function addPortMapping(controller: UpnpController, externalPort: number): Promise<void> {
  const body = await requestUpnpAddPortMapping({
    controlUrl: controller.service.controlUrl,
    gatewayAddress: controller.gatewayAddress,
    localAddress: controller.localAddress,
    serviceType: controller.service.serviceType,
    timeoutMs: controller.httpTimeoutMs
  }, {
    externalPort,
    internalPort: controller.internalPort,
    internalClient: controller.localAddress,
    leaseDurationSeconds: controller.requestedLifetimeSeconds
  })
  assertSoapActionSuccess(body, 'AddPortMapping')
}

async function getSpecificMapping(
  controller: UpnpController,
  externalPort: number
): Promise<VerifiedSpecificMappingEntry> {
  const body = await requestUpnpSpecificPortMapping({
    controlUrl: controller.service.controlUrl,
    gatewayAddress: controller.gatewayAddress,
    localAddress: controller.localAddress,
    serviceType: controller.service.serviceType,
    timeoutMs: controller.httpTimeoutMs
  }, externalPort)
  return parseGetSpecificPortMappingEntryResponse(body)
}

function verifySpecificMapping(
  controller: UpnpController,
  entry: VerifiedSpecificMappingEntry
): number {
  if (
    isIP(entry.internalClient) !== 4 ||
    classifyNetworkAddress(entry.internalClient).normalizedAddress !== controller.localAddress ||
    entry.internalPort !== controller.internalPort ||
    entry.enabled !== true
  ) throw new UpnpError('UPNP_MAPPING_VERIFICATION_FAILED')
  if (entry.leaseDurationSeconds === 0) {
    throw new UpnpError('UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED')
  }
  return Math.min(entry.leaseDurationSeconds, controller.requestedLifetimeSeconds)
}

async function deletePortMapping(controller: UpnpController, externalPort: number): Promise<void> {
  try {
    const body = await requestUpnpDeletePortMapping({
      controlUrl: controller.service.controlUrl,
      gatewayAddress: controller.gatewayAddress,
      localAddress: controller.localAddress,
      serviceType: controller.service.serviceType,
      timeoutMs: controller.httpTimeoutMs
    }, externalPort)
    assertSoapActionSuccess(body, 'DeletePortMapping')
  } catch (error) {
    if (error instanceof UpnpError && error.code === 'UPNP_SOAP_FAULT' && error.soapErrorCode === 714) return
    throw error
  }
}

function nextExternalPort(
  usedPorts: Set<number>,
  randomExternalPort: () => number
): number {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const candidate = randomExternalPort()
    if (
      Number.isInteger(candidate) &&
      candidate >= UPNP_DYNAMIC_PORT_MIN &&
      candidate < UPNP_DYNAMIC_PORT_MAX_EXCLUSIVE &&
      !usedPorts.has(candidate)
    ) return candidate
  }
  throw new UpnpError('UPNP_MAPPING_CONFLICT')
}

const UPNP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN = Symbol('upnp-active-mapping')

interface UpnpRuntimeOptions {
  readonly constructionToken: typeof UPNP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN
  readonly listener: LanTcpServerHandle
  readonly controller: UpnpController
  readonly externalAddress: string
  readonly externalPort: number
  readonly effectiveLeaseSeconds: number
  readonly monotonicClock: MonotonicClockProvider
  readonly autoRenew: boolean
}

export class UpnpActivePortMapping extends ActivePortMappingSource {
  private active = true
  private closeStarted = false
  private renewalTimer: NodeJS.Timeout | null = null
  private renewalTask: Promise<void> | null = null
  private readonly listener: LanTcpServerHandle
  private readonly controller: UpnpController
  private readonly monotonicClock: MonotonicClockProvider
  private readonly autoRenew: boolean
  private readonly unregisterListenerClose: () => void
  private externalAddress: string
  private readonly externalPort: number
  private effectiveLeaseSeconds: number
  private monotonicDeadlineSeconds: number
  private expiresAtUnixSeconds: number

  constructor(options: UpnpRuntimeOptions) {
    if (options.constructionToken !== UPNP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN) {
      throw new UpnpError('UPNP_REQUEST_INVALID')
    }
    super()
    this.listener = options.listener
    this.controller = options.controller
    this.externalAddress = options.externalAddress
    this.externalPort = options.externalPort
    this.effectiveLeaseSeconds = options.effectiveLeaseSeconds
    this.monotonicClock = options.monotonicClock
    this.autoRenew = options.autoRenew
    this.monotonicDeadlineSeconds = this.monotonicClock() + options.effectiveLeaseSeconds
    this.expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + options.effectiveLeaseSeconds
    this.unregisterListenerClose = registerLanTcpServerCloseListener(this.listener, () => {
      this.deactivate()
      void this.deleteAfterPendingRenewal()
    })
    this.scheduleRenewal()
  }

  isActive(): boolean {
    if (!this.active) return false
    if (this.listener.isClosed() || this.monotonicClock() >= this.monotonicDeadlineSeconds) {
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

  getGrantedLifetime(): number { return this.effectiveLeaseSeconds }
  getInternalEndpoint(): BoundTcpEndpoint { return this.listener.endpoint }
  async executeRenewalForTesting(): Promise<void> { await this.startRenewal() }
  async renewForManagedStrategy(): Promise<void> { await this.startRenewal() }

  private scheduleRenewal(): void {
    if (this.renewalTimer) clearTimeout(this.renewalTimer)
    if (!this.active || !this.autoRenew) return
    const delay = Math.min(0x7fffffff, Math.max(1, Math.floor(this.effectiveLeaseSeconds * 500)))
    this.renewalTimer = setTimeout(() => { void this.startRenewal() }, delay)
  }

  private startRenewal(): Promise<void> {
    if (!this.isActive()) return Promise.resolve()
    if (this.renewalTask) return this.renewalTask
    const task = this.executeRenewal()
    this.renewalTask = task
    void task.finally(() => {
      if (this.renewalTask === task) this.renewalTask = null
    })
    return task
  }

  private async executeRenewal(): Promise<void> {
    try {
      await addPortMapping(this.controller, this.externalPort)
      const entry = await getSpecificMapping(this.controller, this.externalPort)
      let effectiveLease: number
      try {
        effectiveLease = verifySpecificMapping(this.controller, entry)
      } catch (error) {
        this.deactivate()
        void this.deleteBestEffort()
        throw error
      }
      let externalAddress: string
      try {
        externalAddress = await getExternalAddress(this.controller)
      } catch (error) {
        if (error instanceof UpnpError && error.code === 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL') {
          this.deactivate()
          void this.deleteBestEffort()
        }
        throw error
      }
      if (!this.active) return
      this.externalAddress = externalAddress
      this.effectiveLeaseSeconds = effectiveLease
      this.monotonicDeadlineSeconds = this.monotonicClock() + effectiveLease
      this.expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + effectiveLease
      this.scheduleRenewal()
    } catch {
      // Sem Add+GetSpecific+GetExternal válidos, a deadline anterior não é estendida.
    }
  }

  private deactivate(): void {
    this.active = false
    if (this.renewalTimer) clearTimeout(this.renewalTimer)
    this.renewalTimer = null
    this.unregisterListenerClose()
  }

  private async deleteBestEffort(): Promise<void> {
    if (this.closeStarted) return
    this.closeStarted = true
    try { await deletePortMapping(this.controller, this.externalPort) } catch { /* advisory */ }
  }

  private async deleteAfterPendingRenewal(): Promise<void> {
    const pendingRenewal = this.renewalTask
    if (pendingRenewal) await pendingRenewal
    await this.deleteBestEffort()
  }

  async close(): Promise<void> {
    this.deactivate()
    await this.deleteAfterPendingRenewal()
  }
}

function validateRequestedLifetime(value: number): number {
  if (
    !Number.isInteger(value) ||
    value < UPNP_MIN_MAPPING_LIFETIME_SECONDS ||
    value > UPNP_MAX_MAPPING_LIFETIME_SECONDS
  ) throw new UpnpError('UPNP_REQUEST_INVALID')
  return value
}

export async function createUpnpPortMapping(
  options: CreateUpnpPortMappingOptions
): Promise<UpnpActivePortMapping> {
  const { listener } = options
  if (listener && typeof listener === 'object' && typeof listener.isClosed === 'function' && listener.isClosed()) {
    throw new UpnpError('UPNP_LISTENER_CLOSED')
  }
  if (!isLegitimateActiveServerHandle(listener)) throw new UpnpError('UPNP_LISTENER_INVALID')
  const endpoint = listener.endpoint
  if (endpoint.family !== 4) throw new UpnpError('UPNP_REQUEST_INVALID')
  const localClass = classifyNetworkAddress(endpoint.address)
  const controlledLoopbackTest = options.testOnlyAllowLoopback === true && localClass.scope === 'LOOPBACK'
  if (localClass.scope !== 'LAN_PRIVATE' && !controlledLoopbackTest) throw new UpnpError('UPNP_REQUEST_INVALID')

  const gateway = await (
    options.gatewayProvider ?? createDefaultPortMappingGatewayProvider()
  ).resolveGatewayForLocalAddress(localClass.normalizedAddress)
  if (!gateway) throw new UpnpError('UPNP_GATEWAY_NOT_FOUND')
  if (isIP(gateway) !== 4) throw new UpnpError('UPNP_GATEWAY_INVALID')
  const gatewayClass = classifyNetworkAddress(gateway)
  if (
    gatewayClass.scope !== 'LAN_PRIVATE' &&
    gatewayClass.scope !== 'LINK_LOCAL' &&
    !(controlledLoopbackTest && gatewayClass.scope === 'LOOPBACK')
  ) throw new UpnpError('UPNP_GATEWAY_INVALID')

  const requestedLifetimeSeconds = validateRequestedLifetime(
    options.requestedLifetimeSeconds ?? UPNP_DEFAULT_MAPPING_LIFETIME_SECONDS
  )
  const location = await discoverUpnpLocation({
    localAddress: localClass.normalizedAddress,
    gatewayAddress: gatewayClass.normalizedAddress,
    destinationAddress: options.testOnlySsdpDestinationAddress,
    destinationPort: options.testOnlySsdpDestinationPort,
    timeoutMs: options.testOnlySsdpTimeoutMs
  })
  const description = await getUpnpDeviceDescription(
    location,
    gatewayClass.normalizedAddress,
    localClass.normalizedAddress,
    options.httpTimeoutMs
  )
  const service = parseUpnpDeviceDescription(description, location, gatewayClass.normalizedAddress)
  const controller: UpnpController = {
    gatewayAddress: gatewayClass.normalizedAddress,
    localAddress: localClass.normalizedAddress,
    internalPort: endpoint.port,
    service,
    requestedLifetimeSeconds,
    httpTimeoutMs: options.httpTimeoutMs
  }
  const externalAddress = await getExternalAddress(controller)
  const usedPorts = new Set<number>()
  const randomExternalPort = options.randomExternalPort ?? (() => randomInt(UPNP_DYNAMIC_PORT_MIN, UPNP_DYNAMIC_PORT_MAX_EXCLUSIVE))
  let externalPort = endpoint.port
  for (let attempt = 0; attempt < UPNP_MAX_EXTERNAL_PORT_ATTEMPTS; attempt += 1) {
    if (attempt > 0) externalPort = nextExternalPort(usedPorts, randomExternalPort)
    usedPorts.add(externalPort)
    try {
      await addPortMapping(controller, externalPort)
    } catch (error) {
      if (error instanceof UpnpError && error.code === 'UPNP_SOAP_FAULT') {
        if (error.soapErrorCode === 718) continue
        if (error.soapErrorCode === 725) {
          throw new UpnpError('UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED', 725)
        }
      }
      throw error
    }

    try {
      const entry = await getSpecificMapping(controller, externalPort)
      const effectiveLeaseSeconds = verifySpecificMapping(controller, entry)
      return new UpnpActivePortMapping({
        constructionToken: UPNP_ACTIVE_MAPPING_CONSTRUCTION_TOKEN,
        listener,
        controller,
        externalAddress,
        externalPort,
        effectiveLeaseSeconds,
        monotonicClock: options.monotonicClock ?? defaultMonotonicSecondsProvider,
        autoRenew: options.autoRenew !== false
      })
    } catch (error) {
      try { await deletePortMapping(controller, externalPort) } catch { /* cleanup best effort */ }
      throw error
    }
  }
  throw new UpnpError('UPNP_MAPPING_CONFLICT', 718)
}
