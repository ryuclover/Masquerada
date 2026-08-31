import type { KeyObject } from 'node:crypto'

import {
  isPeerRelayEndpoint,
  type PeerRelayEndpoint,
  type RegisterRelayTargetOptions,
  type RelayTargetRegistration,
  type RelayTransportStream
} from './peer-relay'
import type { ConnectivitySubsystem } from './connectivity-subsystem'

export const MAX_MANAGED_RELAY_REGISTRATIONS_PER_TARGET = 3
export const MAX_RELAY_REGISTRATION_REFRESH_ATTEMPTS = 2
export const RELAY_REGISTRATION_REFRESH_FRACTION = 0.5

export type ManagedRelayRegistrationErrorCode =
  | 'RELAY_REGISTRATION_MANAGER_INVALID'
  | 'RELAY_REGISTRATION_MANAGER_LIMIT'
  | 'RELAY_REGISTRATION_REFRESH_FAILED'
  | 'RELAY_REGISTRATION_MANAGER_CLOSED'

export class ManagedRelayRegistrationError extends Error {
  constructor(readonly code: ManagedRelayRegistrationErrorCode, options?: ErrorOptions) {
    super(code, options)
    this.name = 'ManagedRelayRegistrationError'
  }
}

export class ManagedRelayRegistrationRegistry {
  private readonly counts = new Map<string, number>()

  reserve(targetServerId: string): () => void {
    const count = this.counts.get(targetServerId) ?? 0
    if (count >= MAX_MANAGED_RELAY_REGISTRATIONS_PER_TARGET) {
      throw new ManagedRelayRegistrationError('RELAY_REGISTRATION_MANAGER_LIMIT')
    }
    this.counts.set(targetServerId, count + 1)
    let released = false
    return () => {
      if (released) return
      released = true
      const current = this.counts.get(targetServerId) ?? 1
      if (current <= 1) this.counts.delete(targetServerId)
      else this.counts.set(targetServerId, current - 1)
    }
  }

  count(targetServerId: string): number {
    return this.counts.get(targetServerId) ?? 0
  }
}

const defaultRegistry = new ManagedRelayRegistrationRegistry()
const MANAGER_TOKEN = Symbol('ManagedRelayTargetRegistration')
const managers = new WeakSet<object>()

export interface CreateManagedRelayTargetRegistrationOptions {
  readonly endpoint: PeerRelayEndpoint
  readonly targetServerId: string
  readonly targetServerPublicKey: Buffer
  readonly targetServerPrivateKey: KeyObject
  readonly relayServerId: string
  readonly outerDeviceFingerprint: string
  readonly onIncomingCircuit: (stream: RelayTransportStream) => void | Promise<void>
  readonly registrationTimeoutMs?: number
  readonly nowMs?: () => number
  readonly maxRefreshAttempts?: number
  readonly registry?: ManagedRelayRegistrationRegistry
  readonly subsystem?: ConnectivitySubsystem
}

export class ManagedRelayTargetRegistration {
  private closed = false
  private refreshing = false
  private refreshAttempts = 0
  private refreshTimer?: ReturnType<typeof setTimeout>
  private registration: RelayTargetRegistration
  private readonly removeEndpointCloseHandler: () => void
  private readonly removeSubsystemResource: () => void

  constructor(
    token: symbol,
    private readonly endpoint: PeerRelayEndpoint,
    registration: RelayTargetRegistration,
    private readonly registrationOptions: RegisterRelayTargetOptions,
    private readonly nowMs: () => number,
    private readonly maxRefreshAttempts: number,
    private readonly releaseRegistry: () => void,
    subsystem?: ConnectivitySubsystem
  ) {
    if (token !== MANAGER_TOKEN || !isPeerRelayEndpoint(endpoint)) {
      throw new ManagedRelayRegistrationError('RELAY_REGISTRATION_MANAGER_INVALID')
    }
    this.registration = registration
    managers.add(this)
    this.removeEndpointCloseHandler = endpoint.onClose(() => this.terminateFromChannel())
    this.removeSubsystemResource = subsystem?.registerResource({
      close: () => this.close(),
      forceClose: () => this.close()
    }) ?? (() => {})
    this.scheduleHalfLifeRefresh()
  }

  isActive(): boolean {
    return !this.closed && !this.registration.isClosed() && this.nowMs() < this.registration.expiresAtMs
  }

  get expiresAtMs(): number {
    return this.registration.expiresAtMs
  }

  get targetServerId(): string {
    return this.registration.targetServerId
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    if (this.refreshTimer) clearTimeout(this.refreshTimer)
    this.refreshTimer = undefined
    this.removeEndpointCloseHandler()
    this.removeSubsystemResource()
    this.registration.close()
    this.releaseRegistry()
    this.removeSubsystemResource()
  }

  private scheduleHalfLifeRefresh(): void {
    if (this.closed || this.registration.isClosed()) return
    if (this.refreshTimer) clearTimeout(this.refreshTimer)
    const remaining = this.registration.expiresAtMs - this.nowMs()
    if (remaining <= 0) return
    this.refreshAttempts = 0
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = undefined
      void this.refresh()
    }, Math.max(1, Math.floor(remaining * RELAY_REGISTRATION_REFRESH_FRACTION)))
  }

  private async refresh(): Promise<void> {
    if (this.closed || this.refreshing || this.registration.isClosed()) return
    this.refreshing = true
    const generation = this.registration
    try {
      const refreshed = await this.endpoint.refreshTargetRegistration(generation, this.registrationOptions)
      if (this.closed || this.registration !== generation) {
        refreshed.close()
        return
      }
      this.registration = refreshed
      this.refreshAttempts = 0
      this.scheduleHalfLifeRefresh()
    } catch {
      if (this.closed || this.registration !== generation || this.registration.isClosed()) return
      this.refreshAttempts += 1
      const remaining = this.registration.expiresAtMs - this.nowMs()
      if (this.refreshAttempts < this.maxRefreshAttempts && remaining > 1) {
        this.refreshTimer = setTimeout(() => {
          this.refreshTimer = undefined
          void this.refresh()
        }, Math.max(1, Math.min(1000, Math.floor(remaining / 2))))
      }
    } finally {
      this.refreshing = false
    }
  }

  private terminateFromChannel(): void {
    if (this.closed) return
    this.closed = true
    if (this.refreshTimer) clearTimeout(this.refreshTimer)
    this.refreshTimer = undefined
    this.releaseRegistry()
  }
}

export async function createManagedRelayTargetRegistration(
  options: CreateManagedRelayTargetRegistrationOptions
): Promise<ManagedRelayTargetRegistration> {
  if (!isPeerRelayEndpoint(options.endpoint)) {
    throw new ManagedRelayRegistrationError('RELAY_REGISTRATION_MANAGER_INVALID')
  }
  const maxRefreshAttempts = options.maxRefreshAttempts ?? MAX_RELAY_REGISTRATION_REFRESH_ATTEMPTS
  if (!Number.isInteger(maxRefreshAttempts) || maxRefreshAttempts < 1 || maxRefreshAttempts > MAX_RELAY_REGISTRATION_REFRESH_ATTEMPTS) {
    throw new ManagedRelayRegistrationError('RELAY_REGISTRATION_MANAGER_INVALID')
  }
  const registry = options.registry ?? defaultRegistry
  const release = registry.reserve(options.targetServerId)
  const registrationOptions: RegisterRelayTargetOptions = {
    targetServerId: options.targetServerId,
    targetServerPublicKey: options.targetServerPublicKey,
    targetServerPrivateKey: options.targetServerPrivateKey,
    relayServerId: options.relayServerId,
    outerDeviceFingerprint: options.outerDeviceFingerprint,
    onIncomingCircuit: options.onIncomingCircuit,
    timeoutMs: options.registrationTimeoutMs
  }
  try {
    const registration = await options.endpoint.registerTarget(registrationOptions)
    return new ManagedRelayTargetRegistration(
      MANAGER_TOKEN,
      options.endpoint,
      registration,
      registrationOptions,
      options.nowMs ?? (() => performance.now()),
      maxRefreshAttempts,
      release,
      options.subsystem
    )
  } catch (cause) {
    release()
    throw cause
  }
}

export function isManagedRelayTargetRegistration(value: unknown): value is ManagedRelayTargetRegistration {
  return typeof value === 'object' && value !== null && managers.has(value)
}
