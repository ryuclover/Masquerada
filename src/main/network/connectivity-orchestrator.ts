import {
  aggregateServerCandidates,
  EphemeralCandidateSuccessCache,
  type AggregateCandidateSourcesOptions,
  type ServerDialPlan
} from './candidate-aggregation'
import {
  CandidateRaceError,
  raceSecureServerConnections,
  type CandidateAuthorization,
  type CandidateRaceDeviceIdentity,
  type SecureConnectionAttempt
} from './candidate-racing'
import {
  MAX_CONNECTIVITY_CANDIDATES,
  type VerifiedConnectivityDescriptor
} from './connectivity-descriptor'
import type { DiscoveredLanServer } from './lan-discovery'
import {
  isCanonicalServerId,
  isPeerRendezvousEndpoint,
  type PeerRendezvousEndpoint,
  type RendezvousShareableDescriptor
} from './peer-rendezvous'
import {
  isPeerRelayEndpoint,
  type PeerRelayEndpoint,
  type RelayTransportStream
} from './peer-relay'
import type { ValidatedStunObservation } from './stun-observation'
import type { NetworkEnvironmentGeneration } from './network-environment'
import {
  establishSecureServerConnectionOverTransport,
  isClientSecurePreAuthorizationConnection,
  type ClientSecurePreAuthorizationConnection,
  type ClientTcpPeerConnection
} from './tcp-transport'
import {
  ConnectivityResourceError
} from './connectivity-resource-governor'
import {
  ConnectivitySubsystem,
  ConnectivitySubsystemError,
  defaultConnectivitySubsystem
} from './connectivity-subsystem'
import {
  classifyConnectivityFailure,
  decideConnectivityContinuation,
  type ConnectivityFailurePhase
} from './connectivity-failure'

export const MAX_RENDEZVOUS_PEERS_PER_CONNECT = 3
export const MAX_RELAY_PEERS_PER_CONNECT = 3
export const MAX_RENDEZVOUS_PHASE_MS = 5000
export const DEFAULT_CONNECT_OVERALL_TIMEOUT_MS = 30_000
export const MAX_CONNECT_OVERALL_TIMEOUT_MS = 45_000
export const DEFAULT_DIRECT_PHASE_TIMEOUT_MS = 12_000
export const MAX_DIRECT_PHASE_TIMEOUT_MS = 15_000
export const RELAY_SUCCESS_HINT_TTL_MS = 10 * 60 * 1000
export const MAX_RELAY_SUCCESS_HINT_ENTRIES = 64

export type ConnectivityOperationState =
  | 'INITIAL'
  | 'DIRECT'
  | 'RENDEZVOUS'
  | 'DIRECT_ENRICHED'
  | 'RELAY_SELECTION'
  | 'RELAY_CONNECTING'
  | 'AUTHORIZING'
  | 'CONNECTED'
  | 'FAILED'
  | 'ABORTED'

export type ConnectivityOrchestrationErrorCode =
  | 'CONNECT_PATH_UNAVAILABLE'
  | 'CONNECT_DIRECT_UNREACHABLE'
  | 'CONNECT_RENDEZVOUS_UNAVAILABLE'
  | 'CONNECT_RELAY_UNAVAILABLE'
  | 'CONNECT_TARGET_AUTHORIZATION_FAILED'
  | 'CONNECT_ABORTED'
  | 'CONNECT_TIMEOUT'
  | 'CONNECT_SECURITY_INVALID'
  | 'CONNECT_OPERATION_IN_PROGRESS'
  | 'CONNECT_RESOURCE_LIMIT'
  | 'CONNECT_SHUTTING_DOWN'

export class ConnectivityOrchestrationError extends Error {
  constructor(readonly code: ConnectivityOrchestrationErrorCode, options?: ErrorOptions) {
    super(code, options)
    this.name = 'ConnectivityOrchestrationError'
  }
}

interface PeerSuccessHint {
  readonly targetServerId: string
  readonly peerId: string
  readonly succeededAtMs: number
  readonly setupLatencyMs?: number
}

class EphemeralPeerSuccessCache {
  private readonly entries = new Map<string, PeerSuccessHint>()
  constructor(
    private readonly nowMs: () => number = () => performance.now(),
    private readonly ttlMs = RELAY_SUCCESS_HINT_TTL_MS,
    private readonly maxEntries = MAX_RELAY_SUCCESS_HINT_ENTRIES
  ) {
    if (ttlMs < 1 || ttlMs > RELAY_SUCCESS_HINT_TTL_MS || maxEntries < 1 || maxEntries > MAX_RELAY_SUCCESS_HINT_ENTRIES) {
      throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    }
  }
  protected record(targetServerId: string, peerId: string, setupLatencyMs?: number): void {
    if (!isCanonicalServerId(targetServerId) || !isCanonicalServerId(peerId)) {
      throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    }
    const key = `${targetServerId}\u0000${peerId}`
    this.entries.delete(key)
    this.entries.set(key, Object.freeze({ targetServerId, peerId, succeededAtMs: this.nowMs(), setupLatencyMs }))
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined
      if (oldest === undefined) break
      this.entries.delete(oldest)
    }
  }
  hasFresh(targetServerId: string, peerId: string): boolean {
    const key = `${targetServerId}\u0000${peerId}`
    const entry = this.entries.get(key)
    if (!entry) return false
    const elapsed = this.nowMs() - entry.succeededAtMs
    if (elapsed < 0 || elapsed >= this.ttlMs) {
      this.entries.delete(key)
      return false
    }
    this.entries.delete(key)
    this.entries.set(key, entry)
    return true
  }
  get size(): number { return this.entries.size }
}

export class EphemeralRelaySuccessCache extends EphemeralPeerSuccessCache {
  recordCryptographicSuccess(
    targetServerId: string,
    peer: PeerRelayEndpoint,
    connection: ClientSecurePreAuthorizationConnection,
    setupLatencyMs?: number
  ): void {
    if (
      !isPeerRelayEndpoint(peer) || !isCanonicalServerId(peer.relayPeerId) ||
      !isClientSecurePreAuthorizationConnection(connection) ||
      connection.expectedServerId !== targetServerId || connection.isDestroyed()
    ) throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    this.record(targetServerId, peer.relayPeerId, setupLatencyMs)
  }
}

export class EphemeralRendezvousPeerSuccessCache extends EphemeralPeerSuccessCache {
  recordDescriptorSuccess(
    targetServerId: string,
    peer: PeerRendezvousEndpoint,
    descriptor: RendezvousShareableDescriptor
  ): void {
    if (
      !isPeerRendezvousEndpoint(peer) || !isCanonicalServerId(peer.peerServerId) ||
      descriptor.serverId !== targetServerId
    ) throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    descriptor.getVerifiedDescriptor()
    this.record(targetServerId, peer.peerServerId)
  }
}

export interface AuthorizedConnectivityPeer {
  readonly rendezvous?: PeerRendezvousEndpoint
  readonly relay?: PeerRelayEndpoint
}

export interface ConnectivityTarget {
  readonly serverId: string
  readonly publicKey: Buffer
}

export interface DirectConnectivitySources {
  readonly descriptors?: readonly VerifiedConnectivityDescriptor[]
  readonly lanDiscoveries?: readonly DiscoveredLanServer[]
  readonly localStunObservation?: ValidatedStunObservation
  readonly candidateSuccessCache?: EphemeralCandidateSuccessCache
  readonly networkGeneration?: NetworkEnvironmentGeneration
}

export type EstablishRelaySecureConnection = (
  stream: RelayTransportStream,
  options: {
    readonly expectedServerId: string
    readonly expectedServerPublicKey: Buffer
    readonly device: CandidateRaceDeviceIdentity
    readonly signal: AbortSignal
  }
) => Promise<ClientSecurePreAuthorizationConnection>

export interface ConnectToServerOptions {
  readonly target: ConnectivityTarget
  readonly directSources?: DirectConnectivitySources
  readonly authorizedPeers?: readonly AuthorizedConnectivityPeer[]
  readonly device: CandidateRaceDeviceIdentity
  readonly authorization: CandidateAuthorization
  readonly signal?: AbortSignal
  readonly overallTimeoutMs?: number
  readonly directPhaseTimeoutMs?: number
  readonly rendezvousPhaseMs?: number
  readonly relayOpenTimeoutMs?: number
  readonly relaySuccessCache?: EphemeralRelaySuccessCache
  readonly rendezvousSuccessCache?: EphemeralRendezvousPeerSuccessCache
  readonly monotonicNowMs?: () => number
  readonly nowSeconds?: () => number
  readonly onStateChange?: (state: ConnectivityOperationState) => void
  readonly establishDirectConnection?: SecureConnectionAttempt
  readonly establishRelayConnection?: EstablishRelaySecureConnection
  readonly subsystem?: ConnectivitySubsystem
}

const MANAGED_CONNECTION_TOKEN = Symbol('ManagedServerConnection')
const managedConnections = new WeakSet<object>()

export class ManagedServerConnection {
  private destroyed = false
  constructor(
    token: symbol,
    readonly connection: ClientTcpPeerConnection,
    readonly source: 'DIRECT' | 'RELAY',
    readonly relayPeerId?: string,
    private readonly onDestroy: () => void = () => {}
  ) {
    if (token !== MANAGED_CONNECTION_TOKEN) throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    managedConnections.add(this)
  }
  destroy(): void {
    if (this.destroyed) return
    this.destroyed = true
    this.connection.destroy()
    this.onDestroy()
  }
}

export function isManagedServerConnection(value: unknown): value is ManagedServerConnection {
  return typeof value === 'object' && value !== null && managedConnections.has(value)
}

function peerId(peer: AuthorizedConnectivityPeer): string | null {
  const rendezvousId = peer.rendezvous?.peerServerId
  const relayId = peer.relay?.relayPeerId
  if (rendezvousId && relayId && rendezvousId !== relayId) return null
  const id = rendezvousId ?? relayId
  return isCanonicalServerId(id) ? id : null
}

function orderPeers<T extends AuthorizedConnectivityPeer>(
  peers: readonly T[],
  targetServerId: string,
  cache: EphemeralPeerSuccessCache | undefined,
  hasCapability: (peer: T) => boolean
): T[] {
  const unique = new Map<string, T>()
  for (const peer of peers) {
    const id = peerId(peer)
    if (!id || !hasCapability(peer) || unique.has(id)) continue
    unique.set(id, peer)
  }
  return [...unique.entries()]
    .sort(([idA], [idB]) => {
      const hintedA = cache?.hasFresh(targetServerId, idA) === true
      const hintedB = cache?.hasFresh(targetServerId, idB) === true
      return hintedA === hintedB ? idA.localeCompare(idB) : hintedA ? -1 : 1
    })
    .map(([, peer]) => peer)
}

async function authorizeSecureConnection(
  secure: ClientSecurePreAuthorizationConnection,
  authorization: CandidateAuthorization,
  signal: AbortSignal
): Promise<ClientTcpPeerConnection> {
  const onAbort = (): void => secure.destroy()
  signal.addEventListener('abort', onAbort, { once: true })
  try {
    if (signal.aborted) throw new ConnectivityOrchestrationError('CONNECT_ABORTED')
    const result = authorization.mode === 'admission'
      ? await secure.authorizeWithInvite(authorization.invite)
      : await secure.authorizeExistingMember()
    return result.connection
  } finally {
    signal.removeEventListener('abort', onAbort)
  }
}

function descriptorKey(descriptor: VerifiedConnectivityDescriptor): string {
  return Buffer.from(descriptor.descriptorId).toString('hex')
}

function planOptions(
  options: ConnectToServerOptions,
  descriptors: readonly VerifiedConnectivityDescriptor[],
  excludeEndpointKeys?: ReadonlySet<string>
): AggregateCandidateSourcesOptions {
  return {
    expectedServerId: options.target.serverId,
    expectedServerPublicKey: options.target.publicKey,
    descriptors,
    lanDiscoveries: options.directSources?.lanDiscoveries,
    successCache: options.directSources?.candidateSuccessCache,
    localStunObservation: options.directSources?.localStunObservation,
    nowSeconds: options.nowSeconds?.(),
    excludeEndpointKeys,
    networkGeneration: options.directSources?.networkGeneration
  }
}

/** Direct-first, single-winner connectivity policy. Relay is considered only after direct exhaustion. */
export async function connectToServer(options: ConnectToServerOptions): Promise<ManagedServerConnection> {
  const overallTimeoutMs = options.overallTimeoutMs ?? DEFAULT_CONNECT_OVERALL_TIMEOUT_MS
  const directPhaseTimeoutMs = options.directPhaseTimeoutMs ?? DEFAULT_DIRECT_PHASE_TIMEOUT_MS
  const rendezvousPhaseMs = options.rendezvousPhaseMs ?? MAX_RENDEZVOUS_PHASE_MS
  const relayOpenTimeoutMs = options.relayOpenTimeoutMs ?? 3000
  if (
    !isCanonicalServerId(options.target.serverId) || !Buffer.isBuffer(options.target.publicKey) ||
    !Number.isInteger(overallTimeoutMs) || overallTimeoutMs < 1 || overallTimeoutMs > MAX_CONNECT_OVERALL_TIMEOUT_MS ||
    !Number.isInteger(directPhaseTimeoutMs) || directPhaseTimeoutMs < 1 || directPhaseTimeoutMs > MAX_DIRECT_PHASE_TIMEOUT_MS ||
    !Number.isInteger(rendezvousPhaseMs) || rendezvousPhaseMs < 1 || rendezvousPhaseMs > MAX_RENDEZVOUS_PHASE_MS ||
    !Number.isInteger(relayOpenTimeoutMs) || relayOpenTimeoutMs < 1 || relayOpenTimeoutMs > 10_000 ||
    !Array.isArray(options.authorizedPeers ?? [])
  ) throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')

  const subsystem = options.subsystem ?? defaultConnectivitySubsystem
  let operation
  try {
    operation = subsystem.beginConnect(options.target.serverId, options.signal)
  } catch (cause) {
    if (cause instanceof ConnectivityResourceError) {
      throw new ConnectivityOrchestrationError(
        cause.code === 'CONNECT_OPERATION_IN_PROGRESS' ? 'CONNECT_OPERATION_IN_PROGRESS' : 'CONNECT_RESOURCE_LIMIT',
        { cause }
      )
    }
    if (cause instanceof ConnectivitySubsystemError) {
      throw new ConnectivityOrchestrationError('CONNECT_SHUTTING_DOWN', { cause })
    }
    throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID', { cause })
  }
  const monotonicNowMs = options.monotonicNowMs ?? (() => performance.now())
  const startedAt = monotonicNowMs()
  if (!Number.isFinite(startedAt)) {
    operation.finish()
    throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
  }
  const overallDeadline = startedAt + overallTimeoutMs
  let lastMonotonicMs = startedAt
  const readMonotonicMs = (): number => {
    const current = monotonicNowMs()
    if (!Number.isFinite(current) || current < lastMonotonicMs) {
      throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    }
    lastMonotonicMs = current
    return current
  }
  const operationController = new AbortController()
  let timedOut = false
  let callerAborted = false
  let settled = false
  let authorizationStarted = false
  const setState = (next: ConnectivityOperationState): void => {
    options.onStateChange?.(next)
  }
  const onOperationAbort = (): void => {
    callerAborted = true
    operationController.abort()
  }
  operation.signal.addEventListener('abort', onOperationAbort, { once: true })
  if (operation.signal.aborted) onOperationAbort()
  const overallTimer = setTimeout(() => {
    timedOut = true
    operationController.abort()
  }, overallTimeoutMs)

  const remainingMs = (): number => Math.max(0, Math.floor(overallDeadline - readMonotonicMs()))
  const abortError = (): ConnectivityOrchestrationError => new ConnectivityOrchestrationError(
    timedOut ? 'CONNECT_TIMEOUT' : 'CONNECT_ABORTED'
  )
  const ensureActive = (): number => {
    const remaining = remainingMs()
    if (remaining <= 0) {
      timedOut = true
      operationController.abort()
    }
    if (operationController.signal.aborted) throw abortError()
    return remaining
  }
  const finish = (
    connection: ClientTcpPeerConnection,
    source: 'DIRECT' | 'RELAY',
    relayPeerId?: string
  ): ManagedServerConnection => {
    ensureActive()
    if (settled) {
      connection.destroy()
      throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    }
    let unregister = (): void => {}
    const managed = new ManagedServerConnection(
      MANAGED_CONNECTION_TOKEN,
      connection,
      source,
      relayPeerId,
      () => unregister()
    )
    unregister = subsystem.registerResource({ close: () => managed.destroy(), forceClose: () => managed.destroy() })
    try {
      setState('CONNECTED')
      ensureActive()
    } catch (cause) {
      managed.destroy()
      throw cause
    }
    settled = true
    return managed
  }
  const authorizeTerminal = async (
    secure: ClientSecurePreAuthorizationConnection,
    source: 'DIRECT' | 'RELAY',
    relay?: PeerRelayEndpoint,
    relayStartedAt?: number
  ): Promise<ManagedServerConnection> => {
    if (authorizationStarted) {
      secure.destroy()
      throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    }
    try {
      ensureActive()
      authorizationStarted = true
      setState('AUTHORIZING')
      ensureActive()
      const connection = await authorizeSecureConnection(secure, options.authorization, operationController.signal)
      ensureActive()
      if (relay) {
        options.relaySuccessCache?.recordCryptographicSuccess(
          options.target.serverId,
          relay,
          secure,
          relayStartedAt === undefined ? undefined : readMonotonicMs() - relayStartedAt
        )
      }
      return finish(connection, source, relay?.relayPeerId)
    } catch (cause) {
      secure.destroy()
      if (operationController.signal.aborted) throw abortError()
      if (cause instanceof ConnectivityOrchestrationError) throw cause
      throw new ConnectivityOrchestrationError('CONNECT_TARGET_AUTHORIZATION_FAILED', { cause })
    }
  }

  try {
    ensureActive()
    const descriptors = [...(options.directSources?.descriptors ?? [])]
    if (descriptors.length > MAX_CONNECTIVITY_CANDIDATES) throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID')
    let initialPlan: ServerDialPlan
    try {
      initialPlan = aggregateServerCandidates(planOptions(options, descriptors))
    } catch (cause) {
      throw new ConnectivityOrchestrationError('CONNECT_SECURITY_INVALID', { cause })
    }
    const seenDescriptors = new Set(descriptors.map(descriptorKey))
    const attemptedEndpoints = new Set<string>()

    if (initialPlan.orderedDialTargets.length > 0) {
      setState('DIRECT')
      for (const target of initialPlan.orderedDialTargets) attemptedEndpoints.add(target.endpointKey)
      try {
        const winner = await raceSecureServerConnections({
          plan: initialPlan,
          device: options.device,
          signal: operationController.signal,
          successCache: options.directSources?.candidateSuccessCache,
          overallTimeoutMs: Math.min(directPhaseTimeoutMs, ensureActive(), MAX_DIRECT_PHASE_TIMEOUT_MS),
          nowSeconds: options.nowSeconds,
          monotonicNowMs: readMonotonicMs,
          establishConnection: options.establishDirectConnection
          ,resourceGovernor: subsystem.governor
        })
        return await authorizeTerminal(winner.connection, 'DIRECT')
      } catch (cause) {
        if (operationController.signal.aborted) throw abortError()
        if (!(cause instanceof CandidateRaceError)) throw cause
        const decision = decideConnectivityContinuation({
          failure: classifyConnectivityFailure(cause), phase: 'DIRECT', authorizationStarted
        })
        if (decision !== 'NEXT_DIRECT_SOURCE') throw cause
      }
    }

    ensureActive()
    const peers = options.authorizedPeers ?? []
    const rendezvousPeers = orderPeers(
      peers,
      options.target.serverId,
      options.rendezvousSuccessCache,
      (peer) => isPeerRendezvousEndpoint(peer.rendezvous)
    ).slice(0, MAX_RENDEZVOUS_PEERS_PER_CONNECT)

    if (rendezvousPeers.length > 0) {
      setState('RENDEZVOUS')
      const phaseDeadline = Math.min(overallDeadline, readMonotonicMs() + rendezvousPhaseMs)
      let enrichedRaceUsed = false
      for (const peer of rendezvousPeers) {
        ensureActive()
        const phaseRemaining = Math.floor(phaseDeadline - readMonotonicMs())
        if (phaseRemaining <= 0) break
        try {
          const shareable = await peer.rendezvous!.requestDescriptor(options.target.serverId, {
            timeoutMs: Math.min(3000, phaseRemaining, ensureActive()),
            signal: operationController.signal
          })
          const key = shareable.getDescriptorId().toString('hex')
          if (seenDescriptors.has(key)) continue
          seenDescriptors.add(key)
          const verified = shareable.getVerifiedDescriptor(options.nowSeconds?.())
          const enrichedPlan = aggregateServerCandidates(planOptions(
            options,
            [...descriptors, verified],
            attemptedEndpoints
          ))
          options.rendezvousSuccessCache?.recordDescriptorSuccess(options.target.serverId, peer.rendezvous!, shareable)
          if (enrichedPlan.orderedDialTargets.length === 0) continue
          for (const target of enrichedPlan.orderedDialTargets) attemptedEndpoints.add(target.endpointKey)
          enrichedRaceUsed = true
          setState('DIRECT_ENRICHED')
          try {
            const winner = await raceSecureServerConnections({
              plan: enrichedPlan,
              device: options.device,
              signal: operationController.signal,
              successCache: options.directSources?.candidateSuccessCache,
              overallTimeoutMs: Math.min(directPhaseTimeoutMs, ensureActive(), MAX_DIRECT_PHASE_TIMEOUT_MS),
              nowSeconds: options.nowSeconds,
              monotonicNowMs: readMonotonicMs,
              establishConnection: options.establishDirectConnection
              ,resourceGovernor: subsystem.governor
            })
            return await authorizeTerminal(winner.connection, 'DIRECT')
          } catch (cause) {
            if (operationController.signal.aborted) throw abortError()
            if (!(cause instanceof CandidateRaceError)) throw cause
            const decision = decideConnectivityContinuation({
              failure: classifyConnectivityFailure(cause), phase: 'DIRECT', authorizationStarted
            })
            if (decision !== 'NEXT_DIRECT_SOURCE') throw cause
          }
          break
        } catch (cause) {
          if (operationController.signal.aborted) throw abortError()
          if (cause instanceof ConnectivityOrchestrationError) throw cause
          const decision = decideConnectivityContinuation({
            failure: classifyConnectivityFailure(cause),
            phase: 'RENDEZVOUS',
            authorizationStarted
          })
          if (decision !== 'NEXT_RENDEZVOUS') throw cause
          if (enrichedRaceUsed) break
          continue
        }
      }
    }

    ensureActive()
    setState('RELAY_SELECTION')
    const relayPeers = orderPeers(
      peers,
      options.target.serverId,
      options.relaySuccessCache,
      (peer) => isPeerRelayEndpoint(peer.relay)
    ).slice(0, MAX_RELAY_PEERS_PER_CONNECT)
    const establishRelay = options.establishRelayConnection ?? (async (stream, relayOptions) =>
      establishSecureServerConnectionOverTransport({
        transport: stream,
        expectedServerId: relayOptions.expectedServerId,
        expectedServerPublicKey: relayOptions.expectedServerPublicKey,
        deviceFingerprint: relayOptions.device.fingerprint,
        devicePublicKey: relayOptions.device.publicKey,
        devicePrivateKey: relayOptions.device.privateKey,
        signal: relayOptions.signal
      }))

    for (const peer of relayPeers) {
      ensureActive()
      setState('RELAY_CONNECTING')
      const relayStartedAt = readMonotonicMs()
      let stream: RelayTransportStream | undefined
      let secure: ClientSecurePreAuthorizationConnection | undefined
      let attemptReservation
      const onRelayAbort = (): void => {
        secure?.destroy()
        stream?.destroy()
      }
      operationController.signal.addEventListener('abort', onRelayAbort, { once: true })
      try {
        ensureActive()
        attemptReservation = subsystem.governor.reserve('SECURE_CONNECTION_ATTEMPT')
        stream = await peer.relay!.openCircuit(options.target.serverId, {
          timeoutMs: Math.min(relayOpenTimeoutMs, ensureActive()),
          signal: operationController.signal,
          autoRenew: true
        })
        ensureActive()
        secure = await establishRelay(stream, {
          expectedServerId: options.target.serverId,
          expectedServerPublicKey: options.target.publicKey,
          device: options.device,
          signal: operationController.signal
        })
        if (!isClientSecurePreAuthorizationConnection(secure) || secure.expectedServerId !== options.target.serverId) {
          secure?.destroy()
          stream.destroy()
          continue
        }
        return await authorizeTerminal(secure, 'RELAY', peer.relay!, relayStartedAt)
      } catch (cause) {
        secure?.destroy()
        stream?.destroy()
        if (operationController.signal.aborted) throw abortError()
        if (cause instanceof ConnectivityOrchestrationError) throw cause
        const phase: ConnectivityFailurePhase = 'RELAY'
        const decision = decideConnectivityContinuation({
          failure: classifyConnectivityFailure(cause),
          phase,
          authorizationStarted
        })
        if (decision !== 'NEXT_RELAY') throw cause
        continue
      } finally {
        operationController.signal.removeEventListener('abort', onRelayAbort)
        attemptReservation?.release()
      }
    }

    setState('FAILED')
    throw new ConnectivityOrchestrationError('CONNECT_PATH_UNAVAILABLE')
  } catch (cause) {
    if (!settled) {
      if (operationController.signal.aborted) setState('ABORTED')
      else setState('FAILED')
    }
    if (cause instanceof ConnectivityOrchestrationError) throw cause
    if (operationController.signal.aborted || callerAborted || timedOut) throw abortError()
    throw new ConnectivityOrchestrationError('CONNECT_PATH_UNAVAILABLE', { cause })
  } finally {
    clearTimeout(overallTimer)
    operation.signal.removeEventListener('abort', onOperationAbort)
    operation.finish()
  }
}
