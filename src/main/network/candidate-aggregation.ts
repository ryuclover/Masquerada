import { createHash, createPublicKey } from 'node:crypto'

import {
  ConnectivityCandidateType,
  ConnectivityDescriptorError,
  MAX_CONNECTIVITY_CANDIDATES,
  verifySignedConnectivityDescriptor,
  type ConnectivityCandidate,
  type VerifiedConnectivityDescriptor
} from './connectivity-descriptor'
import {
  isLegitimateDiscoveredLanServer,
  type DiscoveredLanServer
} from './lan-discovery'
import { classifyNetworkAddress } from './network-interfaces'
import {
  isLegitimateValidatedStunObservation,
  type ValidatedStunObservation
} from './stun-observation'
import {
  isNetworkEnvironmentGeneration,
  sameNetworkGeneration,
  type NetworkEnvironmentGeneration
} from './network-environment'
import {
  isClientSecurePreAuthorizationConnection,
  type ClientSecurePreAuthorizationConnection
} from './tcp-transport'

export const RECENT_SUCCESS_TTL_MS = 10 * 60 * 1000
export const MAX_RECENT_SUCCESS_ENTRIES = 64
export const MAX_CANDIDATE_SOURCES = 32

export type CandidateAggregationErrorCode =
  | 'CANDIDATE_PLAN_INVALID'
  | 'CANDIDATE_SERVER_MISMATCH'
  | 'CANDIDATE_MAX_ENDPOINTS_EXCEEDED'

export class CandidateAggregationError extends Error {
  constructor(readonly code: CandidateAggregationErrorCode) {
    super(code)
    this.name = 'CandidateAggregationError'
  }
}

export type DialTargetProvenance = 'LAN_DISCOVERY' | 'SIGNED_WAN_DESCRIPTOR'

export interface DialTarget {
  readonly family: 4 | 6
  readonly address: string
  readonly port: number
  readonly scopeId?: number
  readonly endpointKey: string
  readonly provenance: DialTargetProvenance
  readonly origins: readonly ConnectivityCandidateType[]
  readonly descriptorExpiresAt: number
  readonly recentCryptographicSuccess: boolean
}

const DIAL_PLAN_TOKEN = Symbol('ServerDialPlan')
const legitimatePlans = new WeakSet<object>()

export class ServerDialPlan {
  readonly expectedServerId: string
  readonly orderedDialTargets: readonly DialTarget[]
  private readonly publicKey: Buffer

  constructor(
    token: symbol,
    expectedServerId: string,
    expectedServerPublicKey: Buffer,
    orderedDialTargets: readonly DialTarget[]
  ) {
    if (token !== DIAL_PLAN_TOKEN) throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
    this.expectedServerId = expectedServerId
    this.publicKey = Buffer.from(expectedServerPublicKey)
    this.orderedDialTargets = Object.freeze([...orderedDialTargets])
    legitimatePlans.add(this)
    Object.freeze(this)
  }

  getExpectedServerPublicKey(): Buffer {
    return Buffer.from(this.publicKey)
  }
}

export function isLegitimateServerDialPlan(value: unknown): value is ServerDialPlan {
  return typeof value === 'object' && value !== null && legitimatePlans.has(value)
}

interface SuccessHint {
  readonly serverId: string
  readonly endpointKey: string
  readonly succeededAtMs: number
  readonly establishmentLatencyMs?: number
}

/** Bounded in-memory LRU. It influences ordering only and is never persisted. */
export class EphemeralCandidateSuccessCache {
  private readonly entries = new Map<string, SuccessHint>()

  constructor(
    private readonly monotonicNowMs: () => number = () => performance.now(),
    private readonly ttlMs = RECENT_SUCCESS_TTL_MS,
    private readonly maxEntries = MAX_RECENT_SUCCESS_ENTRIES
  ) {
    if (ttlMs <= 0 || ttlMs > RECENT_SUCCESS_TTL_MS || maxEntries < 1 || maxEntries > MAX_RECENT_SUCCESS_ENTRIES) {
      throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
    }
  }

  recordCryptographicSuccess(
    serverId: string,
    endpointKey: string,
    connection: ClientSecurePreAuthorizationConnection,
    establishmentLatencyMs?: number
  ): void {
    if (
      !isClientSecurePreAuthorizationConnection(connection) ||
      connection.expectedServerId !== serverId ||
      connection.isDestroyed()
    ) {
      throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
    }
    const key = `${serverId}\u0000${endpointKey}`
    this.entries.delete(key)
    this.entries.set(key, Object.freeze({
      serverId,
      endpointKey,
      succeededAtMs: this.monotonicNowMs(),
      establishmentLatencyMs
    }))
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined
      if (oldest === undefined) break
      this.entries.delete(oldest)
    }
  }

  hasFresh(serverId: string, endpointKey: string): boolean {
    const key = `${serverId}\u0000${endpointKey}`
    const entry = this.entries.get(key)
    if (!entry) return false
    const elapsed = this.monotonicNowMs() - entry.succeededAtMs
    if (elapsed < 0 || elapsed >= this.ttlMs) {
      this.entries.delete(key)
      return false
    }
    this.entries.delete(key)
    this.entries.set(key, entry)
    return true
  }

  get size(): number {
    return this.entries.size
  }
}

export interface AggregateCandidateSourcesOptions {
  readonly expectedServerId: string
  readonly expectedServerPublicKey: Buffer
  readonly descriptors?: readonly VerifiedConnectivityDescriptor[]
  readonly lanDiscoveries?: readonly DiscoveredLanServer[]
  readonly successCache?: EphemeralCandidateSuccessCache
  readonly localStunObservation?: ValidatedStunObservation
  readonly nowSeconds?: number
  /** Operation-local suppression used to avoid reracing endpoints already exhausted. */
  readonly excludeEndpointKeys?: ReadonlySet<string>
  readonly networkGeneration?: NetworkEnvironmentGeneration
}

interface MutableTarget {
  family: 4 | 6
  address: string
  port: number
  scopeId?: number
  endpointKey: string
  provenance: DialTargetProvenance
  origins: Set<ConnectivityCandidateType>
  descriptorExpiresAt: number
}

export function dialEndpointKey(endpoint: {
  readonly family: 4 | 6
  readonly address: string
  readonly port: number
  readonly scopeId?: number
}): string {
  return `${endpoint.family}|${endpoint.address}|${endpoint.port}|${endpoint.scopeId ?? ''}`
}

function assertServerBinding(
  serverId: string,
  serverPublicKey: Buffer,
  expectedServerId: string,
  expectedServerPublicKey: Buffer
): void {
  if (
    serverId !== expectedServerId ||
    !Buffer.isBuffer(serverPublicKey) ||
    !serverPublicKey.equals(expectedServerPublicKey)
  ) {
    throw new CandidateAggregationError('CANDIDATE_SERVER_MISMATCH')
  }
}

function isEligibleWan(candidate: ConnectivityCandidate): boolean {
  const classification = classifyNetworkAddress(candidate.address)
  if (
    candidate.address.includes('%') ||
    classification.normalizedAddress !== candidate.address ||
    !classification.isGloballyRoutableWan ||
    candidate.port < 1 || candidate.port > 65535
  ) return false
  if (candidate.candidateType === ConnectivityCandidateType.PORT_MAPPED_TCP) {
    return classification.family === (candidate.family === 4 ? 'IPv4' : 'IPv6')
  }
  return candidate.candidateType === ConnectivityCandidateType.DIRECT_GLOBAL_TCP &&
    candidate.family === 6 && classification.family === 'IPv6'
}

function interleaveFamilies(targets: MutableTarget[], preferredFamily: 4 | 6): MutableTarget[] {
  const sorted = [...targets].sort((a, b) => a.endpointKey.localeCompare(b.endpointKey))
  const preferred = sorted.filter((target) => target.family === preferredFamily)
  const other = sorted.filter((target) => target.family !== preferredFamily)
  const result: MutableTarget[] = []
  while (preferred.length > 0 || other.length > 0) {
    const first = preferred.shift()
    if (first) result.push(first)
    const second = other.shift()
    if (second) result.push(second)
  }
  return result
}

function orderTargets(
  targets: MutableTarget[],
  expectedServerId: string,
  cache: EphemeralCandidateSuccessCache | undefined,
  stun: ValidatedStunObservation | undefined,
  networkGeneration: NetworkEnvironmentGeneration | undefined
): DialTarget[] {
  const preferredFamily: 4 | 6 = stun &&
    isLegitimateValidatedStunObservation(stun) &&
    (networkGeneration === undefined || sameNetworkGeneration(stun.networkGeneration, networkGeneration)) &&
    stun.isFresh()
    ? stun.family
    : 6
  const groups: MutableTarget[][] = [[], [], [], []]
  for (const target of targets) {
    const recent = cache?.hasFresh(expectedServerId, target.endpointKey) === true
    const rank = target.provenance === 'LAN_DISCOVERY'
      ? 0
      : recent
        ? 1
        : target.origins.has(ConnectivityCandidateType.DIRECT_GLOBAL_TCP)
          ? 2
          : 3
    groups[rank]!.push(target)
  }
  return groups.flatMap((group) => interleaveFamilies(group, preferredFamily)).map((target) => Object.freeze({
    family: target.family,
    address: target.address,
    port: target.port,
    ...(target.scopeId === undefined ? {} : { scopeId: target.scopeId }),
    endpointKey: target.endpointKey,
    provenance: target.provenance,
    origins: Object.freeze([...target.origins].sort((a, b) => a - b)),
    descriptorExpiresAt: target.descriptorExpiresAt,
    recentCryptographicSuccess: cache?.hasFresh(expectedServerId, target.endpointKey) === true
  }))
}

/** Pure aggregation: validates, applies provenance, deduplicates and orders without socket I/O. */
export function aggregateServerCandidates(options: AggregateCandidateSourcesOptions): ServerDialPlan {
  const descriptors = options.descriptors ?? []
  const discoveries = options.lanDiscoveries ?? []
  if (
    !Array.isArray(descriptors) || !Array.isArray(discoveries) ||
    descriptors.length + discoveries.length > MAX_CANDIDATE_SOURCES ||
    !Buffer.isBuffer(options.expectedServerPublicKey) ||
    (options.excludeEndpointKeys !== undefined && (!(options.excludeEndpointKeys instanceof Set) || options.excludeEndpointKeys.size > MAX_CONNECTIVITY_CANDIDATES))
  ) throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
  if (options.networkGeneration !== undefined && !isNetworkEnvironmentGeneration(options.networkGeneration)) {
    throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
  }

  const derivedId = `sha256:${createHash('sha256').update(options.expectedServerPublicKey).digest('hex')}`
  if (derivedId !== options.expectedServerId) {
    throw new CandidateAggregationError('CANDIDATE_SERVER_MISMATCH')
  }
  try {
    const key = createPublicKey({ key: options.expectedServerPublicKey, format: 'der', type: 'spki' })
    const canonical = Buffer.from(key.export({ format: 'der', type: 'spki' }))
    if (key.asymmetricKeyType !== 'ed25519' || !canonical.equals(options.expectedServerPublicKey)) {
      throw new Error('non-canonical Server Identity key')
    }
  } catch {
    throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
  }
  for (const source of [...descriptors, ...discoveries.map((entry) => entry?.descriptor)]) {
    if (!source || typeof source !== 'object') throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
    assertServerBinding(source.serverId, source.serverPublicKey, options.expectedServerId, options.expectedServerPublicKey)
  }
  for (const discovery of discoveries) {
    if (options.networkGeneration !== undefined && !sameNetworkGeneration(discovery.networkGeneration, options.networkGeneration)) continue
    if (!isLegitimateDiscoveredLanServer(discovery)) {
      throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
    }
  }

  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000)
  const targets = new Map<string, MutableTarget>()
  const add = (candidate: ConnectivityCandidate, expiresAt: number, provenance: DialTargetProvenance, scopeId?: number): void => {
    const classification = classifyNetworkAddress(candidate.address, scopeId)
    const address = classification.normalizedAddress
    const endpointKey = dialEndpointKey({ family: candidate.family, address, port: candidate.port, scopeId })
    const existing = targets.get(endpointKey)
    if (existing) {
      existing.origins.add(candidate.candidateType)
      existing.descriptorExpiresAt = Math.max(existing.descriptorExpiresAt, expiresAt)
      if (provenance === 'LAN_DISCOVERY') existing.provenance = provenance
      return
    }
    targets.set(endpointKey, {
      family: candidate.family,
      address,
      port: candidate.port,
      ...(scopeId === undefined ? {} : { scopeId }),
      endpointKey,
      provenance,
      origins: new Set([candidate.candidateType]),
      descriptorExpiresAt: expiresAt
    })
  }

  const reverify = (descriptor: VerifiedConnectivityDescriptor): VerifiedConnectivityDescriptor | null => {
    try {
      return verifySignedConnectivityDescriptor({
        encodedDescriptor: descriptor.rawEncoded,
        expectedServerId: options.expectedServerId,
        nowSeconds,
        allowLoopbackForTesting: true
      })
    } catch (error) {
      if (error instanceof ConnectivityDescriptorError && error.code === 'DESCRIPTOR_EXPIRED') return null
      throw new CandidateAggregationError('CANDIDATE_PLAN_INVALID')
    }
  }

  for (const descriptor of descriptors) {
    const verified = reverify(descriptor)
    if (!verified) continue
    assertServerBinding(verified.serverId, verified.serverPublicKey, options.expectedServerId, options.expectedServerPublicKey)
    for (const candidate of verified.candidates) {
      if (candidate.candidateType !== ConnectivityCandidateType.LAN_TCP && isEligibleWan(candidate)) {
        add(candidate, verified.expiresAt, 'SIGNED_WAN_DESCRIPTOR')
      }
    }
  }

  for (const discovery of discoveries) {
    if (options.networkGeneration !== undefined && !sameNetworkGeneration(discovery.networkGeneration, options.networkGeneration)) continue
    const verified = reverify(discovery.descriptor)
    if (!verified) continue
    const endpointKeys = new Map(discovery.endpoints.map((endpoint: DiscoveredLanServer['endpoints'][number]) => [
      dialEndpointKey(endpoint),
      endpoint
    ]))
    for (const candidate of verified.candidates) {
      if (candidate.candidateType !== ConnectivityCandidateType.LAN_TCP) continue
      const classification = classifyNetworkAddress(candidate.address)
      if (classification.scope === 'LOOPBACK' && !discovery.allowLoopbackForTesting) continue
      if (candidate.address !== discovery.responseSourceAddress) continue
      const scopeId = candidate.family === 6 && candidate.scope === 'LINK_LOCAL'
        ? discovery.endpoints.find((endpoint: DiscoveredLanServer['endpoints'][number]) => endpoint.address === candidate.address && endpoint.port === candidate.port)?.scopeId
        : undefined
      if (candidate.family === 6 && candidate.scope === 'LINK_LOCAL' && scopeId === undefined) continue
      const key = dialEndpointKey({ family: candidate.family, address: candidate.address, port: candidate.port, scopeId })
      if (!endpointKeys.has(key)) continue
      add(candidate, verified.expiresAt, 'LAN_DISCOVERY', scopeId)
    }
  }

  if (targets.size > MAX_CONNECTIVITY_CANDIDATES) {
    throw new CandidateAggregationError('CANDIDATE_MAX_ENDPOINTS_EXCEEDED')
  }
  const ordered = orderTargets(
    [...targets.values()],
    options.expectedServerId,
    options.successCache,
    options.localStunObservation,
    options.networkGeneration
  )
    .filter((target) => !options.excludeEndpointKeys?.has(target.endpointKey))
  return new ServerDialPlan(
    DIAL_PLAN_TOKEN,
    options.expectedServerId,
    options.expectedServerPublicKey,
    ordered
  )
}
