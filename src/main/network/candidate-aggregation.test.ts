import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { createSocket, type Socket } from 'node:dgram'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  aggregateServerCandidates,
  CandidateAggregationError,
  dialEndpointKey,
  EphemeralCandidateSuccessCache,
  MAX_RECENT_SUCCESS_ENTRIES,
  RECENT_SUCCESS_TTL_MS
} from './candidate-aggregation'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  type ConnectivityCandidate,
  type VerifiedConnectivityDescriptor
} from './connectivity-descriptor'
import {
  discoverLanServer,
  encodeDiscoveryResponse,
  parseDiscoveryQuery,
  type DiscoveredLanServer
} from './lan-discovery'
import { stunObservationTestOnly } from './stun-observation'
import { tcpTransportTestOnly } from './tcp-transport'
import { NetworkEnvironmentTracker } from './network-environment'
import type { NetworkInterfaceInfo } from 'node:os'

interface Identity {
  serverId: string
  publicKey: Buffer
  privateKey: KeyObject
}

const NOW = 2_000_000_000

function identity(): Identity {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    serverId: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

function descriptor(id: Identity, candidates: readonly ConnectivityCandidate[], issuedAt = NOW): VerifiedConnectivityDescriptor {
  const raw = createSignedConnectivityDescriptor({
    serverId: id.serverId,
    serverPublicKey: id.publicKey,
    serverPrivateKey: id.privateKey,
    candidates,
    customIssuedAt: issuedAt,
    lifetimeSeconds: 300,
    allowRawCandidatesForTesting: true,
    allowLoopbackForTesting: true
  })
  return verifySignedConnectivityDescriptor({
    encodedDescriptor: raw,
    expectedServerId: id.serverId,
    nowSeconds: issuedAt,
    allowLoopbackForTesting: true
  })
}

const mapped = (address: string, port: number, family: 4 | 6 = 4): ConnectivityCandidate => ({
  candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
  family,
  address,
  port
})
const direct = (address: string, port: number): ConnectivityCandidate => ({
  candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
  family: 6,
  address,
  port
})
const lan = (address: string, port: number, scope: 'LAN_PRIVATE' | 'LINK_LOCAL' | 'LOOPBACK' = 'LAN_PRIVATE'): ConnectivityCandidate => ({
  candidateType: ConnectivityCandidateType.LAN_TCP,
  family: address.includes(':') ? 6 : 4,
  address,
  port,
  scope
})

async function discoveryFixture(id: Identity, candidates: readonly ConnectivityCandidate[]): Promise<{
  discovery: DiscoveredLanServer
  socket: Socket
}> {
  const signed = createSignedConnectivityDescriptor({
    serverId: id.serverId,
    serverPublicKey: id.publicKey,
    serverPrivateKey: id.privateKey,
    candidates,
    lifetimeSeconds: 300,
    allowRawCandidatesForTesting: true,
    allowLoopbackForTesting: true
  })
  const socket = createSocket('udp4')
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve))
  const port = socket.address().port
  socket.on('message', (message, source) => {
    const query = parseDiscoveryQuery(message)
    if (!query) return
    socket.send(encodeDiscoveryResponse(query.queryNonce, id.serverId, id.privateKey, signed), source.port, source.address)
  })
  const discovery = await discoverLanServer({
    expectedServerId: id.serverId,
    localInterfaceAddress: '127.0.0.1',
    targetUnicastAddress: '127.0.0.1',
    port,
    timeoutMs: 1000,
    allowLoopbackForTesting: true
  })
  return { discovery, socket }
}

describe('candidate aggregation, provenance and eligibility', () => {
  const server = identity()
  let discovered: DiscoveredLanServer
  let discoverySocket: Socket

  beforeAll(async () => {
    const fixture = await discoveryFixture(server, [lan('127.0.0.1', 41001, 'LOOPBACK')])
    discovered = fixture.discovery
    discoverySocket = fixture.socket
  })

  afterAll(() => discoverySocket.close())

  const plan = (descriptors: readonly VerifiedConnectivityDescriptor[] = [], extra: Record<string, unknown> = {}) =>
    aggregateServerCandidates({
      expectedServerId: server.serverId,
      expectedServerPublicKey: server.publicKey,
      descriptors,
      nowSeconds: NOW,
      ...extra
    })

  it('ignores generic signed LAN and loopback candidates, preventing LAN/localhost SSRF', () => {
    const result = plan([
      descriptor(server, [lan('192.168.1.1', 80)]),
      descriptor(server, [lan('127.0.0.1', 22, 'LOOPBACK')])
    ])
    expect(result.orderedDialTargets).toHaveLength(0)
  })

  it('accepts only runtime provenance from targeted authenticated LAN discovery', () => {
    const result = plan([], { lanDiscoveries: [discovered], nowSeconds: Math.floor(Date.now() / 1000) })
    expect(result.orderedDialTargets).toMatchObject([{
      address: '127.0.0.1',
      port: 41001,
      provenance: 'LAN_DISCOVERY'
    }])
    expect(() => plan([], { lanDiscoveries: [{ ...discovered }] })).toThrowError(CandidateAggregationError)
  })

  it('rejects mixed server IDs and inconsistent public-key binding before dialing', () => {
    const other = identity()
    expect(() => plan([descriptor(other, [mapped('8.8.8.8', 4000)])])).toThrowError(
      expect.objectContaining({ code: 'CANDIDATE_SERVER_MISMATCH' })
    )
    expect(() => aggregateServerCandidates({
      expectedServerId: server.serverId,
      expectedServerPublicKey: other.publicKey,
      descriptors: []
    })).toThrowError(expect.objectContaining({ code: 'CANDIDATE_SERVER_MISMATCH' }))
  })

  it('revalidates strict-global PORT_MAPPED_TCP and IPv6-only DIRECT_GLOBAL_TCP', () => {
    const result = plan([descriptor(server, [
      mapped('8.8.8.8', 45000),
      direct('2606:4700:4700::1111', 45001)
    ])])
    expect(result.orderedDialTargets).toHaveLength(2)
    expect(result.orderedDialTargets[0]!.origins).toContain(ConnectivityCandidateType.DIRECT_GLOBAL_TCP)
    expect(result.orderedDialTargets[1]!.origins).toContain(ConnectivityCandidateType.PORT_MAPPED_TCP)
  })

  it('uses only fresh sources and permits a fresh source when another has expired', () => {
    const expired = descriptor(server, [mapped('8.8.4.4', 4400)], NOW - 400)
    const fresh = descriptor(server, [mapped('8.8.8.8', 4401)], NOW)
    const result = plan([expired, fresh])
    expect(result.orderedDialTargets.map((target) => target.address)).toEqual(['8.8.8.8'])
  })

  it('deduplicates the same socket endpoint across candidate types and preserves origins', () => {
    const address = '2606:4700:4700::1111'
    const result = plan([descriptor(server, [mapped(address, 45000, 6), direct(address, 45000)])])
    expect(result.orderedDialTargets).toHaveLength(1)
    expect(result.orderedDialTargets[0]!.origins).toEqual([
      ConnectivityCandidateType.PORT_MAPPED_TCP,
      ConnectivityCandidateType.DIRECT_GLOBAL_TCP
    ])
  })

  it('uses scope in link-local endpoint identity', () => {
    expect(dialEndpointKey({ family: 6, address: 'fe80::1', port: 4000, scopeId: 3 })).not.toBe(
      dialEndpointKey({ family: 6, address: 'fe80::1', port: 4000, scopeId: 4 })
    )
    expect(plan([descriptor(server, [lan('fe80::1', 4000, 'LINK_LOCAL')])]).orderedDialTargets).toHaveLength(0)
  })

  it('is deterministic across input order and interleaves IPv6/IPv4 within a class', () => {
    const a = descriptor(server, [mapped('8.8.8.8', 4001), mapped('2606:4700::1', 4001, 6)])
    const b = descriptor(server, [mapped('1.1.1.1', 4002), mapped('2606:4700::2', 4002, 6)])
    const first = plan([a, b]).orderedDialTargets
    const second = plan([b, a]).orderedDialTargets
    expect(first.map((target) => target.endpointKey)).toEqual(second.map((target) => target.endpointKey))
    expect(first.map((target) => target.family)).toEqual([6, 4, 6, 4])
  })

  it('keeps proven LAN first and allows fresh STUN only to break the family tie', () => {
    let monotonic = 0
    const stun = stunObservationTestOnly.createObservation({
      localAddress: '192.168.1.10', localPort: 50000,
      observedAddress: '8.8.8.8', observedPort: 50000,
      family: 4, observedScope: 'GLOBAL', serverAddress: '1.1.1.1', serverPort: 3478
    }, () => monotonic, () => NOW)
    const wan = descriptor(server, [mapped('8.8.8.8', 5000), mapped('2606:4700::1', 5000, 6)])
    const result = plan([wan], {
      lanDiscoveries: [discovered],
      localStunObservation: stun,
      nowSeconds: Math.floor(Date.now() / 1000)
    })
    expect(result.orderedDialTargets[0]!.provenance).toBe('LAN_DISCOVERY')
    expect(result.orderedDialTargets.slice(1).map((target) => target.family)).toEqual([4, 6])
    monotonic = 31_000
    expect(plan([wan], { localStunObservation: stun }).orderedDialTargets.map((target) => target.family)).toEqual([6, 4])
  })

  it('drops prior-generation STUN/LAN provenance while fresh WAN descriptors survive local change', () => {
    let address = '192.168.1.10'
    const provider = () => ({ Ethernet: [{
      address, family: 'IPv4', internal: false, netmask: '255.255.255.0', cidr: `${address}/24`,
      mac: '00:11:22:33:44:55'
    } as NetworkInterfaceInfo] })
    const tracker = new NetworkEnvironmentTracker(provider)
    const first = tracker.snapshot()
    const stun = stunObservationTestOnly.createObservation({
      localAddress: address, localPort: 50000, observedAddress: '8.8.8.8', observedPort: 50000,
      family: 4, observedScope: 'GLOBAL', serverAddress: '1.1.1.1', serverPort: 3478
    }, () => 0, () => NOW, first)
    address = '192.168.1.11'
    const second = tracker.refresh()
    const wan = descriptor(server, [mapped('8.8.8.8', 5000), mapped('2606:4700::1', 5000, 6)])
    const result = plan([wan], {
      lanDiscoveries: [discovered],
      localStunObservation: stun,
      networkGeneration: second,
      nowSeconds: Math.floor(Date.now() / 1000)
    })
    expect(result.orderedDialTargets.map((target) => target.provenance)).toEqual([
      'SIGNED_WAN_DESCRIPTOR', 'SIGNED_WAN_DESCRIPTOR'
    ])
    expect(result.orderedDialTargets.map((target) => target.family)).toEqual([6, 4])
  })

  it('recent cryptographic success is server-bound, expiring, bounded, and cannot create a target', () => {
    let now = 0
    const cache = new EphemeralCandidateSuccessCache(() => now)
    const firstKey = dialEndpointKey({ family: 4, address: '8.8.8.8', port: 5001 })
    const secureConnection = tcpTransportTestOnly.createSecurePreAuthorizationConnection({
      expectedServerId: server.serverId
    })
    cache.recordCryptographicSuccess(server.serverId, firstKey, secureConnection, 12)
    expect(() => cache.recordCryptographicSuccess(identity().serverId, firstKey, secureConnection)).toThrowError(
      expect.objectContaining({ code: 'CANDIDATE_PLAN_INVALID' })
    )
    const candidates = descriptor(server, [mapped('1.1.1.1', 5002), mapped('8.8.8.8', 5001)])
    expect(plan([candidates], { successCache: cache }).orderedDialTargets[0]!.address).toBe('8.8.8.8')
    expect(plan([], { successCache: cache }).orderedDialTargets).toHaveLength(0)
    expect(cache.hasFresh(identity().serverId, firstKey)).toBe(false)
    now = RECENT_SUCCESS_TTL_MS
    expect(plan([candidates], { successCache: cache }).orderedDialTargets[0]!.address).toBe('1.1.1.1')
    for (let index = 0; index < MAX_RECENT_SUCCESS_ENTRIES + 10; index++) {
      cache.recordCryptographicSuccess(server.serverId, `key-${index}`, secureConnection)
    }
    expect(cache.size).toBe(MAX_RECENT_SUCCESS_ENTRIES)
  })

  it('rejects more than 16 unique aggregated endpoints instead of silently dropping', () => {
    const candidates = Array.from({ length: 16 }, (_, index) => mapped(`11.0.0.${index + 1}`, 5000 + index))
    const extra = descriptor(server, [mapped('12.0.0.1', 6000)])
    expect(() => plan([descriptor(server, candidates), extra])).toThrowError(
      expect.objectContaining({ code: 'CANDIDATE_MAX_ENDPOINTS_EXCEEDED' })
    )
  })

  it('bounds huge/fake inputs and keeps ServerDialPlan non-forgeable', () => {
    expect(() => aggregateServerCandidates({
      expectedServerId: server.serverId,
      expectedServerPublicKey: server.publicKey,
      descriptors: Array.from({ length: 33 }, () => descriptor(server, [mapped('8.8.8.8', 5000)]))
    })).toThrowError(expect.objectContaining({ code: 'CANDIDATE_PLAN_INVALID' }))
  })
})

describe('LAN response source binding', () => {
  it('does not mint dial provenance when response source and advertised candidate differ', async () => {
    const server = identity()
    const signed = createSignedConnectivityDescriptor({
      serverId: server.serverId,
      serverPublicKey: server.publicKey,
      serverPrivateKey: server.privateKey,
      candidates: [lan('127.0.0.2', 41000, 'LOOPBACK')],
      allowRawCandidatesForTesting: true,
      allowLoopbackForTesting: true
    })
    const socket = createSocket('udp4')
    await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve))
    socket.on('message', (message, source) => {
      const query = parseDiscoveryQuery(message)
      if (query) socket.send(encodeDiscoveryResponse(query.queryNonce, server.serverId, server.privateKey, signed), source.port, source.address)
    })
    await expect(discoverLanServer({
      expectedServerId: server.serverId,
      localInterfaceAddress: '127.0.0.1',
      targetUnicastAddress: '127.0.0.1',
      port: socket.address().port,
      timeoutMs: 50,
      allowLoopbackForTesting: true
    })).rejects.toMatchObject({ code: 'DISCOVERY_TIMEOUT' })
    socket.close()
  })
})
