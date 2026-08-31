import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'

import {
  connectToServer,
  ConnectivityOrchestrationError,
  EphemeralRelaySuccessCache,
  isManagedServerConnection
} from './connectivity-orchestrator'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor
} from './connectivity-descriptor'
import { createPeerRelayEndpoint, createPeerRelayService } from './peer-relay'
import {
  createPeerRendezvousEndpoint,
  markRendezvousShareable,
  RendezvousDescriptorStore
} from './peer-rendezvous'
import { tcpTransportTestOnly } from './tcp-transport'
import { ConnectivitySubsystem } from './connectivity-subsystem'
import { CandidateRaceError } from './candidate-racing'
import {
  ConnectivityResourceGovernor,
  MAX_PENDING_SECURE_CONNECTION_ATTEMPTS
} from './connectivity-resource-governor'

const NOW = 2_000_000_000

function identity(): { serverId: string; publicKey: Buffer; privateKey: KeyObject } {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    serverId: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

const target = identity()
const deviceIdentity = identity()
const device = {
  fingerprint: deviceIdentity.serverId,
  publicKey: deviceIdentity.publicKey,
  privateKey: deviceIdentity.privateKey
}

function descriptor(address = '8.8.8.8', port = 45000) {
  return verifySignedConnectivityDescriptor({
    encodedDescriptor: createSignedConnectivityDescriptor({
      serverId: target.serverId,
      serverPublicKey: target.publicKey,
      serverPrivateKey: target.privateKey,
      candidates: [{ candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP, family: 4, address, port }],
      customIssuedAt: NOW,
      lifetimeSeconds: 300,
      allowRawCandidatesForTesting: true
    }),
    expectedServerId: target.serverId,
    nowSeconds: NOW
  })
}

function base() {
  return {
    target: { serverId: target.serverId, publicKey: target.publicKey },
    device,
    authorization: { mode: 'admission' as const, invite: 'MQR1-test' },
    nowSeconds: () => NOW
  }
}

async function relayPath() {
  const relay = identity()
  const targetDevice = identity().serverId
  const requesterDevice = identity().serverId
  const connect = (deviceFingerprint: string) => {
    const delivery: { client?: (bytes: Buffer) => Promise<void>; server?: (bytes: Buffer) => Promise<void> } = {}
    const client = tcpTransportTestOnly.createAuthorizedPeerChannel({
      serverId: relay.serverId,
      peerDeviceFingerprint: deviceFingerprint,
      onSend: async (bytes) => delivery.server!(bytes)
    })
    const server = tcpTransportTestOnly.createAuthorizedPeerChannel({
      serverId: relay.serverId,
      peerDeviceFingerprint: deviceFingerprint,
      onSend: async (bytes) => delivery.client!(bytes)
    })
    delivery.client = client.deliver
    delivery.server = server.deliver
    return { client: client.channel, server: server.channel }
  }
  const targetChannels = connect(targetDevice)
  const requesterChannels = connect(requesterDevice)
  const service = createPeerRelayService({ relayServerId: relay.serverId })
  createPeerRelayEndpoint({ channel: targetChannels.server, service })
  createPeerRelayEndpoint({ channel: requesterChannels.server, service })
  const targetEndpoint = createPeerRelayEndpoint({ channel: targetChannels.client })
  const requesterEndpoint = createPeerRelayEndpoint({ channel: requesterChannels.client })
  const registration = await targetEndpoint.registerTarget({
    targetServerId: target.serverId,
    targetServerPublicKey: target.publicKey,
    targetServerPrivateKey: target.privateKey,
    relayServerId: relay.serverId,
    outerDeviceFingerprint: targetDevice,
    onIncomingCircuit: (stream) => { stream.resume() }
  })
  return { relay, requesterEndpoint, registration }
}

function unavailableRelayPath() {
  const relay = identity()
  const deviceFingerprint = identity().serverId
  const delivery: { client?: (bytes: Buffer) => Promise<void>; server?: (bytes: Buffer) => Promise<void> } = {}
  const client = tcpTransportTestOnly.createAuthorizedPeerChannel({
    serverId: relay.serverId,
    peerDeviceFingerprint: deviceFingerprint,
    onSend: async (bytes) => delivery.server!(bytes)
  })
  const server = tcpTransportTestOnly.createAuthorizedPeerChannel({
    serverId: relay.serverId,
    peerDeviceFingerprint: deviceFingerprint,
    onSend: async (bytes) => delivery.client!(bytes)
  })
  delivery.client = client.deliver
  delivery.server = server.deliver
  const service = createPeerRelayService({ relayServerId: relay.serverId })
  createPeerRelayEndpoint({ channel: server.channel, service })
  return createPeerRelayEndpoint({ channel: client.channel })
}

function rendezvousPath() {
  const peer = identity()
  const delivery: { requester?: (bytes: Buffer) => Promise<void>; responder?: (bytes: Buffer) => Promise<void> } = {}
  const requester = tcpTransportTestOnly.createAuthorizedPeerChannel({
    serverId: peer.serverId,
    peerDeviceFingerprint: identity().serverId,
    onSend: async (bytes) => delivery.responder!(bytes)
  })
  const responder = tcpTransportTestOnly.createAuthorizedPeerChannel({
    serverId: peer.serverId,
    peerDeviceFingerprint: identity().serverId,
    onSend: async (bytes) => delivery.requester!(bytes)
  })
  delivery.requester = requester.deliver
  delivery.responder = responder.deliver
  const store = new RendezvousDescriptorStore(() => NOW)
  store.put(markRendezvousShareable(descriptor(), NOW))
  createPeerRendezvousEndpoint({ channel: responder.channel, store })
  return createPeerRendezvousEndpoint({ channel: requester.channel })
}

describe('unified connectivity orchestrator', () => {
  it('uses direct first and performs authorization exactly once on the cryptographic winner', async () => {
    const states: string[] = []
    const authorizations: string[] = []
    let attempts = 0
    const result = await connectToServer({
      ...base(),
      directSources: { descriptors: [descriptor()] },
      onStateChange: (state) => states.push(state),
      establishDirectConnection: async () => {
        attempts += 1
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({
          expectedServerId: target.serverId,
          onAuthorize: async (mode, invite) => {
            authorizations.push(`${mode}:${invite}`)
            return { status: 'admitted' }
          }
        })
      }
    })
    expect(isManagedServerConnection(result)).toBe(true)
    expect(result.source).toBe('DIRECT')
    expect(attempts).toBe(1)
    expect(authorizations).toEqual(['admission:MQR1-test'])
    expect(states).toEqual(['DIRECT', 'AUTHORIZING', 'CONNECTED'])
    result.destroy()
  })

  it('treats authorization rejection as terminal and never attempts another direct endpoint', async () => {
    let attempts = 0
    let authorizations = 0
    await expect(connectToServer({
      ...base(),
      directSources: { descriptors: [descriptor('8.8.8.8', 1), descriptor('1.1.1.1', 2)] },
      establishDirectConnection: async () => {
        attempts += 1
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({
          expectedServerId: target.serverId,
          onAuthorize: async () => {
            authorizations += 1
            throw new Error('private rejection detail')
          }
        })
      }
    })).rejects.toMatchObject({ code: 'CONNECT_TARGET_AUTHORIZATION_FAILED' })
    expect(attempts).toBe(1)
    expect(authorizations).toBe(1)
  })

  it('returns one bounded error after exhausting an empty direct/rendezvous/relay plan', async () => {
    await expect(connectToServer(base())).rejects.toEqual(
      expect.objectContaining({ code: 'CONNECT_PATH_UNAVAILABLE', message: 'CONNECT_PATH_UNAVAILABLE' })
    )
  })

  it('falls back from exhausted direct reachability to one explicit relay and authenticates the same target', async () => {
    const relay = await relayPath()
    const states: string[] = []
    let directAttempts = 0
    let relayHandshakes = 0
    let authorizations = 0
    const result = await connectToServer({
      ...base(),
      directSources: { descriptors: [descriptor()] },
      authorizedPeers: [{ relay: relay.requesterEndpoint }],
      onStateChange: (state) => states.push(state),
      establishDirectConnection: async () => {
        directAttempts += 1
        throw new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED')
      },
      establishRelayConnection: async (_stream, options) => {
        relayHandshakes += 1
        expect(options.expectedServerId).toBe(target.serverId)
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({
          expectedServerId: target.serverId,
          onAuthorize: async () => {
            authorizations += 1
            return { status: 'admitted' }
          }
        })
      }
    })
    expect(result.source).toBe('RELAY')
    expect(result.relayPeerId).toBe(relay.relay.serverId)
    expect(directAttempts).toBe(1)
    expect(relayHandshakes).toBe(1)
    expect(authorizations).toBe(1)
    expect(states).toEqual(['DIRECT', 'RELAY_SELECTION', 'RELAY_CONNECTING', 'AUTHORIZING', 'CONNECTED'])
    result.destroy(); relay.registration.close()
  })

  it('uses exact rendezvous enrichment for at most one additional direct race before relay', async () => {
    const rendezvous = rendezvousPath()
    const states: string[] = []
    let attempts = 0
    const result = await connectToServer({
      ...base(),
      authorizedPeers: [{ rendezvous }],
      onStateChange: (state) => states.push(state),
      establishDirectConnection: async () => {
        attempts += 1
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({ expectedServerId: target.serverId })
      }
    })
    expect(result.source).toBe('DIRECT')
    expect(attempts).toBe(1)
    expect(states).toEqual(['RENDEZVOUS', 'DIRECT_ENRICHED', 'AUTHORIZING', 'CONNECTED'])
    result.destroy()
  })

  it('tries relay peers sequentially and advances after NOT_AVAILABLE', async () => {
    const unavailable = unavailableRelayPath()
    const available = await relayPath()
    const relaySuccessCache = new EphemeralRelaySuccessCache()
    relaySuccessCache.recordCryptographicSuccess(
      target.serverId,
      unavailable,
      tcpTransportTestOnly.createSecurePreAuthorizationConnection({ expectedServerId: target.serverId })
    )
    let handshakes = 0
    const result = await connectToServer({
      ...base(),
      authorizedPeers: [{ relay: unavailable }, { relay: available.requesterEndpoint }],
      relaySuccessCache,
      establishRelayConnection: async () => {
        handshakes += 1
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({ expectedServerId: target.serverId })
      }
    })
    expect(result.source).toBe('RELAY')
    expect(result.relayPeerId).toBe(available.relay.serverId)
    expect(handshakes).toBe(1)
    result.destroy(); available.registration.close()
  })

  it('aborts the whole operation and cannot continue into later phases', async () => {
    const controller = new AbortController()
    let attempts = 0
    const operation = connectToServer({
      ...base(),
      signal: controller.signal,
      directSources: { descriptors: [descriptor()] },
      establishDirectConnection: (_dial, options) => new Promise((_resolve, reject) => {
        attempts += 1
        options.signal.addEventListener('abort', () => reject(new Error('internal')), { once: true })
      })
    })
    controller.abort()
    await expect(operation).rejects.toMatchObject({ code: 'CONNECT_ABORTED' })
    expect(attempts).toBeLessThanOrEqual(1)
  })

  it('validates timeout policy and target identity before starting network work', async () => {
    const attempt = vi.fn()
    await expect(connectToServer({
      ...base(),
      overallTimeoutMs: 45_001,
      establishDirectConnection: attempt
    })).rejects.toBeInstanceOf(ConnectivityOrchestrationError)
    expect(attempt).not.toHaveBeenCalled()
  })

  it('rejects a second simultaneous operation for the same cryptographic target', async () => {
    const subsystem = new ConnectivitySubsystem()
    const controller = new AbortController()
    const first = connectToServer({
      ...base(), subsystem, signal: controller.signal,
      directSources: { descriptors: [descriptor()] },
      establishDirectConnection: (_target, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
      })
    })
    await Promise.resolve()
    await expect(connectToServer({ ...base(), subsystem })).rejects.toMatchObject({ code: 'CONNECT_OPERATION_IN_PROGRESS' })
    controller.abort()
    await expect(first).rejects.toMatchObject({ code: 'CONNECT_ABORTED' })
    expect(subsystem.governor.snapshot().counts.CONNECT_OPERATION).toBe(0)
  })

  it('treats global secure-attempt exhaustion as terminal without entering relay fallback', async () => {
    const governor = new ConnectivityResourceGovernor()
    const held = Array.from({ length: MAX_PENDING_SECURE_CONNECTION_ATTEMPTS }, () =>
      governor.reserve('SECURE_CONNECTION_ATTEMPT'))
    const subsystem = new ConnectivitySubsystem(governor)
    const states: string[] = []
    await expect(connectToServer({
      ...base(), subsystem,
      directSources: { descriptors: [descriptor()] },
      authorizedPeers: [{ relay: (await relayPath()).requesterEndpoint }],
      onStateChange: (state) => states.push(state)
    })).rejects.toMatchObject({ code: 'CONNECT_PATH_UNAVAILABLE' })
    expect(states).not.toContain('RELAY_SELECTION')
    for (const reservation of held) reservation.release()
  })

  it('does not treat an unknown relay failure as fallback-safe', async () => {
    const first = await relayPath()
    const second = await relayPath()
    const cache = new EphemeralRelaySuccessCache()
    cache.recordCryptographicSuccess(
      target.serverId,
      first.requesterEndpoint,
      tcpTransportTestOnly.createSecurePreAuthorizationConnection({ expectedServerId: target.serverId })
    )
    let handshakes = 0
    await expect(connectToServer({
      ...base(),
      authorizedPeers: [{ relay: first.requesterEndpoint }, { relay: second.requesterEndpoint }],
      relaySuccessCache: cache,
      establishRelayConnection: async () => {
        handshakes += 1
        throw new Error('foreign unclassified failure')
      }
    })).rejects.toMatchObject({ code: 'CONNECT_PATH_UNAVAILABLE' })
    expect(handshakes).toBe(1)
    first.registration.close(); second.registration.close()
  })

  it('never retries an invite on another relay after target authorization starts', async () => {
    const first = await relayPath()
    const second = await relayPath()
    const cache = new EphemeralRelaySuccessCache()
    cache.recordCryptographicSuccess(
      target.serverId,
      first.requesterEndpoint,
      tcpTransportTestOnly.createSecurePreAuthorizationConnection({ expectedServerId: target.serverId })
    )
    let handshakes = 0
    let inviteUses = 0
    await expect(connectToServer({
      ...base(),
      authorizedPeers: [{ relay: first.requesterEndpoint }, { relay: second.requesterEndpoint }],
      relaySuccessCache: cache,
      establishRelayConnection: async () => {
        handshakes += 1
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({
          expectedServerId: target.serverId,
          onAuthorize: async (_mode, invite) => {
            if (invite === 'MQR1-test') inviteUses += 1
            throw new Error('disconnect after request')
          }
        })
      }
    })).rejects.toMatchObject({ code: 'CONNECT_TARGET_AUTHORIZATION_FAILED' })
    expect(handshakes).toBe(1)
    expect(inviteUses).toBe(1)
    first.registration.close(); second.registration.close()
  })

  it('does not start child network work when the monotonic overall deadline is exhausted', async () => {
    let clockReads = 0
    let attempts = 0
    await expect(connectToServer({
      ...base(), overallTimeoutMs: 1,
      directSources: { descriptors: [descriptor()] },
      monotonicNowMs: () => clockReads++ === 0 ? 0 : 2,
      establishDirectConnection: async () => {
        attempts += 1
        return tcpTransportTestOnly.createSecurePreAuthorizationConnection({ expectedServerId: target.serverId })
      }
    })).rejects.toMatchObject({ code: 'CONNECT_TIMEOUT' })
    expect(attempts).toBe(0)
  })

  it('shutdown during authorization destroys the secure winner and never delivers a connection', async () => {
    const subsystem = new ConnectivitySubsystem()
    let rejectAuthorization!: (cause: unknown) => void
    let authorizationStarted!: () => void
    const started = new Promise<void>((resolve) => { authorizationStarted = resolve })
    const authorization = new Promise<never>((_resolve, reject) => { rejectAuthorization = reject })
    let destroyed = 0
    const operation = connectToServer({
      ...base(), subsystem,
      directSources: { descriptors: [descriptor()] },
      establishDirectConnection: async () => tcpTransportTestOnly.createSecurePreAuthorizationConnection({
        expectedServerId: target.serverId,
        onAuthorize: async () => { authorizationStarted(); return authorization },
        onDestroy: () => { destroyed += 1; rejectAuthorization(new Error('shutdown')) }
      })
    })
    await started
    await subsystem.shutdown()
    await expect(operation).rejects.toMatchObject({ code: 'CONNECT_ABORTED' })
    expect(destroyed).toBeGreaterThanOrEqual(1)
    expect(subsystem.governor.snapshot().counts.CONNECT_OPERATION).toBe(0)
  })
})
