import { createHash, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'

import { createPeerRelayEndpoint, createPeerRelayService, type PeerRelayEndpoint } from './peer-relay'
import {
  createManagedRelayTargetRegistration,
  isManagedRelayTargetRegistration,
  ManagedRelayRegistrationRegistry
} from './relay-lifecycle'
import { tcpTransportTestOnly, type AuthorizedPeerChannel } from './tcp-transport'
import { ConnectivitySubsystem } from './connectivity-subsystem'

function identity() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    serverId: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

function linkedChannels(binding: { serverId: string; peerDeviceFingerprint: string }): {
  remote: AuthorizedPeerChannel
  relay: AuthorizedPeerChannel
  closeRemote: () => void
  closeRelay: () => void
} {
  const delivery: { remote?: (bytes: Buffer) => Promise<void>; relay?: (bytes: Buffer) => Promise<void> } = {}
  const remote = tcpTransportTestOnly.createAuthorizedPeerChannel({
    onSend: async (bytes) => delivery.relay!(bytes)
  })
  const relay = tcpTransportTestOnly.createAuthorizedPeerChannel({
    ...binding,
    onSend: async (bytes) => delivery.remote!(bytes)
  })
  delivery.remote = remote.deliver
  delivery.relay = relay.deliver
  return { remote: remote.channel, relay: relay.channel, closeRemote: remote.close, closeRelay: relay.close }
}

async function managedFixture(
  lifetimeSeconds = 2,
  registry = new ManagedRelayRegistrationRegistry(),
  subsystem?: ConnectivitySubsystem
) {
  const relayIdentity = identity()
  const targetIdentity = identity()
  const device = identity().serverId
  const channels = linkedChannels({ serverId: relayIdentity.serverId, peerDeviceFingerprint: device })
  const service = createPeerRelayService({
    relayServerId: relayIdentity.serverId,
    registrationLifetimeSeconds: lifetimeSeconds
  })
  createPeerRelayEndpoint({ channel: channels.relay, service })
  const endpoint = createPeerRelayEndpoint({ channel: channels.remote })
  const manager = await createManagedRelayTargetRegistration({
    endpoint,
    targetServerId: targetIdentity.serverId,
    targetServerPublicKey: targetIdentity.publicKey,
    targetServerPrivateKey: targetIdentity.privateKey,
    relayServerId: relayIdentity.serverId,
    outerDeviceFingerprint: device,
    onIncomingCircuit: () => {},
    registry,
    subsystem
  })
  return { relayIdentity, targetIdentity, device, channels, service, endpoint, manager, registry }
}

describe('managed relay registration lifecycle', () => {
  it('refreshes at half-life with a fresh registration and remains active beyond the original expiry', async () => {
    vi.useFakeTimers()
    const fixture = await managedFixture()
    const firstExpiry = fixture.manager.expiresAtMs
    expect(isManagedRelayTargetRegistration(fixture.manager)).toBe(true)
    await vi.advanceTimersByTimeAsync(1001)
    expect(fixture.manager.expiresAtMs).toBeGreaterThan(firstExpiry)
    await vi.advanceTimersByTimeAsync(1001)
    expect(fixture.manager.isActive()).toBe(true)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(true)
    fixture.manager.close()
    vi.useRealTimers()
  })

  it('cancels refresh and releases its registry slot on close or channel loss', async () => {
    vi.useFakeTimers()
    const fixture = await managedFixture()
    expect(fixture.registry.count(fixture.targetIdentity.serverId)).toBe(1)
    fixture.manager.close(); fixture.manager.close()
    await vi.advanceTimersByTimeAsync(3000)
    expect(fixture.registry.count(fixture.targetIdentity.serverId)).toBe(0)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)

    const second = await managedFixture()
    second.channels.closeRemote()
    expect(second.manager.isActive()).toBe(false)
    expect(second.registry.count(second.targetIdentity.serverId)).toBe(0)
    vi.useRealTimers()
  })

  it('enforces the explicit per-target manager bound', () => {
    const registry = new ManagedRelayRegistrationRegistry()
    const target = identity().serverId
    const releases = [registry.reserve(target), registry.reserve(target), registry.reserve(target)]
    expect(registry.count(target)).toBe(3)
    expect(() => registry.reserve(target)).toThrowError(expect.objectContaining({ code: 'RELAY_REGISTRATION_MANAGER_LIMIT' }))
    for (const release of releases) release()
    expect(registry.count(target)).toBe(0)
  })

  it('rejects non-relay endpoint capabilities before reserving state', async () => {
    const registry = new ManagedRelayRegistrationRegistry()
    await expect(createManagedRelayTargetRegistration({
      endpoint: {} as PeerRelayEndpoint,
      targetServerId: identity().serverId,
      targetServerPublicKey: Buffer.alloc(1),
      targetServerPrivateKey: identity().privateKey,
      relayServerId: identity().serverId,
      outerDeviceFingerprint: identity().serverId,
      onIncomingCircuit: () => {},
      registry
    })).rejects.toMatchObject({ code: 'RELAY_REGISTRATION_MANAGER_INVALID' })
  })

  it('shutdown cancels managed refresh and unregisters without post-shutdown renewal', async () => {
    vi.useFakeTimers()
    const subsystem = new ConnectivitySubsystem()
    const fixture = await managedFixture(2, new ManagedRelayRegistrationRegistry(), subsystem)
    await subsystem.shutdown()
    expect(fixture.manager.isActive()).toBe(false)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)
    await vi.advanceTimersByTimeAsync(5000)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)
    vi.useRealTimers()
  })
})
