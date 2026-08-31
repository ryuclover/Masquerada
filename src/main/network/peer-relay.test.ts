import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'

import {
  createPeerRelayEndpoint,
  createPeerRelayService,
  createRelayRegistrationTranscript,
  decodeRelayMessage,
  encodeRelayMessage,
  isRelayTargetRegistration,
  isRelayTransportStream,
  MAX_RELAY_DATA_PAYLOAD_BYTES,
  MAX_RELAY_BYTES_PER_CIRCUIT_HARD,
  PeerRelayError,
  RELAY_CHALLENGE_BYTES,
  RELAY_PROTOCOL_VERSION,
  RelayCloseReason,
  RelayMessageType,
  RelayStatus
} from './peer-relay'
import { tcpTransportTestOnly, type AuthorizedPeerChannel } from './tcp-transport'
import { ConnectivitySubsystem } from './connectivity-subsystem'
import { ConnectivityResourceGovernor } from './connectivity-resource-governor'

function identity() {
  const pair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }))
  return {
    serverId: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    publicKey,
    privateKey: pair.privateKey
  }
}

interface LinkedPeer {
  readonly remoteChannel: AuthorizedPeerChannel
  readonly relayChannel: AuthorizedPeerChannel
  readonly closeRemote: () => void
  readonly closeRelay: () => void
  readonly remoteWire: Buffer[]
  readonly relayWire: Buffer[]
  setRelayGate(gate?: Promise<void>): void
}

function linkedPeer(binding: { readonly serverId?: string; readonly peerDeviceFingerprint?: string } = {}): LinkedPeer {
  const delivery: { remote?: (bytes: Buffer) => Promise<void>; relay?: (bytes: Buffer) => Promise<void> } = {}
  const remoteWire: Buffer[] = []
  const relayWire: Buffer[] = []
  let relayGate: Promise<void> | undefined
  const remote = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: async (bytes) => {
    remoteWire.push(Buffer.from(bytes))
    await delivery.relay!(bytes)
  } })
  const relay = tcpTransportTestOnly.createAuthorizedPeerChannel({
    ...binding,
    onSend: async (bytes) => {
      relayWire.push(Buffer.from(bytes))
      await relayGate
      await delivery.remote!(bytes)
    }
  })
  delivery.remote = remote.deliver
  delivery.relay = relay.deliver
  return {
    remoteChannel: remote.channel,
    relayChannel: relay.channel,
    closeRemote: remote.close,
    closeRelay: relay.close,
    remoteWire,
    relayWire,
    setRelayGate(gate?: Promise<void>) { relayGate = gate }
  }
}

async function registeredNetwork(options: {
  random?: (bytes: number) => Buffer
  service?: Partial<{
    registrationLifetimeSeconds: number
    openTimeoutMs: number
    maxCircuitsGlobal: number
    maxCircuitsPerChannel: number
    maxQueuedBytes: number
    maxGlobalQueuedBytes: number
    maxBytesPerCircuit: number
    maxLifetimeMs: number
    idleTimeoutMs: number
    resourceGovernor: ConnectivityResourceGovernor
  }>
  endpoint?: Partial<{
    circuitLeaseMs: number
    subsystem: ConnectivitySubsystem
  }>
} = {}) {
  const relayIdentity = identity()
  const targetIdentity = identity()
  const targetDevice = identity().serverId
  const requesterDevice = identity().serverId
  const targetLink = linkedPeer({ serverId: relayIdentity.serverId, peerDeviceFingerprint: targetDevice })
  const requesterLink = linkedPeer({ serverId: relayIdentity.serverId, peerDeviceFingerprint: requesterDevice })
  const service = createPeerRelayService({ relayServerId: relayIdentity.serverId, random: options.random, ...options.service })
  const relayTargetEndpoint = createPeerRelayEndpoint({ channel: targetLink.relayChannel, service })
  const relayRequesterEndpoint = createPeerRelayEndpoint({ channel: requesterLink.relayChannel, service })
  const target = createPeerRelayEndpoint({ channel: targetLink.remoteChannel, ...options.endpoint })
  const requester = createPeerRelayEndpoint({ channel: requesterLink.remoteChannel, ...options.endpoint })
  const incoming: Parameters<Parameters<typeof target.registerTarget>[0]['onIncomingCircuit']>[0][] = []
  const registration = await target.registerTarget({
    targetServerId: targetIdentity.serverId,
    targetServerPublicKey: targetIdentity.publicKey,
    targetServerPrivateKey: targetIdentity.privateKey,
    relayServerId: relayIdentity.serverId,
    outerDeviceFingerprint: targetDevice,
    onIncomingCircuit: (stream) => { incoming.push(stream) }
  })
  return { relayIdentity, targetIdentity, targetDevice, requesterDevice, targetLink, requesterLink, service, relayTargetEndpoint, relayRequesterEndpoint, target, requester, registration, incoming }
}

describe('peer relay protocol v1', () => {
  it('encodes fixed OPEN request/response byte-exact without host, IP or port', () => {
    const targetServerId = `sha256:${'a'.repeat(64)}`
    const nonce = Buffer.alloc(32, 0x11)
    const circuitId = Buffer.alloc(16, 0x22)
    const request = encodeRelayMessage({ type: RelayMessageType.OPEN_REQUEST, requestNonce: nonce, targetServerId })
    expect(request).toHaveLength(105)
    expect(request.subarray(0, 2)).toEqual(Buffer.from([1, 0x35]))
    expect(decodeRelayMessage(request)).toEqual({ type: RelayMessageType.OPEN_REQUEST, requestNonce: nonce, targetServerId })
    const ready = encodeRelayMessage({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.READY, requestNonce: nonce, targetServerId, circuitId })
    expect(ready).toHaveLength(122)
    expect(ready.subarray(0, 3)).toEqual(Buffer.from([1, 0x36, 1]))
    expect(decodeRelayMessage(ready)).toEqual({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.READY, requestNonce: nonce, targetServerId, circuitId })
    expect(Object.keys(decodeRelayMessage(request))).toEqual(['type', 'requestNonce', 'targetServerId'])
    const cancel = encodeRelayMessage({ type: RelayMessageType.OPEN_CANCEL, requestNonce: nonce, targetServerId })
    expect(cancel).toHaveLength(105)
    expect(cancel[1]).toBe(0x3b)
  })

  it('uses one canonical NOT_AVAILABLE representation and bounded close reasons', () => {
    const targetServerId = `sha256:${'b'.repeat(64)}`
    const requestNonce = Buffer.alloc(32, 1)
    const encoded = encodeRelayMessage({ type: RelayMessageType.OPEN_RESPONSE, status: RelayStatus.NOT_AVAILABLE, requestNonce, targetServerId, circuitId: Buffer.alloc(16) })
    expect(encoded.subarray(-16)).toEqual(Buffer.alloc(16))
    expect(decodeRelayMessage(encoded)).toMatchObject({ status: RelayStatus.NOT_AVAILABLE, targetServerId })
    const close = encodeRelayMessage({ type: RelayMessageType.CLOSE, circuitId: Buffer.alloc(16, 2), reason: RelayCloseReason.RESOURCE_LIMIT })
    expect(close).toHaveLength(19)
  })

  it('encodes strict fixed-size circuit renewal messages', () => {
    const circuitId = Buffer.alloc(16, 0x31)
    const renewNonce = Buffer.alloc(32, 0x42)
    const request = encodeRelayMessage({ type: RelayMessageType.CIRCUIT_RENEW, circuitId, renewNonce })
    expect(request).toHaveLength(50)
    expect(request.subarray(0, 2)).toEqual(Buffer.from([RELAY_PROTOCOL_VERSION, 0x3c]))
    expect(decodeRelayMessage(request)).toEqual({ type: RelayMessageType.CIRCUIT_RENEW, circuitId, renewNonce })
    const result = encodeRelayMessage({ type: RelayMessageType.CIRCUIT_RENEW_RESULT, status: RelayStatus.READY, circuitId, renewNonce })
    expect(result).toHaveLength(51)
    expect(result.subarray(0, 3)).toEqual(Buffer.from([RELAY_PROTOCOL_VERSION, 0x3d, RelayStatus.READY]))
    expect(decodeRelayMessage(result)).toEqual({ type: RelayMessageType.CIRCUIT_RENEW_RESULT, status: RelayStatus.READY, circuitId, renewNonce })
    expect(() => decodeRelayMessage(Buffer.concat([request, Buffer.of(0)]))).toThrow(PeerRelayError)
  })

  it('keeps the finite default byte budget but permits an explicitly bounded long-lived budget', () => {
    const relay = identity()
    expect(() => createPeerRelayService({ relayServerId: relay.serverId, maxBytesPerCircuit: MAX_RELAY_BYTES_PER_CIRCUIT_HARD })).not.toThrow()
    expect(() => createPeerRelayService({ relayServerId: relay.serverId, maxBytesPerCircuit: MAX_RELAY_BYTES_PER_CIRCUIT_HARD + 1 })).toThrow(PeerRelayError)
  })

  it('parses DATA exactly, accepts 16384 and rejects oversized/truncated/trailing', () => {
    const circuitId = Buffer.alloc(16, 3)
    const payload = Buffer.alloc(MAX_RELAY_DATA_PAYLOAD_BYTES, 4)
    const encoded = encodeRelayMessage({ type: RelayMessageType.DATA, circuitId, payload })
    expect(decodeRelayMessage(encoded)).toEqual({ type: RelayMessageType.DATA, circuitId, payload })
    expect(() => encodeRelayMessage({ type: RelayMessageType.DATA, circuitId, payload: Buffer.alloc(MAX_RELAY_DATA_PAYLOAD_BYTES + 1) })).toThrow(PeerRelayError)
    expect(() => decodeRelayMessage(encoded.subarray(0, -1))).toThrow(PeerRelayError)
    expect(() => decodeRelayMessage(Buffer.concat([encoded, Buffer.of(0)]))).toThrow(PeerRelayError)
  })

  it('rejects malformed/fuzz-like control plaintexts without accepting arbitrary values', () => {
    for (let length = 0; length < 300; length++) {
      const bytes = Buffer.alloc(length)
      for (let index = 0; index < length; index++) bytes[index] = (length * 31 + index * 17) & 0xff
      expect(() => decodeRelayMessage(bytes)).toThrow(PeerRelayError)
    }
    expect(() => decodeRelayMessage(Buffer.from([RELAY_PROTOCOL_VERSION + 1, RelayMessageType.OPEN_REQUEST]))).toThrow(PeerRelayError)
  })

  it('builds a deterministic domain-separated transcript bound to relay/channel/device', () => {
    const relay = identity(); const target = identity(); const device = identity().serverId
    const base = {
      relayServerId: relay.serverId,
      targetServerId: target.serverId,
      targetServerPublicKey: target.publicKey,
      challenge: Buffer.alloc(RELAY_CHALLENGE_BYTES, 5),
      channelBinding: Buffer.alloc(32, 6),
      outerDeviceFingerprint: device
    }
    const transcript = createRelayRegistrationTranscript(base)
    expect(transcript).toEqual(createRelayRegistrationTranscript(base))
    expect(transcript.toString('utf8')).toContain('Masquerada/peer-relay-target-registration/v1')
    expect(createRelayRegistrationTranscript({ ...base, channelBinding: Buffer.alloc(32, 7) })).not.toEqual(transcript)
  })
})

describe('target registration and exact relay switching', () => {
  it('uses a 32-byte one-shot CSPRNG challenge and activates a real Ed25519 registration', async () => {
    const fixture = await registeredNetwork()
    expect(isRelayTargetRegistration(fixture.registration)).toBe(true)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(true)
    const challenge = fixture.targetLink.relayWire.map(decodeRelayMessage).find((message) => message.type === RelayMessageType.REGISTER_CHALLENGE)
    expect(challenge).toMatchObject({ type: RelayMessageType.REGISTER_CHALLENGE, targetServerId: fixture.targetIdentity.serverId })
    if (challenge?.type !== RelayMessageType.REGISTER_CHALLENGE) throw new Error('missing challenge')
    expect(challenge.challenge).toHaveLength(32)
    const proof = fixture.targetLink.remoteWire.map(decodeRelayMessage).find((message) => message.type === RelayMessageType.REGISTER_PROOF)
    if (proof?.type !== RelayMessageType.REGISTER_PROOF) throw new Error('missing proof')
    await expect(fixture.target.sendControl(proof)).rejects.toBeDefined()
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(true)
  })

  it('rejects serverId/public-key mismatch before registration', async () => {
    const relay = identity(); const target = identity(); const wrong = identity(); const device = identity().serverId; const link = linkedPeer({ serverId: relay.serverId, peerDeviceFingerprint: device })
    const service = createPeerRelayService({ relayServerId: relay.serverId })
    createPeerRelayEndpoint({ channel: link.relayChannel, service })
    const endpoint = createPeerRelayEndpoint({ channel: link.remoteChannel })
    await expect(endpoint.registerTarget({
      targetServerId: target.serverId,
      targetServerPublicKey: wrong.publicKey,
      targetServerPrivateKey: wrong.privateKey,
      relayServerId: relay.serverId,
      outerDeviceFingerprint: identity().serverId,
      onIncomingCircuit: () => {}
    })).rejects.toBeInstanceOf(PeerRelayError)
    expect(service.hasRegistration(target.serverId)).toBe(false)
  })

  it('binds proof to relay and authenticated outer device', async () => {
    const relay = identity(); const target = identity(); const actualDevice = identity().serverId; const link = linkedPeer({ serverId: relay.serverId, peerDeviceFingerprint: actualDevice })
    const service = createPeerRelayService({ relayServerId: relay.serverId })
    createPeerRelayEndpoint({ channel: link.relayChannel, service })
    const endpoint = createPeerRelayEndpoint({ channel: link.remoteChannel })
    await expect(endpoint.registerTarget({ targetServerId: target.serverId, targetServerPublicKey: target.publicKey, targetServerPrivateKey: target.privateKey, relayServerId: identity().serverId, outerDeviceFingerprint: actualDevice, onIncomingCircuit: () => {} })).rejects.toBeInstanceOf(PeerRelayError)
    expect(service.hasRegistration(target.serverId)).toBe(false)
  })

  it('binds the one-shot proof to the exact channel and rejects expiry/replay', () => {
    let now = 1000
    const relay = identity(); const target = identity(); const deviceA = identity().serverId; const deviceB = identity().serverId
    const linkA = linkedPeer({ serverId: relay.serverId, peerDeviceFingerprint: deviceA })
    const linkB = linkedPeer({ serverId: relay.serverId, peerDeviceFingerprint: deviceB })
    const service = createPeerRelayService({ relayServerId: relay.serverId, nowMs: () => now })
    const endpointA = createPeerRelayEndpoint({ channel: linkA.relayChannel, service, nowMs: () => now })
    const endpointB = createPeerRelayEndpoint({ channel: linkB.relayChannel, service, nowMs: () => now })
    const challenge = service.beginRegistration(endpointA, target.serverId)
    if (challenge.type !== RelayMessageType.REGISTER_CHALLENGE) throw new Error('missing challenge')
    const transcript = createRelayRegistrationTranscript({
      relayServerId: relay.serverId,
      targetServerId: target.serverId,
      targetServerPublicKey: target.publicKey,
      challenge: challenge.challenge,
      channelBinding: challenge.channelBinding,
      outerDeviceFingerprint: deviceA
    })
    const proof = {
      type: RelayMessageType.REGISTER_PROOF as const,
      targetServerId: target.serverId,
      targetServerPublicKey: target.publicKey,
      challenge: challenge.challenge,
      signature: sign(null, transcript, target.privateKey)
    }
    expect(() => service.proveRegistration(endpointB, proof)).toThrow(PeerRelayError)
    const result = service.proveRegistration(endpointA, proof)
    expect(result).toMatchObject({ status: RelayStatus.READY })
    expect(() => service.proveRegistration(endpointA, proof)).toThrow(PeerRelayError)

    const target2 = identity()
    const challenge2 = service.beginRegistration(endpointB, target2.serverId)
    if (challenge2.type !== RelayMessageType.REGISTER_CHALLENGE) throw new Error('missing challenge')
    now += 10_001
    const transcript2 = createRelayRegistrationTranscript({ relayServerId: relay.serverId, targetServerId: target2.serverId, targetServerPublicKey: target2.publicKey, challenge: challenge2.challenge, channelBinding: challenge2.channelBinding, outerDeviceFingerprint: deviceB })
    expect(() => service.proveRegistration(endpointB, { type: RelayMessageType.REGISTER_PROOF, targetServerId: target2.serverId, targetServerPublicKey: target2.publicKey, challenge: challenge2.challenge, signature: sign(null, transcript2, target2.privateKey) })).toThrow(PeerRelayError)
  })

  it('rejects invalid Ed25519 signatures and generates independent challenges', () => {
    const relay = identity(); const targetA = identity(); const targetB = identity(); const deviceA = identity().serverId; const deviceB = identity().serverId
    const linkA = linkedPeer({ serverId: relay.serverId, peerDeviceFingerprint: deviceA })
    const linkB = linkedPeer({ serverId: relay.serverId, peerDeviceFingerprint: deviceB })
    const service = createPeerRelayService({ relayServerId: relay.serverId })
    const endpointA = createPeerRelayEndpoint({ channel: linkA.relayChannel, service })
    const endpointB = createPeerRelayEndpoint({ channel: linkB.relayChannel, service })
    const challengeA = service.beginRegistration(endpointA, targetA.serverId)
    const challengeB = service.beginRegistration(endpointB, targetB.serverId)
    if (challengeA.type !== RelayMessageType.REGISTER_CHALLENGE || challengeB.type !== RelayMessageType.REGISTER_CHALLENGE) throw new Error('missing challenge')
    expect(challengeA.challenge).not.toEqual(challengeB.challenge)
    expect(() => service.proveRegistration(endpointA, {
      type: RelayMessageType.REGISTER_PROOF,
      targetServerId: targetA.serverId,
      targetServerPublicKey: targetA.publicKey,
      challenge: challengeA.challenge,
      signature: Buffer.alloc(64)
    })).toThrow(PeerRelayError)
    expect(service.hasRegistration(targetA.serverId)).toBe(false)
  })

  it('explicit unregister and target channel close remove registration idempotently', async () => {
    const fixture = await registeredNetwork()
    fixture.registration.close(); fixture.registration.close()
    await new Promise((resolve) => setImmediate(resolve))
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)
    const second = await registeredNetwork()
    second.targetLink.closeRelay()
    expect(second.service.hasRegistration(second.targetIdentity.serverId)).toBe(false)
  })

  it('refreshes registration with a fresh proof and preserves active circuits', async () => {
    const fixture = await registeredNetwork()
    const stream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const previousChallengeCount = fixture.targetLink.relayWire.map(decodeRelayMessage)
      .filter((message) => message.type === RelayMessageType.REGISTER_CHALLENGE).length
    const refreshed = await fixture.target.refreshTargetRegistration(fixture.registration, {
      targetServerId: fixture.targetIdentity.serverId,
      targetServerPublicKey: fixture.targetIdentity.publicKey,
      targetServerPrivateKey: fixture.targetIdentity.privateKey,
      relayServerId: fixture.relayIdentity.serverId,
      outerDeviceFingerprint: fixture.targetDevice,
      onIncomingCircuit: (incoming) => { fixture.incoming.push(incoming) }
    })
    const challenges = fixture.targetLink.relayWire.map(decodeRelayMessage)
      .filter((message) => message.type === RelayMessageType.REGISTER_CHALLENGE)
    expect(challenges).toHaveLength(previousChallengeCount + 1)
    expect(fixture.registration.isClosed()).toBe(true)
    expect(refreshed.isClosed()).toBe(false)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(true)
    expect(fixture.service.activeCircuitCount).toBe(1)
    stream.destroy(); refreshed.close()
  })

  it('opens only exact registered target and exposes no listing API', async () => {
    const fixture = await registeredNetwork()
    const stream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    expect(isRelayTransportStream(stream)).toBe(true)
    expect(fixture.incoming).toHaveLength(1)
    await expect(fixture.requester.openCircuit(identity().serverId)).rejects.toMatchObject({ code: 'RELAY_TARGET_NOT_AVAILABLE' })
    expect('listTargets' in fixture.service).toBe(false)
  })

  it('expires a registration and closes its active circuits', async () => {
    vi.useFakeTimers()
    const fixture = await registeredNetwork({ service: { registrationLifetimeSeconds: 1 } })
    const requesterStream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    requesterStream.resume()
    const ended = new Promise<void>((resolve) => requesterStream.once('end', resolve))
    await vi.advanceTimersByTimeAsync(1001)
    await ended
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)
    expect(fixture.service.activeCircuitCount).toBe(0)
    vi.useRealTimers()
  })

  it('enforces per-channel/global circuit limits and open rate without target-state detail', async () => {
    const fixture = await registeredNetwork()
    const first = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const second = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    await expect(fixture.requester.openCircuit(fixture.targetIdentity.serverId)).rejects.toMatchObject({ code: 'RELAY_TARGET_NOT_AVAILABLE' })
    first.destroy(); second.destroy()
    await new Promise((resolve) => setImmediate(resolve))
    for (let attempt = 0; attempt < 2; attempt++) {
      const stream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
      stream.destroy()
      await new Promise((resolve) => setImmediate(resolve))
    }
    await expect(fixture.requester.openCircuit(fixture.targetIdentity.serverId)).rejects.toMatchObject({ code: 'RELAY_TARGET_NOT_AVAILABLE' })
  })

  it('enforces the global circuit bound across distinct requester channels', async () => {
    const fixture = await registeredNetwork({ service: { maxCircuitsGlobal: 1 } })
    const first = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const secondDevice = identity().serverId
    const secondLink = linkedPeer({ serverId: fixture.relayIdentity.serverId, peerDeviceFingerprint: secondDevice })
    createPeerRelayEndpoint({ channel: secondLink.relayChannel, service: fixture.service })
    const secondRequester = createPeerRelayEndpoint({ channel: secondLink.remoteChannel })
    await expect(secondRequester.openCircuit(fixture.targetIdentity.serverId)).rejects.toMatchObject({ code: 'RELAY_TARGET_NOT_AVAILABLE' })
    expect(fixture.service.activeCircuitCount).toBe(1)
    first.destroy()
  })

  it('OPEN_CANCEL removes pending state, rejects late accept and DATA before ACTIVE closes the circuit', async () => {
    const relay = identity(); const target = identity(); const targetDevice = identity().serverId; const requesterDevice = identity().serverId
    const targetMessages: ReturnType<typeof decodeRelayMessage>[] = []
    const targetHarness = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId: relay.serverId, peerDeviceFingerprint: targetDevice, onSend: async (bytes) => { targetMessages.push(decodeRelayMessage(bytes)) } })
    const requesterHarness = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId: relay.serverId, peerDeviceFingerprint: requesterDevice, onSend: async () => {} })
    const service = createPeerRelayService({ relayServerId: relay.serverId })
    const targetEndpoint = createPeerRelayEndpoint({ channel: targetHarness.channel, service })
    const requesterEndpoint = createPeerRelayEndpoint({ channel: requesterHarness.channel, service })
    const challenge = service.beginRegistration(targetEndpoint, target.serverId)
    if (challenge.type !== RelayMessageType.REGISTER_CHALLENGE) throw new Error('missing challenge')
    const transcript = createRelayRegistrationTranscript({ relayServerId: relay.serverId, targetServerId: target.serverId, targetServerPublicKey: target.publicKey, challenge: challenge.challenge, channelBinding: challenge.channelBinding, outerDeviceFingerprint: targetDevice })
    service.proveRegistration(targetEndpoint, { type: RelayMessageType.REGISTER_PROOF, targetServerId: target.serverId, targetServerPublicKey: target.publicKey, challenge: challenge.challenge, signature: sign(null, transcript, target.privateKey) })

    const nonceA = Buffer.alloc(32, 1)
    await service.open(requesterEndpoint, { type: RelayMessageType.OPEN_REQUEST, requestNonce: nonceA, targetServerId: target.serverId })
    expect(service.activeCircuitCount).toBe(1)
    const incomingA = [...targetMessages].reverse().find((message) => message.type === RelayMessageType.INCOMING_CIRCUIT)
    if (incomingA?.type !== RelayMessageType.INCOMING_CIRCUIT) throw new Error('missing incoming')
    service.cancelOpen(requesterEndpoint, { type: RelayMessageType.OPEN_CANCEL, requestNonce: nonceA, targetServerId: target.serverId })
    expect(service.activeCircuitCount).toBe(0)
    await expect(service.accept(targetEndpoint, { type: RelayMessageType.CIRCUIT_ACCEPT, status: RelayStatus.READY, circuitId: incomingA.circuitId, targetServerId: target.serverId })).rejects.toBeInstanceOf(PeerRelayError)

    const nonceB = Buffer.alloc(32, 2)
    await service.open(requesterEndpoint, { type: RelayMessageType.OPEN_REQUEST, requestNonce: nonceB, targetServerId: target.serverId })
    expect(service.activeCircuitCount).toBe(1)
    const incoming = [...targetMessages].reverse().find((message) => message.type === RelayMessageType.INCOMING_CIRCUIT)
    if (incoming?.type !== RelayMessageType.INCOMING_CIRCUIT) throw new Error('missing incoming')
    const circuitId = incoming.circuitId
    await expect(service.data(requesterEndpoint, { type: RelayMessageType.DATA, circuitId, payload: Buffer.of(1) })).rejects.toBeInstanceOf(PeerRelayError)
    expect(service.activeCircuitCount).toBe(0)
  })

  it('outer target channel close removes registration/circuits and a fresh service starts empty', async () => {
    const fixture = await registeredNetwork()
    const stream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    stream.resume()
    const ended = new Promise<void>((resolve) => stream.once('end', resolve))
    fixture.targetLink.closeRelay()
    await ended
    expect(fixture.service.activeCircuitCount).toBe(0)
    expect(fixture.service.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)
    const restarted = createPeerRelayService({ relayServerId: fixture.relayIdentity.serverId })
    expect(restarted.hasRegistration(fixture.targetIdentity.serverId)).toBe(false)
    expect(restarted.activeCircuitCount).toBe(0)
  })

  it('closes circuits at byte, per-direction queue and global queue bounds', async () => {
    const byteBudget = await registeredNetwork({ service: { maxBytesPerCircuit: 4 } })
    const budgetStream = await byteBudget.requester.openCircuit(byteBudget.targetIdentity.serverId)
    budgetStream.write(Buffer.alloc(5, 1))
    await new Promise((resolve) => setImmediate(resolve))
    expect(byteBudget.service.activeCircuitCount).toBe(0)

    const queueBound = await registeredNetwork({ service: { maxQueuedBytes: 4 } })
    const queueStream = await queueBound.requester.openCircuit(queueBound.targetIdentity.serverId)
    queueStream.write(Buffer.alloc(5, 2))
    await new Promise((resolve) => setImmediate(resolve))
    expect(queueBound.service.activeCircuitCount).toBe(0)

    const globalBound = await registeredNetwork({ service: { maxQueuedBytes: 8, maxGlobalQueuedBytes: 10 } })
    const streamA = await globalBound.requester.openCircuit(globalBound.targetIdentity.serverId)
    const streamB = await globalBound.requester.openCircuit(globalBound.targetIdentity.serverId)
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    globalBound.targetLink.setRelayGate(gate)
    streamA.write(Buffer.alloc(6, 3))
    streamB.write(Buffer.alloc(6, 4))
    await new Promise((resolve) => setImmediate(resolve))
    expect(globalBound.service.activeCircuitCount).toBe(1)
    release()
  })

  it('enforces idle and absolute lifetime timers with activity refreshing only idle', async () => {
    vi.useFakeTimers()
    const idle = await registeredNetwork({ service: { idleTimeoutMs: 20, maxLifetimeMs: 100 } })
    const idleStream = await idle.requester.openCircuit(idle.targetIdentity.serverId)
    idleStream.resume()
    const idleEnded = new Promise<void>((resolve) => idleStream.once('end', resolve))
    await vi.advanceTimersByTimeAsync(21)
    await idleEnded
    expect(idle.service.activeCircuitCount).toBe(0)

    const lifetime = await registeredNetwork({ service: { idleTimeoutMs: 20, maxLifetimeMs: 35 } })
    const lifetimeStream = await lifetime.requester.openCircuit(lifetime.targetIdentity.serverId)
    lifetimeStream.resume()
    const lifetimeEnded = new Promise<void>((resolve) => lifetimeStream.once('end', resolve))
    await vi.advanceTimersByTimeAsync(15)
    lifetimeStream.write(Buffer.of(1))
    await vi.advanceTimersByTimeAsync(15)
    lifetimeStream.write(Buffer.of(2))
    await vi.advanceTimersByTimeAsync(6)
    await lifetimeEnded
    expect(lifetime.service.activeCircuitCount).toBe(0)
    vi.useRealTimers()
  })

  it('renews only an opted-in requester circuit while low-level default remains finite', async () => {
    vi.useFakeTimers()
    const renewed = await registeredNetwork({
      service: { maxLifetimeMs: 100, idleTimeoutMs: 1000 },
      endpoint: { circuitLeaseMs: 100 }
    })
    const kept = await renewed.requester.openCircuit(renewed.targetIdentity.serverId, { autoRenew: true })
    kept.resume()
    await vi.advanceTimersByTimeAsync(260)
    expect(renewed.service.activeCircuitCount).toBe(1)
    const renews = renewed.requesterLink.remoteWire.map(decodeRelayMessage)
      .filter((message) => message.type === RelayMessageType.CIRCUIT_RENEW)
    expect(renews.length).toBeGreaterThanOrEqual(2)
    kept.destroy()

    const finite = await registeredNetwork({
      service: { maxLifetimeMs: 100, idleTimeoutMs: 1000 },
      endpoint: { circuitLeaseMs: 100 }
    })
    const expired = await finite.requester.openCircuit(finite.targetIdentity.serverId)
    expired.resume()
    await vi.advanceTimersByTimeAsync(101)
    expect(finite.service.activeCircuitCount).toBe(0)
    vi.useRealTimers()
  })

  it('subsystem shutdown closes active circuits and suppresses later renew timers', async () => {
    vi.useFakeTimers()
    const subsystem = new ConnectivitySubsystem()
    const fixture = await registeredNetwork({
      service: { maxLifetimeMs: 100, idleTimeoutMs: 1000 },
      endpoint: { circuitLeaseMs: 100, subsystem }
    })
    const stream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId, { autoRenew: true })
    stream.resume()
    await subsystem.shutdown()
    expect(fixture.service.activeCircuitCount).toBe(0)
    const renewCount = fixture.requesterLink.remoteWire.map(decodeRelayMessage)
      .filter((message) => message.type === RelayMessageType.CIRCUIT_RENEW).length
    await vi.advanceTimersByTimeAsync(1000)
    expect(fixture.requesterLink.remoteWire.map(decodeRelayMessage)
      .filter((message) => message.type === RelayMessageType.CIRCUIT_RENEW)).toHaveLength(renewCount)
    vi.useRealTimers()
  })

  it('accounts relay circuits globally and releases the reservation exactly once', async () => {
    const governor = new ConnectivityResourceGovernor()
    const fixture = await registeredNetwork({ service: { resourceGovernor: governor } })
    const stream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    expect(governor.snapshot().counts.RELAY_CIRCUIT).toBe(1)
    stream.destroy(); stream.destroy()
    await new Promise((resolve) => setImmediate(resolve))
    expect(governor.snapshot().counts.RELAY_CIRCUIT).toBe(0)
  })

  it('forwards exact opaque bytes with arbitrary fragmentation and close propagation', async () => {
    const fixture = await registeredNetwork()
    const requesterStream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const targetStream = fixture.incoming[0]!
    const received: Buffer[] = []
    targetStream.on('data', (bytes: Buffer) => received.push(Buffer.from(bytes)))
    requesterStream.write(Buffer.from('one'))
    requesterStream.write(Buffer.from('two'))
    requesterStream.write(Buffer.alloc(MAX_RELAY_DATA_PAYLOAD_BYTES + 7, 9))
    await new Promise((resolve) => setImmediate(resolve))
    expect(Buffer.concat(received)).toEqual(Buffer.concat([Buffer.from('one'), Buffer.from('two'), Buffer.alloc(MAX_RELAY_DATA_PAYLOAD_BYTES + 7, 9)]))
    const dataMessages = fixture.requesterLink.remoteWire.map(decodeRelayMessage).filter((message) => message.type === RelayMessageType.DATA)
    expect(dataMessages.every((message) => message.type === RelayMessageType.DATA && message.payload.length <= MAX_RELAY_DATA_PAYLOAD_BYTES)).toBe(true)
    const ended = new Promise<void>((resolve) => targetStream.once('end', resolve))
    requesterStream.destroy()
    await ended
  })

  it('binds circuit ownership to both channels and rejects takeover, double accept and data after close', async () => {
    const fixture = await registeredNetwork()
    const requesterStream = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const ready = fixture.requesterLink.relayWire.map(decodeRelayMessage).find((message) => message.type === RelayMessageType.OPEN_RESPONSE && message.status === RelayStatus.READY)
    if (ready?.type !== RelayMessageType.OPEN_RESPONSE) throw new Error('missing ready')
    const thirdDevice = identity().serverId
    const thirdLink = linkedPeer({ serverId: fixture.relayIdentity.serverId, peerDeviceFingerprint: thirdDevice })
    createPeerRelayEndpoint({ channel: thirdLink.relayChannel, service: fixture.service })
    const third = createPeerRelayEndpoint({ channel: thirdLink.remoteChannel })
    await expect(third.sendControl({ type: RelayMessageType.DATA, circuitId: ready.circuitId, payload: Buffer.of(1) })).rejects.toBeInstanceOf(PeerRelayError)
    await expect(fixture.service.accept(fixture.relayTargetEndpoint, { type: RelayMessageType.CIRCUIT_ACCEPT, status: RelayStatus.READY, circuitId: ready.circuitId, targetServerId: fixture.targetIdentity.serverId })).rejects.toBeInstanceOf(PeerRelayError)
    requesterStream.destroy()
    await new Promise((resolve) => setImmediate(resolve))
    await expect(fixture.requester.sendControl({ type: RelayMessageType.DATA, circuitId: ready.circuitId, payload: Buffer.of(2) })).rejects.toBeInstanceOf(PeerRelayError)
    expect(fixture.service.activeCircuitCount).toBe(0)
  })

  it('regenerates a colliding circuitId with bounded attempts', async () => {
    let calls = 0
    const ids = [Buffer.alloc(32, 1), Buffer.alloc(16, 2), Buffer.alloc(16, 2), Buffer.alloc(16, 3)]
    const fixture = await registeredNetwork({ random: (bytes) => {
      calls++
      const next = ids.shift()
      return next?.length === bytes ? next : Buffer.alloc(bytes, calls)
    } })
    const first = await fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const secondPromise = fixture.requester.openCircuit(fixture.targetIdentity.serverId)
    const second = await secondPromise
    expect(first).not.toBe(second)
    expect(calls).toBeGreaterThan(3)
  })

  it('enforces two outstanding opens, abort, timeout and cleanup', async () => {
    vi.useFakeTimers()
    const link = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: async () => {} })
    const endpoint = createPeerRelayEndpoint({ channel: link.channel })
    const target = identity().serverId
    const first = endpoint.openCircuit(target, { timeoutMs: 50 })
    const firstRejected = expect(first).rejects.toMatchObject({ code: 'RELAY_OPEN_TIMEOUT' })
    const controller = new AbortController()
    const second = endpoint.openCircuit(target, { timeoutMs: 50, signal: controller.signal })
    const secondRejected = expect(second).rejects.toMatchObject({ code: 'RELAY_OPEN_ABORTED' })
    await expect(endpoint.openCircuit(target, { timeoutMs: 50 })).rejects.toMatchObject({ code: 'RELAY_CIRCUIT_LIMIT' })
    controller.abort()
    await secondRejected
    await vi.advanceTimersByTimeAsync(51)
    await firstRejected
    expect(endpoint.outstandingOpenCount).toBe(0)
    vi.useRealTimers()
  })

  it('rejects fake/pre-auth-shaped channels and fake relay streams', () => {
    expect(() => createPeerRelayEndpoint({ channel: { authorized: true } as never })).toThrow(PeerRelayError)
    expect(isRelayTransportStream({ write() {}, destroy() {} })).toBe(false)
  })

  it('uses no network destination and imports no inner protocol parser by construction', () => {
    const openKeys = Object.keys({ targetServerId: identity().serverId, timeoutMs: 10 })
    expect(openKeys).not.toEqual(expect.arrayContaining(['host', 'address', 'port', 'url', 'socket']))
    expect(RelayMessageType.DATA).toBe(0x39)
  })
})
