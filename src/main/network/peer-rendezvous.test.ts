import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { describe, expect, it, vi, afterEach } from 'vitest'

import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  type ConnectivityCandidate,
  type VerifiedConnectivityDescriptor
} from './connectivity-descriptor'
import {
  createPeerRendezvousEndpoint,
  decodeRendezvousRequest,
  decodeRendezvousResponse,
  encodeRendezvousRequest,
  encodeRendezvousResponse,
  markRendezvousShareable,
  MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES,
  MAX_RENDEZVOUS_OUTSTANDING_REQUESTS,
  MAX_RENDEZVOUS_REQUESTS_GLOBAL,
  PeerRendezvousError,
  RENDEZVOUS_PROTOCOL_VERSION,
  RENDEZVOUS_REQUEST_BYTES,
  RENDEZVOUS_REQUEST_NONCE_BYTES,
  RENDEZVOUS_RESPONSE_HEADER_BYTES,
  RendezvousDescriptorStore,
  RendezvousGlobalRateLimiter,
  RendezvousMessageType,
  RendezvousResponseStatus,
  type PeerRendezvousEndpoint
} from './peer-rendezvous'
import { tcpTransportTestOnly, type AuthorizedPeerChannel } from './tcp-transport'
import { ConnectivitySubsystem } from './connectivity-subsystem'

interface Identity {
  readonly serverId: string
  readonly publicKey: Buffer
  readonly privateKey: KeyObject
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

const mapped = (address = '8.8.8.8', port = 45000): ConnectivityCandidate => ({
  candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
  family: 4,
  address,
  port
})
const direct = (address = '2606:4700:4700::1111', port = 45001): ConnectivityCandidate => ({
  candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
  family: 6,
  address,
  port
})
const lan = (address = '192.168.1.20', port = 45002): ConnectivityCandidate => ({
  candidateType: ConnectivityCandidateType.LAN_TCP,
  family: address.includes(':') ? 6 : 4,
  address,
  port,
  scope: address === '::1' || address.startsWith('127.') ? 'LOOPBACK' : 'LAN_PRIVATE'
})

function descriptor(
  server: Identity,
  candidates: readonly ConnectivityCandidate[],
  issuedAt = NOW,
  lifetimeSeconds = 300
): VerifiedConnectivityDescriptor {
  const raw = createSignedConnectivityDescriptor({
    serverId: server.serverId,
    serverPublicKey: server.publicKey,
    serverPrivateKey: server.privateKey,
    candidates,
    customIssuedAt: issuedAt,
    lifetimeSeconds,
    allowRawCandidatesForTesting: true,
    allowLoopbackForTesting: true
  })
  return verifySignedConnectivityDescriptor({
    encodedDescriptor: raw,
    expectedServerId: server.serverId,
    nowSeconds: issuedAt,
    allowLoopbackForTesting: true
  })
}

function endpointPair(store?: RendezvousDescriptorStore): {
  requester: PeerRendezvousEndpoint
  responder: PeerRendezvousEndpoint
  requesterChannel: AuthorizedPeerChannel
  close: () => void
} {
  const delivery: {
    requester?: (plaintext: Buffer) => Promise<void>
    responder?: (plaintext: Buffer) => Promise<void>
  } = {}
  const requesterSeam = tcpTransportTestOnly.createAuthorizedPeerChannel({
    onSend: async (plaintext) => delivery.responder!(plaintext)
  })
  const responderSeam = tcpTransportTestOnly.createAuthorizedPeerChannel({
    onSend: async (plaintext) => delivery.requester!(plaintext)
  })
  delivery.requester = requesterSeam.deliver
  delivery.responder = responderSeam.deliver
  const requester = createPeerRendezvousEndpoint({ channel: requesterSeam.channel })
  const responder = createPeerRendezvousEndpoint({ channel: responderSeam.channel, store })
  return {
    requester,
    responder,
    requesterChannel: requesterSeam.channel,
    close: () => { requesterSeam.close(); responderSeam.close() }
  }
}

describe('rendezvous shareability and ephemeral store', () => {
  it.each([
    ['PORT_MAPPED_TCP', [mapped()]],
    ['DIRECT_GLOBAL_TCP', [direct()]],
    ['mixed WAN', [mapped(), direct()]]
  ])('marks a fresh %s descriptor shareable without changing raw bytes', (_name, candidates) => {
    const server = identity()
    const verified = descriptor(server, candidates)
    const shareable = markRendezvousShareable(verified, NOW)
    expect(shareable.getRawEncoded()).toEqual(verified.rawEncoded)
    expect(shareable.getVerifiedDescriptor(NOW).expiresAt).toBe(verified.expiresAt)
  })

  it.each([
    ['LAN-only', [lan()]],
    ['LAN plus WAN', [lan(), mapped()]],
    ['loopback', [lan('127.0.0.1')]],
    ['IPv6 loopback', [lan('::1')]]
  ])('rejects %s descriptors before storage or racing', (_name, candidates) => {
    const server = identity()
    expect(() => markRendezvousShareable(descriptor(server, candidates), NOW)).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_DESCRIPTOR_NOT_SHAREABLE' })
    )
  })

  it('rejects expired descriptors and forged wrapper objects', () => {
    const server = identity()
    const verified = descriptor(server, [mapped()], NOW - 400)
    expect(() => markRendezvousShareable(verified, NOW)).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_DESCRIPTOR_INVALID' })
    )
    const store = new RendezvousDescriptorStore(() => NOW)
    expect(() => store.put({ serverId: server.serverId } as never)).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_DESCRIPTOR_INVALID' })
    )
  })

  it('uses signed timestamps and descriptorId for replacement and blocks rollback', () => {
    const server = identity()
    const store = new RendezvousDescriptorStore(() => NOW)
    const older = markRendezvousShareable(descriptor(server, [mapped('8.8.4.4')], NOW - 10), NOW)
    const newer = markRendezvousShareable(descriptor(server, [mapped('8.8.8.8')], NOW), NOW)
    expect(store.put(older)).toBe(true)
    expect(store.put(newer)).toBe(true)
    expect(store.put(older)).toBe(false)
    expect(store.get(server.serverId)?.getRawEncoded()).toEqual(newer.getRawEncoded())
  })

  it('purges on lookup, never extends signed expiry, and a new store is empty', () => {
    let now = NOW
    const server = identity()
    const verified = descriptor(server, [mapped()], NOW, 1)
    const shareable = markRendezvousShareable(verified, now)
    const store = new RendezvousDescriptorStore(() => now)
    store.put(shareable)
    now += 1
    expect(store.get(server.serverId)).toBeNull()
    expect(store.size).toBe(0)
    expect(new RendezvousDescriptorStore(() => now).size).toBe(0)
    expect(shareable.expiresAt).toBe(verified.expiresAt)
  })

  it('enforces entry and byte bounds independently', () => {
    const first = identity()
    const sample = markRendezvousShareable(descriptor(first, [mapped()]), NOW)
    const entryBound = new RendezvousDescriptorStore(() => NOW, 1)
    entryBound.put(sample)
    const second = identity()
    expect(() => entryBound.put(markRendezvousShareable(descriptor(second, [mapped()]), NOW))).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_STORE_FULL' })
    )
    const byteBound = new RendezvousDescriptorStore(() => NOW, MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES, sample.getRawEncoded().length)
    byteBound.put(sample)
    expect(() => byteBound.put(markRendezvousShareable(descriptor(second, [mapped()]), NOW))).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_STORE_FULL' })
    )
  })

  it('stays bounded when a sixty-fifth distinct server is inserted', () => {
    const store = new RendezvousDescriptorStore(() => NOW)
    for (let index = 0; index < MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES; index++) {
      const server = identity()
      store.put(markRendezvousShareable(descriptor(server, [mapped(`11.0.0.${index + 1}`)]), NOW))
    }
    const overflow = identity()
    expect(() => store.put(markRendezvousShareable(descriptor(overflow, [mapped('12.0.0.1')]), NOW))).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_STORE_FULL' })
    )
    expect(store.size).toBe(MAX_RENDEZVOUS_DESCRIPTOR_ENTRIES)
  })
})

describe('rendezvous protocol codec', () => {
  const serverId = `sha256:${'ab'.repeat(32)}`
  const nonce = Buffer.alloc(RENDEZVOUS_REQUEST_NONCE_BYTES, 0x5a)

  it('encodes the fixed request byte-exactly', () => {
    const encoded = encodeRendezvousRequest({ requestNonce: nonce, serverId })
    expect(encoded).toHaveLength(RENDEZVOUS_REQUEST_BYTES)
    expect(encoded[0]).toBe(RENDEZVOUS_PROTOCOL_VERSION)
    expect(encoded[1]).toBe(RendezvousMessageType.RENDEZVOUS_REQUEST)
    expect(encoded.subarray(2, 34)).toEqual(nonce)
    expect(encoded.subarray(34).toString('ascii')).toBe(serverId)
    expect(decodeRendezvousRequest(encoded)).toEqual({ requestNonce: nonce, serverId })
  })

  it('encodes FOUND with exact raw bytes and no peer signature', () => {
    const raw = Buffer.from([1, 2, 3, 4])
    const encoded = encodeRendezvousResponse({
      status: RendezvousResponseStatus.FOUND,
      requestNonce: nonce,
      serverId,
      descriptorBytes: raw
    })
    expect(encoded).toHaveLength(RENDEZVOUS_RESPONSE_HEADER_BYTES + raw.length)
    expect(encoded.readUInt16BE(RENDEZVOUS_RESPONSE_HEADER_BYTES - 2)).toBe(raw.length)
    expect(encoded.subarray(RENDEZVOUS_RESPONSE_HEADER_BYTES)).toEqual(raw)
    expect(decodeRendezvousResponse(encoded).descriptorBytes).toEqual(raw)
  })

  it('encodes one indistinguishable NOT_AVAILABLE outcome with zero descriptor bytes', () => {
    const encoded = encodeRendezvousResponse({
      status: RendezvousResponseStatus.NOT_AVAILABLE,
      requestNonce: nonce,
      serverId,
      descriptorBytes: Buffer.alloc(0)
    })
    expect(encoded).toHaveLength(RENDEZVOUS_RESPONSE_HEADER_BYTES)
    expect(encoded.readUInt16BE(encoded.length - 2)).toBe(0)
    expect(decodeRendezvousResponse(encoded).status).toBe(RendezvousResponseStatus.NOT_AVAILABLE)
  })

  it('rejects malformed, truncated, trailing, wrong-version/type/status/serverId inputs boundedly', () => {
    const request = encodeRendezvousRequest({ requestNonce: nonce, serverId })
    const response = encodeRendezvousResponse({
      status: RendezvousResponseStatus.NOT_AVAILABLE, requestNonce: nonce, serverId, descriptorBytes: Buffer.alloc(0)
    })
    const malformed = [
      Buffer.alloc(0), request.subarray(0, request.length - 1), Buffer.concat([request, Buffer.from([0])]),
      Buffer.from(request), Buffer.from(request), Buffer.from(request),
      response.subarray(0, response.length - 1), Buffer.concat([response, Buffer.from([0])]), Buffer.from(response)
    ]
    malformed[3]![0] = 2
    malformed[4]![1] = 0xff
    malformed[5]!.fill(0x41, 34)
    malformed[8]![2] = 0xff
    for (const buffer of malformed.slice(0, 6)) expect(() => decodeRendezvousRequest(buffer)).toThrowError(PeerRendezvousError)
    for (const buffer of malformed.slice(6)) expect(() => decodeRendezvousResponse(buffer)).toThrowError(PeerRendezvousError)
  })

  it('fuzzes arbitrary plaintext without accepting or allocating from declared lengths', () => {
    for (let length = 0; length < 300; length++) {
      const garbage = Buffer.alloc(length, length & 0xff)
      expect(() => decodeRendezvousRequest(garbage)).toThrowError(PeerRendezvousError)
      expect(() => decodeRendezvousResponse(garbage)).toThrowError(PeerRendezvousError)
    }
  })
})

describe('authorized endpoint requester/responder state', () => {
  afterEach(() => vi.useRealTimers())

  it('requires a runtime authorized channel; a pre-auth-shaped object is rejected', () => {
    expect(() => createPeerRendezvousEndpoint({ channel: {} as AuthorizedPeerChannel })).toThrowError(
      expect.objectContaining({ code: 'RENDEZVOUS_NOT_AUTHORIZED' })
    )
  })

  it('performs exact lookup, returns raw-identical verified bytes, and permits fresh logical replay', async () => {
    const server = identity()
    const shareable = markRendezvousShareable(descriptor(server, [mapped(), direct()]), NOW)
    const store = new RendezvousDescriptorStore(() => NOW)
    store.put(shareable)
    const pair = endpointPair(store)
    const first = await pair.requester.requestDescriptor(server.serverId)
    const second = await pair.requester.requestDescriptor(server.serverId)
    expect(first.getRawEncoded()).toEqual(shareable.getRawEncoded())
    expect(second.getRawEncoded()).toEqual(shareable.getRawEncoded())
    pair.close()
  })

  it('returns only NOT_AVAILABLE for a random exact serverId without enumerating cache keys', async () => {
    const store = new RendezvousDescriptorStore(() => NOW)
    const known = identity()
    store.put(markRendezvousShareable(descriptor(known, [mapped()]), NOW))
    const pair = endpointPair(store)
    await expect(pair.requester.requestDescriptor(identity().serverId)).rejects.toMatchObject({
      code: 'RENDEZVOUS_NOT_AVAILABLE'
    })
    expect(pair.requester).not.toHaveProperty('listServers')
    pair.close()
  })

  it('correlates nonce and exact serverId and rejects a descriptor signed by another server', async () => {
    const requested = identity()
    const other = identity()
    let outbound: Buffer | undefined
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: (plaintext) => { outbound = plaintext } })
    const endpoint = createPeerRendezvousEndpoint({ channel: seam.channel })
    const pending = endpoint.requestDescriptor(requested.serverId)
    await new Promise<void>((resolve) => setImmediate(resolve))
    const request = decodeRendezvousRequest(outbound!)
    const wrong = markRendezvousShareable(descriptor(other, [mapped()]), NOW)
    await seam.deliver(encodeRendezvousResponse({
      status: RendezvousResponseStatus.FOUND,
      requestNonce: request.requestNonce,
      serverId: requested.serverId,
      descriptorBytes: wrong.getRawEncoded()
    }))
    await expect(pending).rejects.toBeDefined()
    seam.close()
  })

  it('ignores an unknown nonce, rejects exact-nonce serverId mismatch, and uses fresh CSPRNG nonces', async () => {
    const requested = identity()
    const sent: Buffer[] = []
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: (plaintext) => { sent.push(plaintext) } })
    const endpoint = createPeerRendezvousEndpoint({ channel: seam.channel })
    const first = endpoint.requestDescriptor(requested.serverId)
    const second = endpoint.requestDescriptor(requested.serverId)
    first.catch(() => {})
    second.catch(() => {})
    await new Promise<void>((resolve) => setImmediate(resolve))
    const firstRequest = decodeRendezvousRequest(sent[0]!)
    const secondRequest = decodeRendezvousRequest(sent[1]!)
    expect(firstRequest.requestNonce).not.toEqual(secondRequest.requestNonce)

    await seam.deliver(encodeRendezvousResponse({
      status: RendezvousResponseStatus.NOT_AVAILABLE,
      requestNonce: Buffer.alloc(32, 0xee),
      serverId: requested.serverId,
      descriptorBytes: Buffer.alloc(0)
    }))
    expect(endpoint.outstandingRequests).toBe(2)

    await seam.deliver(encodeRendezvousResponse({
      status: RendezvousResponseStatus.NOT_AVAILABLE,
      requestNonce: firstRequest.requestNonce,
      serverId: identity().serverId,
      descriptorBytes: Buffer.alloc(0)
    }))
    await expect(first).rejects.toMatchObject({ code: 'RENDEZVOUS_SERVER_MISMATCH' })
    seam.close()
    await expect(second).rejects.toMatchObject({ code: 'RENDEZVOUS_CHANNEL_CLOSED' })
  })

  it('rejects tampered, LAN-containing and expired FOUND responses', async () => {
    const cases: Array<(server: Identity) => Buffer> = [
      (server) => {
        const raw = markRendezvousShareable(descriptor(server, [mapped()]), NOW).getRawEncoded()
        raw[raw.length - 1] = raw[raw.length - 1]! ^ 1
        return raw
      },
      (server) => descriptor(server, [lan()]).rawEncoded,
      (server) => descriptor(server, [mapped()], Math.floor(Date.now() / 1000) - 400).rawEncoded
    ]
    for (const makeRaw of cases) {
      const server = identity()
      let outbound: Buffer | undefined
      const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: (plaintext) => { outbound = plaintext } })
      const endpoint = createPeerRendezvousEndpoint({ channel: seam.channel })
      const pending = endpoint.requestDescriptor(server.serverId)
      await new Promise<void>((resolve) => setImmediate(resolve))
      const request = decodeRendezvousRequest(outbound!)
      await seam.deliver(encodeRendezvousResponse({
        status: RendezvousResponseStatus.FOUND,
        requestNonce: request.requestNonce,
        serverId: server.serverId,
        descriptorBytes: makeRaw(server)
      }))
      await expect(pending).rejects.toBeDefined()
      seam.close()
    }
  })

  it('bounds outstanding requests, times out, aborts, and cleans on channel close', async () => {
    vi.useFakeTimers()
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: () => {} })
    const endpoint = createPeerRendezvousEndpoint({ channel: seam.channel })
    const serverIds = Array.from({ length: MAX_RENDEZVOUS_OUTSTANDING_REQUESTS + 1 }, () => identity().serverId)
    const first = endpoint.requestDescriptor(serverIds[0]!, { timeoutMs: 100 })
    const second = endpoint.requestDescriptor(serverIds[1]!, { timeoutMs: 100 })
    await expect(endpoint.requestDescriptor(serverIds[2]!)).rejects.toMatchObject({ code: 'RENDEZVOUS_OUTSTANDING_LIMIT' })
    expect(endpoint.outstandingRequests).toBe(2)
    const firstExpectation = expect(first).rejects.toMatchObject({ code: 'RENDEZVOUS_TIMEOUT' })
    const secondExpectation = expect(second).rejects.toMatchObject({ code: 'RENDEZVOUS_TIMEOUT' })
    await vi.advanceTimersByTimeAsync(100)
    await firstExpectation
    await secondExpectation
    expect(endpoint.outstandingRequests).toBe(0)

    const controller = new AbortController()
    const aborted = endpoint.requestDescriptor(identity().serverId, { signal: controller.signal })
    controller.abort()
    await expect(aborted).rejects.toMatchObject({ code: 'RENDEZVOUS_ABORTED' })
    expect(endpoint.outstandingRequests).toBe(0)

    const closed = endpoint.requestDescriptor(identity().serverId)
    seam.close()
    await expect(closed).rejects.toMatchObject({ code: 'RENDEZVOUS_CHANNEL_CLOSED' })
  })

  it('enforces global and per-session rate bounds without unbounded work', async () => {
    let now = 0
    const limiter = new RendezvousGlobalRateLimiter(() => now)
    for (let index = 0; index < MAX_RENDEZVOUS_REQUESTS_GLOBAL; index++) expect(limiter.consume()).toBe(true)
    expect(limiter.consume()).toBe(false)
    now = 10_000
    expect(limiter.consume()).toBe(true)

    const responses: Buffer[] = []
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: (plaintext) => { responses.push(plaintext) } })
    const endpoint = createPeerRendezvousEndpoint({
      channel: seam.channel,
      store: new RendezvousDescriptorStore(() => NOW),
      globalRateLimiter: new RendezvousGlobalRateLimiter(() => 0),
      monotonicNowMs: () => 0
    })
    for (let index = 0; index < 10; index++) {
      await seam.deliver(encodeRendezvousRequest({
        requestNonce: Buffer.alloc(32, index + 1),
        serverId: identity().serverId
      }))
    }
    await expect(seam.deliver(encodeRendezvousRequest({
      requestNonce: Buffer.alloc(32, 12), serverId: identity().serverId
    }))).rejects.toMatchObject({ code: 'RENDEZVOUS_RATE_LIMITED' })
    expect(responses).toHaveLength(10)
    expect(endpoint.outstandingRequests).toBe(0)
    seam.close()
  })

  it('subsystem shutdown cancels pending rendezvous and releases global accounting', async () => {
    const subsystem = new ConnectivitySubsystem()
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: () => {} })
    const endpoint = createPeerRendezvousEndpoint({ channel: seam.channel, subsystem })
    const pending = endpoint.requestDescriptor(identity().serverId)
    expect(subsystem.governor.snapshot().counts.RENDEZVOUS_REQUEST).toBe(1)
    await subsystem.shutdown()
    await expect(pending).rejects.toMatchObject({ code: 'RENDEZVOUS_CHANNEL_CLOSED' })
    expect(subsystem.governor.snapshot().counts.RENDEZVOUS_REQUEST).toBe(0)
    await expect(endpoint.requestDescriptor(identity().serverId)).rejects.toMatchObject({ code: 'RENDEZVOUS_CHANNEL_CLOSED' })
  })

  it('propagates A to B to C with identical bytes and unchanged expiry', async () => {
    const server = identity()
    const original = markRendezvousShareable(descriptor(server, [mapped()], NOW), NOW)
    const storeA = new RendezvousDescriptorStore(() => NOW)
    const storeB = new RendezvousDescriptorStore(() => NOW)
    storeA.put(original)
    const ab = endpointPair(storeA)
    const receivedB = await ab.requester.requestDescriptor(server.serverId)
    storeB.put(receivedB)
    const bc = endpointPair(storeB)
    const receivedC = await bc.requester.requestDescriptor(server.serverId)
    expect(receivedC.getRawEncoded()).toEqual(original.getRawEncoded())
    expect(receivedC.expiresAt).toBe(original.expiresAt)
    ab.close(); bc.close()
  })

  it('does not push or gossip when an endpoint/store is created or populated', () => {
    let sends = 0
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ onSend: () => { sends += 1 } })
    const store = new RendezvousDescriptorStore(() => NOW)
    createPeerRendezvousEndpoint({ channel: seam.channel, store })
    const server = identity()
    store.put(markRendezvousShareable(descriptor(server, [mapped()]), NOW))
    expect(sends).toBe(0)
    seam.close()
  })
})
