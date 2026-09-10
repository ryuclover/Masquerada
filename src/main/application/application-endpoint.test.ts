import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type AuthorizedPeerChannel, tcpTransportTestOnly } from '../network/tcp-transport'
import {
  ApplicationEndpointError, ApplicationResources, createApplicationClient, createApplicationHost
} from './application-endpoint'
import {
  ApplicationProtocolError, createApplicationMessageId, decodeApplicationEnvelope,
  encodeApplicationEnvelope, type ApplicationEnvelope, type ServerState
} from './application-protocol'

const serverId = `sha256:${'a'.repeat(64)}`
const peerDeviceFingerprint = `sha256:${'b'.repeat(64)}`
const state: ServerState = { displayName: 'Server', channels: [{ channelId: '02'.repeat(16), name: 'General' }] }
const now = (): number => Date.now()
const cleanup: (() => void)[] = []

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function request(overrides: Partial<ApplicationEnvelope> = {}): Buffer {
  return encodeApplicationEnvelope({
    kind: 'request', messageType: 'server-state.request', messageId: createApplicationMessageId(),
    correlationId: null, serverId, channelId: null, sequence: null, payload: {}, ...overrides
  } as ApplicationEnvelope)
}

function response(correlationId: string, sequence = 1, overrides: Partial<ApplicationEnvelope> = {}): Buffer {
  return encodeApplicationEnvelope({
    kind: 'response', messageType: 'server-state.response', messageId: createApplicationMessageId(),
    correlationId, serverId, channelId: null, sequence,
    payload: { status: 'ok', server: { displayName: state.displayName }, channels: state.channels }, ...overrides
  } as ApplicationEnvelope)
}

function clientFixture(resources = new ApplicationResources()) {
  const sent: Buffer[] = []
  const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId, onSend: (frame) => { sent.push(frame) } })
  const client = createApplicationClient({ channel: seam.channel, expectedServerId: serverId, monotonicNowMs: now, resources })
  cleanup.push(client.close)
  return { ...seam, client, sent, resources }
}

function hostFixture(options: {
  resources?: ApplicationResources
  readServerState?: (context: { serverId: string; peerDeviceFingerprint: string }, signal: AbortSignal) => Promise<ServerState>
  authorizeServerStateRead?: (context: { serverId: string; peerDeviceFingerprint: string }, signal: AbortSignal) => Promise<void>
  sendMessage?: (context: { serverId: string; peerDeviceFingerprint: string }, draft: { channelId: string; clientMessageId: string; content: string }, signal: AbortSignal) => Promise<{ sequence: number; messageId: string; createdAt: number; dedup: boolean }>
  monotonicNowMs?: () => number
} = {}) {
  const resources = options.resources ?? new ApplicationResources()
  const sent: Buffer[] = []
  const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({
    serverId, peerDeviceFingerprint, onSend: (frame) => { sent.push(frame) }
  })
  const read = vi.fn(options.readServerState ?? (async () => state))
  const authorize = vi.fn(options.authorizeServerStateRead ?? (async () => {}))
  const send = vi.fn(options.sendMessage ?? (async (_context, draft) => ({
    sequence: 1, messageId: draft.clientMessageId, createdAt: 1700000000, dedup: false
  })))
  const host = createApplicationHost({
    channel: seam.channel, serverId, readServerState: read, authorizeServerStateRead: authorize, sendMessage: send,
    monotonicNowMs: options.monotonicNowMs ?? now, resources
  })
  cleanup.push(host.close)
  return { ...seam, host, sent, read, authorize, send, resources }
}

async function flush(): Promise<void> { await vi.advanceTimersByTimeAsync(0) }

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(0) })
afterEach(() => {
  for (const close of cleanup.splice(0)) close()
  expect(vi.getTimerCount()).toBe(0)
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('application endpoint capabilities and namespace', () => {
  it('rejects forged, closed and mismatched channels and missing host fingerprint', () => {
    const fake = { isClosed: () => false, getAuthorizationBinding: () => ({ serverId }) }
    expect(() => createApplicationClient({ channel: fake as AuthorizedPeerChannel, expectedServerId: serverId }))
      .toThrow(ApplicationEndpointError)
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId, onSend: () => {} })
    expect(() => createApplicationClient({ channel: seam.channel, expectedServerId: peerDeviceFingerprint }))
      .toThrow('INVALID_BINDING')
    expect(() => createApplicationHost({ channel: seam.channel, serverId,
      readServerState: async () => state, authorizeServerStateRead: async () => {}, sendMessage: async () => ({
        sequence: 1, messageId: 'a'.repeat(32), createdAt: 1, dedup: false
      }) })).toThrow('INVALID_BINDING')
    seam.close()
    expect(() => createApplicationClient({ channel: seam.channel, expectedServerId: serverId })).toThrow('INVALID_CHANNEL')
  })

  it('coexists with another namespace and unregisters exactly once without closing transport', async () => {
    const fixture = clientFixture()
    const other = vi.fn()
    const unregister = fixture.channel.registerMessageHandler([0x60], other)
    await fixture.deliver(Buffer.from([1, 0x60]))
    fixture.client.close()
    fixture.client.close()
    expect(fixture.channel.isClosed()).toBe(false)
    await fixture.deliver(Buffer.from([1, 0x60]))
    expect(other).toHaveBeenCalledTimes(2)
    await expect(fixture.deliver(response(createApplicationMessageId()))).rejects.toThrow()
    unregister()
  })

  it('rejects malformed, wrong direction and wrong scope before callbacks', async () => {
    const host = hostFixture()
    await expect(host.deliver(Buffer.from([1, 0x70, 0xff]))).rejects.toThrow(ApplicationProtocolError)
    await expect(host.deliver(response(createApplicationMessageId()))).rejects.toThrow('INVALID_SCOPE_OR_DIRECTION')
    await expect(host.deliver(request({ serverId: peerDeviceFingerprint }))).rejects.toThrow('INVALID_SCOPE_OR_DIRECTION')
    expect(host.authorize).not.toHaveBeenCalled()
    expect(host.read).not.toHaveBeenCalled()
    const client = clientFixture()
    await expect(client.deliver(request())).rejects.toThrow('INVALID_SCOPE_OR_DIRECTION')
    await expect(client.deliver(response(createApplicationMessageId(), 1, { serverId: peerDeviceFingerprint })))
      .rejects.toThrow('INVALID_SCOPE_OR_DIRECTION')
  })
})

describe('application client', () => {
  it('handles immediate loopback responses without leaking timers or accounting', async () => {
    const resources = new ApplicationResources()
    const seam = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId,
      onSend: (frame) => seam.deliver(response(decodeApplicationEnvelope(frame).messageId)) })
    const client = createApplicationClient({ channel: seam.channel, expectedServerId: serverId, resources, monotonicNowMs: now })
    cleanup.push(client.close)
    await expect(client.requestServerState()).resolves.toEqual(state)
    expect(resources.pendingClientRequests).toBe(0)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('matches concurrent correlation IDs rather than request order', async () => {
    const fixture = clientFixture()
    const first = fixture.client.requestServerState()
    const second = fixture.client.requestServerState()
    const ids = fixture.sent.map((frame) => decodeApplicationEnvelope(frame).messageId)
    expect(new Set(ids).size).toBe(2)
    await fixture.deliver(response(ids[1]!, 1))
    await expect(second).resolves.toEqual(state)
    expect(fixture.resources.pendingClientRequests).toBe(1)
    await fixture.deliver(response(ids[0]!, 2))
    await expect(first).resolves.toEqual(state)
  })

  it('counts timeout, abort, transport close and late send failure only once', async () => {
    const fixture = clientFixture()
    const release = vi.spyOn(fixture.resources, 'releaseClient')
    const signal = new AbortController()
    const remove = vi.spyOn(signal.signal, 'removeEventListener')
    const pending = fixture.client.requestServerState({ signal: signal.signal, timeoutMs: 100 }).catch((error) => error)
    await vi.advanceTimersByTimeAsync(100)
    expect(await pending).toMatchObject({ code: 'TIMEOUT' })
    signal.abort()
    fixture.close()
    fixture.client.close()
    expect(release).toHaveBeenCalledTimes(1)
    expect(remove).toHaveBeenCalledTimes(1)
    expect(fixture.resources.pendingClientRequests).toBe(0)
    await expect(fixture.client.requestServerState()).rejects.toThrow('CLOSED')
  })

  it('aborts pending and pre-aborted requests with no extra send', async () => {
    const fixture = clientFixture()
    const controller = new AbortController()
    const pending = fixture.client.requestServerState({ signal: controller.signal }).catch((error) => error)
    controller.abort()
    expect(await pending).toMatchObject({ code: 'ABORTED' })
    await expect(fixture.client.requestServerState({ signal: controller.signal })).rejects.toThrow('ABORTED')
    expect(fixture.sent).toHaveLength(1)
    expect(fixture.resources.pendingClientRequests).toBe(0)
  })

  it('rejects invalid deadlines and expires by monotonic time even before timer dispatch', async () => {
    const fixture = clientFixture()
    for (const timeoutMs of [0, -1, 5001, Infinity, NaN]) {
      await expect(fixture.client.requestServerState({ timeoutMs })).rejects.toThrow('INVALID_TIMEOUT')
    }
    const pending = fixture.client.requestServerState().catch((error) => error)
    vi.setSystemTime(5000)
    await fixture.deliver(response(decodeApplicationEnvelope(fixture.sent[0]!).messageId))
    expect(await pending).toMatchObject({ code: 'TIMEOUT' })
    expect(vi.getTimerCount()).toBe(0)
  })

  it('advances sequence for late and unknown valid responses but rejects replay and gaps', async () => {
    const fixture = clientFixture()
    const expired = fixture.client.requestServerState({ timeoutMs: 1 }).catch((error) => error)
    const id = decodeApplicationEnvelope(fixture.sent[0]!).messageId
    await vi.advanceTimersByTimeAsync(1)
    expect(await expired).toMatchObject({ code: 'TIMEOUT' })
    await fixture.deliver(response(id, 1))
    await fixture.deliver(response(createApplicationMessageId(), 2))
    await expect(fixture.deliver(response(id, 2))).rejects.toThrow('INVALID_SEQUENCE')
    await expect(fixture.deliver(response(id, 4))).rejects.toThrow('INVALID_SEQUENCE')
    const pending = fixture.client.requestServerState()
    const frame = response(decodeApplicationEnvelope(fixture.sent[1]!).messageId, 3)
    await fixture.deliver(frame)
    await expect(pending).resolves.toEqual(state)
    await expect(fixture.deliver(response(id, 4, { messageId: decodeApplicationEnvelope(frame).messageId })))
      .rejects.toThrow('DUPLICATE_MESSAGE_ID')
  })

  it('bounds all incoming frames including unknown valid responses', async () => {
    const fixture = clientFixture()
    for (let seq = 1; seq <= 128; seq++) await fixture.deliver(response(createApplicationMessageId(), seq))
    await expect(fixture.deliver(response(createApplicationMessageId(), 129))).rejects.toThrow('RATE_LIMITED')
    await vi.advanceTimersByTimeAsync(1000)
    await fixture.deliver(response(createApplicationMessageId(), 129))
  })

  it('limits pending requests to 8 locally and 128 globally', async () => {
    const resources = new ApplicationResources()
    const clients = Array.from({ length: 17 }, () => clientFixture(resources))
    const pending: Promise<unknown>[] = []
    for (const fixture of clients.slice(0, 16)) {
      for (let i = 0; i < 8; i++) pending.push(fixture.client.requestServerState().catch((error) => error))
    }
    expect(resources.pendingClientRequests).toBe(128)
    await expect(clients[0]!.client.requestServerState()).rejects.toThrow('RESOURCE_LIMIT')
    await expect(clients[16]!.client.requestServerState()).rejects.toThrow('RESOURCE_LIMIT')
    for (const fixture of clients) fixture.client.close()
    await Promise.all(pending)
    expect(resources.pendingClientRequests).toBe(0)
  })

  it('maps a safe host failure and a send failure without exposing details', async () => {
    const fixture = clientFixture()
    const pending = fixture.client.requestServerState().catch((error) => error)
    await fixture.deliver(response(decodeApplicationEnvelope(fixture.sent[0]!).messageId, 1, {
      payload: { status: 'error', code: 'UNAVAILABLE' }
    }))
    expect(await pending).toMatchObject({ code: 'UNAVAILABLE', message: 'UNAVAILABLE' })
    const write = deferred<void>()
    const send = vi.spyOn(fixture.channel, 'send').mockReturnValue(write.promise)
    const next = fixture.client.requestServerState().catch((error) => error)
    fixture.client.close()
    write.reject(new Error('secret storage path'))
    await flush()
    expect(await next).toMatchObject({ code: 'CLOSED' })
    expect(fixture.resources.pendingClientRequests).toBe(0)
    send.mockRestore()
  })
})

describe('application host', () => {
  it('authorizes before read and again before disclosure, with host assigned sequences', async () => {
    const fixture = hostFixture()
    const first = request()
    await fixture.deliver(first)
    await flush()
    expect(fixture.authorize).toHaveBeenCalledTimes(2)
    expect(fixture.authorize).toHaveBeenCalledWith({ serverId, peerDeviceFingerprint }, expect.any(AbortSignal))
    expect(fixture.authorize.mock.invocationCallOrder[0]).toBeLessThan(fixture.read.mock.invocationCallOrder[0]!)
    expect(fixture.read.mock.invocationCallOrder[0]).toBeLessThan(fixture.authorize.mock.invocationCallOrder[1]!)
    expect(decodeApplicationEnvelope(fixture.sent[0]!)).toMatchObject({
      correlationId: decodeApplicationEnvelope(first).messageId, sequence: 1,
      payload: { status: 'ok', server: { displayName: state.displayName }, channels: state.channels }
    })
    await fixture.deliver(request())
    await flush()
    expect(decodeApplicationEnvelope(fixture.sent[1]!)).toMatchObject({ sequence: 2 })
    expect(fixture.resources.activeHostRequests).toBe(0)
  })

  it.each(['authorization', 'read', 'reauthorization'])('returns only UNAVAILABLE on %s failure', async (stage) => {
    let calls = 0
    const fixture = hostFixture({
      authorizeServerStateRead: async () => {
        calls++
        if (stage === 'authorization' || (stage === 'reauthorization' && calls === 2)) throw new Error('secret auth details')
      },
      readServerState: async () => {
        if (stage === 'read') throw new Error('secret database path')
        return state
      }
    })
    await fixture.deliver(request())
    await flush()
    expect(decodeApplicationEnvelope(fixture.sent[0]!).payload).toEqual({ status: 'error', code: 'UNAVAILABLE' })
    expect(fixture.sent[0]!.toString()).not.toContain('secret')
    if (stage === 'authorization') expect(fixture.read).not.toHaveBeenCalled()
  })

  it.each(['authorization', 'read', 'reauthorization'])('checks monotonic deadline after %s await', async (stage) => {
    let time = 0
    let calls = 0
    const fixture = hostFixture({
      monotonicNowMs: () => time,
      authorizeServerStateRead: async () => {
        calls++
        if (stage === 'authorization' || (stage === 'reauthorization' && calls === 2)) time = 5000
      },
      readServerState: async () => { if (stage === 'read') time = 5000; return state }
    })
    await fixture.deliver(request())
    await flush()
    expect(fixture.sent).toHaveLength(0)
    expect(fixture.resources.activeHostRequests).toBe(0)
    if (stage === 'authorization') expect(fixture.read).not.toHaveBeenCalled()
  })

  it('keeps blocked callback capacity after timeout/close and releases exactly once when it finishes', async () => {
    const blocked = deferred<ServerState>()
    let signal!: AbortSignal
    const fixture = hostFixture({ readServerState: async (_, sig) => { signal = sig; return blocked.promise } })
    const release = vi.spyOn(fixture.resources, 'releaseHost')
    await fixture.deliver(request())
    await flush()
    await vi.advanceTimersByTimeAsync(5000)
    expect(signal.aborted).toBe(true)
    expect(fixture.resources.activeHostRequests).toBe(1)
    expect(vi.getTimerCount()).toBe(0)
    await fixture.deliver(request())
    expect(fixture.read).toHaveBeenCalledTimes(1)
    expect(decodeApplicationEnvelope(fixture.sent[0]!).payload).toEqual({ status: 'error', code: 'UNAVAILABLE' })
    fixture.host.close()
    fixture.close()
    expect(fixture.resources.activeHostRequests).toBe(1)
    blocked.resolve(state)
    await flush()
    expect(release).toHaveBeenCalledTimes(1)
    expect(fixture.resources.activeHostRequests).toBe(0)
    expect(fixture.sent).toHaveLength(1)
  })

  it('holds the global 32 slots while callbacks ignore cancellation; never queues overflow', async () => {
    const resources = new ApplicationResources()
    const blocked = deferred<ServerState>()
    const hosts = Array.from({ length: 33 }, () => hostFixture({ resources, readServerState: () => blocked.promise }))
    for (const fixture of hosts) await fixture.deliver(request())
    await flush()
    expect(resources.activeHostRequests).toBe(32)
    expect(hosts[32]!.read).not.toHaveBeenCalled()
    expect(decodeApplicationEnvelope(hosts[32]!.sent[0]!).payload).toEqual({ status: 'error', code: 'UNAVAILABLE' })
    for (const fixture of hosts) fixture.host.close()
    expect(resources.activeHostRequests).toBe(32)
    blocked.resolve(state)
    await flush()
    expect(resources.activeHostRequests).toBe(0)
    for (const fixture of hosts.slice(0, 32)) expect(fixture.sent).toHaveLength(0)
  })

  it('bounds host requests to burst 8 and refill 4 per second', async () => {
    const fixture = hostFixture()
    for (let i = 0; i < 8; i++) { await fixture.deliver(request()); await flush() }
    await expect(fixture.deliver(request())).rejects.toThrow('RATE_LIMITED')
    await vi.advanceTimersByTimeAsync(250)
    await fixture.deliver(request())
    await flush()
    await expect(fixture.deliver(request())).rejects.toThrow('RATE_LIMITED')
    expect(fixture.read).toHaveBeenCalledTimes(9)
  })

  it('bounds global host requests to burst 128 and refill 64 per second', async () => {
    const resources = new ApplicationResources()
    const hosts = Array.from({ length: 17 }, () => hostFixture({ resources }))
    for (const fixture of hosts.slice(0, 16)) {
      for (let i = 0; i < 8; i++) { await fixture.deliver(request()); await flush() }
    }
    await expect(hosts[16]!.deliver(request())).rejects.toThrow('RATE_LIMITED')
    await vi.advanceTimersByTimeAsync(16)
    await hosts[16]!.deliver(request())
    await flush()
    expect(hosts[16]!.read).toHaveBeenCalledTimes(1)
    await expect(hosts[16]!.deliver(request())).rejects.toThrow('RATE_LIMITED')
  })

  it('rejects recent replay, expires IDs at 30 seconds and caps the cache at 256', async () => {
    const fixture = hostFixture()
    const first = request()
    await fixture.deliver(first)
    await flush()
    await expect(fixture.deliver(first)).rejects.toThrow('DUPLICATE_MESSAGE_ID')
    await vi.advanceTimersByTimeAsync(30_000)
    await fixture.deliver(first)
    await flush()
    // Rejected overload requests also consume bounded replay-cache entries.
    for (let i = 0; i < 256; i++) {
      await vi.advanceTimersByTimeAsync(16)
      await fixture.deliver(request()).catch((error) => expect(error.code).toBe('RATE_LIMITED'))
      await flush()
    }
    await vi.advanceTimersByTimeAsync(250)
    await fixture.deliver(first)
    await flush()
  })

  it('supports synchronous paired delivery and a next request from a response continuation', async () => {
    const resources = new ApplicationResources()
    const clientSeam = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId, onSend: (frame) => hostSeam.deliver(frame) })
    const hostSeam = tcpTransportTestOnly.createAuthorizedPeerChannel({ serverId, peerDeviceFingerprint, onSend: (frame) => clientSeam.deliver(frame) })
    const host = createApplicationHost({ channel: hostSeam.channel, serverId,
      readServerState: async () => state, authorizeServerStateRead: async () => {}, sendMessage: async () => ({
        sequence: 1, messageId: 'a'.repeat(32), createdAt: 1, dedup: false
      }), resources, monotonicNowMs: now })
    const client = createApplicationClient({ channel: clientSeam.channel, expectedServerId: serverId, resources, monotonicNowMs: now })
    cleanup.push(host.close, client.close)
    await expect(client.requestServerState().then(() => client.requestServerState())).resolves.toEqual(state)
    expect(resources.pendingClientRequests).toBe(0)
    expect(resources.activeHostRequests).toBe(0)
  })
})
