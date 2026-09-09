import { performance } from 'node:perf_hooks'
import { isAuthorizedPeerChannel, type AuthorizedPeerChannel } from '../network/tcp-transport'
import {
  APPLICATION_MESSAGE_TYPE,
  ApplicationProtocolError,
  createApplicationMessageId,
  decodeApplicationEnvelope,
  encodeApplicationEnvelope,
  type ApplicationEnvelope,
  type ServerState,
  type ServerStateResponsePayload
} from './application-protocol'

export class ApplicationEndpointError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'ApplicationEndpointError'
  }
}

class RateLimit {
  private tokens: number
  private updatedAt: number | undefined

  constructor(private readonly rate: number, private readonly burst: number) {
    this.tokens = burst
  }

  take(now: number): boolean {
    if (this.updatedAt !== undefined) {
      this.tokens = Math.min(this.burst, this.tokens + Math.max(0, now - this.updatedAt) * this.rate / 1000)
    }
    this.updatedAt = Math.max(this.updatedAt ?? now, now)
    if (this.tokens < 1) return false
    this.tokens--
    return true
  }
}

/** Shared by default; inject one instance across endpoints for isolated resource accounting. */
export class ApplicationResources {
  private clients = 0
  private hosts = 0
  private readonly requests = new RateLimit(64, 128)

  get pendingClientRequests(): number { return this.clients }
  get activeHostRequests(): number { return this.hosts }

  acquireClient(): boolean {
    if (this.clients >= 128) return false
    this.clients++
    return true
  }

  releaseClient(): void { this.clients-- }

  acquireHost(): boolean {
    if (this.hosts >= 32) return false
    this.hosts++
    return true
  }

  releaseHost(): void { this.hosts-- }
  takeHostRequest(now: number): boolean { return this.requests.take(now) }
}

const sharedResources = new ApplicationResources()
const monotonicNowMs = (): number => performance.now()
const DEADLINE_MS = 5000

function checkChannel(channel: AuthorizedPeerChannel, serverId: string, host = false): void {
  if (!isAuthorizedPeerChannel(channel) || channel.isClosed()) {
    throw new ApplicationEndpointError('INVALID_CHANNEL')
  }
  const binding = channel.getAuthorizationBinding()
  if (!/^sha256:[0-9a-f]{64}$/.test(serverId) || binding.serverId !== serverId ||
      (host && !/^sha256:[0-9a-f]{64}$/.test(binding.peerDeviceFingerprint ?? ''))) {
    throw new ApplicationEndpointError('INVALID_BINDING')
  }
}

function remember(ids: Map<string, number>, id: string, now: number): void {
  for (const [key, expires] of ids) {
    if (expires <= now) ids.delete(key)
  }
  if (ids.has(id)) throw new ApplicationProtocolError('DUPLICATE_MESSAGE_ID')
  if (ids.size >= 256) ids.delete(ids.keys().next().value!)
  ids.set(id, now + 30_000)
}

interface EndpointOptions {
  channel: AuthorizedPeerChannel
  monotonicNowMs?: () => number
  resources?: ApplicationResources
}

export function createApplicationClient(options: EndpointOptions & { expectedServerId: string }): {
  requestServerState(options?: { signal?: AbortSignal; timeoutMs?: number }): Promise<ServerState>
  close(): void
} {
  const { channel, expectedServerId, resources = sharedResources } = options
  const now = options.monotonicNowMs ?? monotonicNowMs
  checkChannel(channel, expectedServerId)
  const inputRate = new RateLimit(64, 128)
  const requestIds = new Map<string, number>()
  const responseIds = new Map<string, number>()
  const pending = new Map<string, {
    deadline: number
    finish(error?: ApplicationEndpointError, state?: ServerState): void
  }>()
  let closed = false
  let sequence = 0
  let unregister = (): void => {}
  let removeClose = (): void => {}

  function close(): void {
    if (closed) return
    closed = true
    unregister()
    removeClose()
    for (const request of pending.values()) request.finish(new ApplicationEndpointError('CLOSED'))
    requestIds.clear()
    responseIds.clear()
  }

  unregister = channel.registerMessageHandler([APPLICATION_MESSAGE_TYPE], (frame) => {
    if (closed) return
    const time = now()
    if (!inputRate.take(time)) throw new ApplicationProtocolError('RATE_LIMITED')
    const envelope = decodeApplicationEnvelope(frame)
    if (envelope.kind !== 'response' || envelope.serverId !== expectedServerId) {
      throw new ApplicationProtocolError('INVALID_SCOPE_OR_DIRECTION')
    }
    if (sequence === Number.MAX_SAFE_INTEGER || envelope.sequence !== sequence + 1) {
      throw new ApplicationProtocolError('INVALID_SEQUENCE')
    }
    remember(responseIds, envelope.messageId, time)
    sequence = envelope.sequence
    const request = pending.get(envelope.correlationId)
    if (!request) return
    if (time >= request.deadline) {
      request.finish(new ApplicationEndpointError('TIMEOUT'))
    } else if (envelope.payload.status === 'error') {
      request.finish(new ApplicationEndpointError('UNAVAILABLE'))
    } else {
      request.finish(undefined, {
        displayName: envelope.payload.server.displayName,
        channels: envelope.payload.channels
      })
    }
  })
  removeClose = channel.onClose(close)

  function requestServerState(requestOptions: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<ServerState> {
    if (closed) return Promise.reject(new ApplicationEndpointError('CLOSED'))
    const { signal, timeoutMs = DEADLINE_MS } = requestOptions
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > DEADLINE_MS) {
      return Promise.reject(new ApplicationEndpointError('INVALID_TIMEOUT'))
    }
    if (signal?.aborted) return Promise.reject(new ApplicationEndpointError('ABORTED'))
    if (pending.size >= 8 || !resources.acquireClient()) {
      return Promise.reject(new ApplicationEndpointError('RESOURCE_LIMIT'))
    }
    return new Promise<ServerState>((resolve, reject) => {
      let finished = false
      let timer: ReturnType<typeof setTimeout> | undefined
      let messageId: string | undefined
      let registered = false
      const deadline = now() + timeoutMs
      const abort = (): void => finish(new ApplicationEndpointError('ABORTED'))
      function finish(error?: ApplicationEndpointError, state?: ServerState): void {
        if (finished) return
        finished = true
        if (timer !== undefined) clearTimeout(timer)
        signal?.removeEventListener('abort', abort)
        if (registered) pending.delete(messageId!)
        resources.releaseClient()
        if (error) reject(error)
        else resolve(state!)
      }
      try {
        messageId = createApplicationMessageId()
        if (pending.has(messageId)) throw new ApplicationProtocolError('DUPLICATE_MESSAGE_ID')
        remember(requestIds, messageId, now())
        const frame = encodeApplicationEnvelope({
          kind: 'request', messageType: 'server-state.request', messageId,
          correlationId: null, serverId: expectedServerId, channelId: null, sequence: null, payload: {}
        })
        pending.set(messageId, { deadline, finish })
        registered = true
        timer = setTimeout(() => finish(new ApplicationEndpointError('TIMEOUT')), timeoutMs)
        signal?.addEventListener('abort', abort, { once: true })
        if (signal?.aborted) abort()
        if (finished) return
        if (now() >= deadline) {
          finish(new ApplicationEndpointError('TIMEOUT'))
          return
        }
        // Register before send: test channels and loopback transports may respond synchronously.
        void channel.send(frame).then(() => {
          if (now() >= deadline) finish(new ApplicationEndpointError('TIMEOUT'))
        }, () => finish(new ApplicationEndpointError('UNAVAILABLE')))
      } catch {
        finish(new ApplicationEndpointError('UNAVAILABLE'))
      }
    })
  }

  return { requestServerState, close }
}

type ReadContext = Readonly<{ serverId: string; peerDeviceFingerprint: string }>

export function createApplicationHost(options: EndpointOptions & {
  serverId: string
  readServerState: (context: ReadContext, signal: AbortSignal) => Promise<ServerState>
  authorizeServerStateRead: (context: ReadContext, signal: AbortSignal) => Promise<void>
}): { close(): void } {
  const { channel, serverId, resources = sharedResources } = options
  const now = options.monotonicNowMs ?? monotonicNowMs
  checkChannel(channel, serverId, true)
  const context = Object.freeze({ serverId, peerDeviceFingerprint: channel.getAuthorizationBinding().peerDeviceFingerprint! })
  const inputRate = new RateLimit(64, 128)
  const requestRate = new RateLimit(4, 8)
  const recentIds = new Map<string, number>()
  let closed = false
  let sequence = 0
  let active: { controller: AbortController; timer?: ReturnType<typeof setTimeout> } | undefined
  let unregister = (): void => {}
  let removeClose = (): void => {}

  function cancel(): void {
    if (!active) return
    if (active.timer !== undefined) {
      clearTimeout(active.timer)
      active.timer = undefined
    }
    if (!active.controller.signal.aborted) active.controller.abort()
  }

  function close(): void {
    if (closed) return
    closed = true
    unregister()
    removeClose()
    cancel()
    recentIds.clear()
  }

  function sendResponse(request: ApplicationEnvelope & { kind: 'request' }, payload: ServerStateResponsePayload, deadline: number): void {
    if (closed || now() >= deadline) return
    if (sequence === Number.MAX_SAFE_INTEGER) {
      close()
      return
    }
    const frame = encodeApplicationEnvelope({
      kind: 'response', messageType: 'server-state.response', messageId: createApplicationMessageId(),
      correlationId: request.messageId, serverId, channelId: null, sequence: sequence + 1, payload
    })
    if (closed || now() >= deadline) return
    sequence++
    // Do not await peer dispatch: a peer can issue its next request during this send.
    void channel.send(frame).catch(close)
  }

  async function serve(request: ApplicationEnvelope & { kind: 'request' }, deadline: number): Promise<void> {
    const operation = active!
    const live = (): boolean => {
      if (closed || operation.controller.signal.aborted) return false
      if (now() >= deadline) {
        cancel()
        return false
      }
      return true
    }
    try {
      if (!live()) return
      await options.authorizeServerStateRead(context, operation.controller.signal)
      if (!live()) return
      const state = await options.readServerState(context, operation.controller.signal)
      if (!live()) return
      await options.authorizeServerStateRead(context, operation.controller.signal)
      if (!live()) return
      sendResponse(request, { status: 'ok', server: { displayName: state.displayName }, channels: state.channels }, deadline)
    } catch {
      if (live()) {
        try { sendResponse(request, { status: 'error', code: 'UNAVAILABLE' }, deadline) }
        catch { close() }
      }
    } finally {
      // Timeout/close cancels work but cannot free capacity while a callback still runs.
      if (operation.timer !== undefined) clearTimeout(operation.timer)
      active = undefined
      resources.releaseHost()
    }
  }

  unregister = channel.registerMessageHandler([APPLICATION_MESSAGE_TYPE], (frame) => {
    if (closed) return
    const time = now()
    if (!inputRate.take(time)) throw new ApplicationProtocolError('RATE_LIMITED')
    const request = decodeApplicationEnvelope(frame)
    if (request.kind !== 'request' || request.serverId !== serverId) {
      throw new ApplicationProtocolError('INVALID_SCOPE_OR_DIRECTION')
    }
    remember(recentIds, request.messageId, time)
    if (!requestRate.take(time) || !resources.takeHostRequest(time)) {
      throw new ApplicationProtocolError('RATE_LIMITED')
    }
    const deadline = time + DEADLINE_MS
    if (active || !resources.acquireHost()) {
      sendResponse(request, { status: 'error', code: 'UNAVAILABLE' }, deadline)
      return
    }
    active = { controller: new AbortController() }
    active.timer = setTimeout(cancel, DEADLINE_MS)
    void serve(request, deadline)
  })
  removeClose = channel.onClose(close)
  return { close }
}
