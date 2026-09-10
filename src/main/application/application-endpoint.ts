import { performance } from 'node:perf_hooks'
import { isAuthorizedPeerChannel, type AuthorizedPeerChannel } from '../network/tcp-transport'
import {
  APPLICATION_MESSAGE_TYPE,
  ApplicationProtocolError,
  createApplicationMessageId,
  decodeApplicationEnvelope,
  encodeApplicationEnvelope,
  type ApplicationEnvelope,
  type HistoryQuery,
  type HistoryResponsePayload,
  type HistoryWireMessage,
  type MessageSendAccepted,
  type MessageSendDraft,
  type MessageSendResponsePayload,
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
  requestHistory(query: HistoryQuery, options?: { signal?: AbortSignal; timeoutMs?: number }): Promise<{ messages: readonly HistoryWireMessage[]; hasMore: boolean }>
  sendMessage(draft: MessageSendDraft, options?: { signal?: AbortSignal; timeoutMs?: number }): Promise<MessageSendAccepted>
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
    finish(error?: ApplicationEndpointError, result?: PendingResult): void
  }>()
  type PendingResult = ServerState | { messages: readonly HistoryWireMessage[]; hasMore: boolean } | MessageSendAccepted
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
      request.finish(new ApplicationEndpointError(envelope.payload.code))
    } else if (envelope.payload.status === 'ok' && 'server' in envelope.payload) {
      request.finish(undefined, {
        displayName: envelope.payload.server.displayName,
        channels: envelope.payload.channels
      })
    } else if (envelope.payload.status === 'ok' && 'messages' in envelope.payload) {
      request.finish(undefined, {
        messages: envelope.payload.messages,
        hasMore: envelope.payload.hasMore
      })
    } else if (envelope.payload.status === 'ok' && 'accepted' in envelope.payload) {
      request.finish(undefined, envelope.payload.accepted)
    }
  })
  removeClose = channel.onClose(close)

  function issueRequest(
    messageType: 'server-state.request' | 'history.request' | 'message.send.request',
    payload: Record<string, never> | HistoryQuery | MessageSendDraft,
    requestOptions: { signal?: AbortSignal; timeoutMs?: number }
  ): Promise<PendingResult> {
    const { signal, timeoutMs = DEADLINE_MS } = requestOptions
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > DEADLINE_MS) {
      return Promise.reject(new ApplicationEndpointError('INVALID_TIMEOUT'))
    }
    if (signal?.aborted) return Promise.reject(new ApplicationEndpointError('ABORTED'))
    if (pending.size >= 8 || !resources.acquireClient()) {
      return Promise.reject(new ApplicationEndpointError('RESOURCE_LIMIT'))
    }
    return new Promise<PendingResult>((resolve, reject) => {
      let finished = false
      let timer: ReturnType<typeof setTimeout> | undefined
      let messageId: string | undefined
      let registered = false
      const deadline = now() + timeoutMs
      const abort = (): void => finish(new ApplicationEndpointError('ABORTED'))
      function finish(error?: ApplicationEndpointError, result?: PendingResult): void {
        if (finished) return
        finished = true
        if (timer !== undefined) clearTimeout(timer)
        signal?.removeEventListener('abort', abort)
        if (registered) pending.delete(messageId!)
        resources.releaseClient()
        if (error) reject(error)
        else resolve(result!)
      }
      try {
        messageId = createApplicationMessageId()
        if (pending.has(messageId)) throw new ApplicationProtocolError('DUPLICATE_MESSAGE_ID')
        remember(requestIds, messageId, now())
        const frame = encodeApplicationEnvelope({
          kind: 'request', messageType, messageId,
          correlationId: null, serverId: expectedServerId, channelId: null, sequence: null,
          payload
        } as ApplicationEnvelope)
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

  function requestServerState(requestOptions: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<ServerState> {
    if (closed) return Promise.reject(new ApplicationEndpointError('CLOSED'))
    return issueRequest('server-state.request', {}, requestOptions) as Promise<ServerState>
  }

  function requestHistory(
    query: HistoryQuery,
    requestOptions: { signal?: AbortSignal; timeoutMs?: number } = {}
  ): Promise<{ messages: readonly HistoryWireMessage[]; hasMore: boolean }> {
    if (closed) return Promise.reject(new ApplicationEndpointError('CLOSED'))
    return issueRequest('history.request', query, requestOptions) as Promise<{ messages: readonly HistoryWireMessage[]; hasMore: boolean }>
  }

  function sendMessage(
    draft: MessageSendDraft,
    requestOptions: { signal?: AbortSignal; timeoutMs?: number } = {}
  ): Promise<MessageSendAccepted> {
    if (closed) return Promise.reject(new ApplicationEndpointError('CLOSED'))
    return issueRequest('message.send.request', draft, requestOptions) as Promise<MessageSendAccepted>
  }
  return { requestServerState, requestHistory, sendMessage, close }
}

type ReadContext = Readonly<{ serverId: string; peerDeviceFingerprint: string }>

export interface HistoryPage {
  readonly messages: readonly HistoryWireMessage[]
  readonly hasMore: boolean
}

export function createApplicationHost(options: EndpointOptions & {
  serverId: string
  readServerState: (context: ReadContext, signal: AbortSignal) => Promise<ServerState>
  readServerHistory?: (context: ReadContext, query: HistoryQuery, signal: AbortSignal) => Promise<HistoryPage>
  sendMessage: (context: ReadContext, draft: MessageSendDraft, signal: AbortSignal) => Promise<MessageSendAccepted>
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

  function sendResponse(
    request: ApplicationEnvelope & { kind: 'request' },
    payload: ServerStateResponsePayload | HistoryResponsePayload | MessageSendResponsePayload,
    deadline: number
  ): void {
    if (closed || now() >= deadline) return
    if (sequence === Number.MAX_SAFE_INTEGER) {
      close()
      return
    }
    const frame = encodeApplicationEnvelope({
      kind: 'response',
      messageType: request.messageType === 'history.request' ? 'history.response'
        : request.messageType === 'message.send.request' ? 'message.send.response'
        : 'server-state.response',
      messageId: createApplicationMessageId(),
      correlationId: request.messageId, serverId, channelId: null, sequence: sequence + 1, payload
    } as ApplicationEnvelope)
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
      let payload: ServerStateResponsePayload | HistoryResponsePayload | MessageSendResponsePayload
      if (request.messageType === 'history.request') {
        const query = request.payload as HistoryQuery
        const page = await options.readServerHistory!(context, query, operation.controller.signal)
        if (!live()) return
        await options.authorizeServerStateRead(context, operation.controller.signal)
        if (!live()) return
        // Deterministic batch reduction keeps large contents under the wire payload limit.
        let messages = page.messages
        for (;;) {
          payload = { status: 'ok', messages, hasMore: page.hasMore || messages.length < page.messages.length }
          try {
            sendResponse(request, payload, deadline)
            return
          } catch (error) {
            const oversize = error instanceof ApplicationProtocolError &&
              (error.code === 'APPLICATION_PAYLOAD_TOO_LARGE' || error.code === 'APPLICATION_BODY_TOO_LARGE')
            if (!oversize || messages.length <= 1) throw error
            messages = messages.slice(0, Math.ceil(messages.length / 2))
          }
        }
      } else if (request.messageType === 'message.send.request') {
        const draft = request.payload as MessageSendDraft
        const accepted = await options.sendMessage(context, draft, operation.controller.signal)
        if (!live()) return
        payload = { status: 'ok', accepted }
      } else {
        const state = await options.readServerState(context, operation.controller.signal)
        if (!live()) return
        await options.authorizeServerStateRead(context, operation.controller.signal)
        if (!live()) return
        payload = { status: 'ok', server: { displayName: state.displayName }, channels: state.channels }
      }
      sendResponse(request, payload, deadline)
    } catch (error) {
      if (live()) {
        try { sendResponse(request, { status: 'error', code: sendErrorCode(error) }, deadline) }
        catch { close() }
      }
    } finally {
      // Timeout/close cancels work but cannot free capacity while a callback still runs.
      if (operation.timer !== undefined) clearTimeout(operation.timer)
      active = undefined
      resources.releaseHost()
    }
  }

  function sendErrorCode(error: unknown): Exclude<MessageSendResponsePayload, { status: 'ok' }>['code'] {
    if (error instanceof ApplicationEndpointError) {
      const mapping: Record<string, Exclude<MessageSendResponsePayload, { status: 'ok' }>['code']> = {
        APPLICATION_NOT_AUTHORIZED: 'FORBIDDEN',
        SERVER_CHANNEL_ARCHIVED: 'ARCHIVED',
        SERVER_CHANNEL_NOT_FOUND: 'NOT_FOUND',
        SERVER_MESSAGE_NOT_FOUND: 'NOT_FOUND',
        SERVER_MESSAGE_FORBIDDEN: 'FORBIDDEN',
        SERVER_MESSAGE_CAPACITY_REACHED: 'CAPACITY',
        SERVER_MESSAGE_DUPLICATE: 'INVALID',
        SERVER_MESSAGE_INVALID: 'INVALID',
        SERVER_CHANNEL_INVALID: 'INVALID'
      }
      return mapping[error.code] ?? 'UNAVAILABLE'
    }
    return 'UNAVAILABLE'
  }

  unregister = channel.registerMessageHandler([APPLICATION_MESSAGE_TYPE], (frame) => {
    if (closed) return
    const time = now()
    if (!inputRate.take(time)) throw new ApplicationProtocolError('RATE_LIMITED')
    const request = decodeApplicationEnvelope(frame)
    if (request.kind !== 'request' || request.serverId !== serverId) {
      throw new ApplicationProtocolError('INVALID_SCOPE_OR_DIRECTION')
    }
    if (request.messageType === 'history.request' && !options.readServerHistory) {
      throw new ApplicationProtocolError('UNSUPPORTED_MESSAGE_TYPE')
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
