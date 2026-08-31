import {
  ConnectivityResourceGovernor,
  type ConnectivityResourceReservation,
  defaultConnectivityResourceGovernor
} from './connectivity-resource-governor'

export const CONNECTIVITY_SHUTDOWN_TIMEOUT_MS = 5000

export type ConnectivitySubsystemState = 'RUNNING' | 'SHUTTING_DOWN' | 'SHUT_DOWN'
export type ConnectivitySubsystemErrorCode = 'CONNECTIVITY_SHUTTING_DOWN' | 'CONNECTIVITY_SHUT_DOWN'

export class ConnectivitySubsystemError extends Error {
  constructor(readonly code: ConnectivitySubsystemErrorCode) {
    super(code)
    this.name = 'ConnectivitySubsystemError'
  }
}

export interface ConnectivityOwnedResource {
  close(): void | Promise<void>
  forceClose?(): void
}

interface ResourceEntry { readonly resource: ConnectivityOwnedResource }

const OPERATION_TOKEN = Symbol('ConnectivityOperationHandle')

export class ConnectivityOperationHandle {
  private finished = false
  private readonly removeCallerAbort?: () => void

  constructor(
    token: symbol,
    readonly generation: number,
    readonly signal: AbortSignal,
    private readonly controller: AbortController,
    private readonly reservation: ConnectivityResourceReservation | undefined,
    callerSignal: AbortSignal | undefined,
    private readonly onFinish: () => void
  ) {
    if (token !== OPERATION_TOKEN) throw new ConnectivitySubsystemError('CONNECTIVITY_SHUT_DOWN')
    if (callerSignal) {
      const abort = (): void => controller.abort()
      callerSignal.addEventListener('abort', abort, { once: true })
      this.removeCallerAbort = () => callerSignal.removeEventListener('abort', abort)
      if (callerSignal.aborted) controller.abort()
    }
  }

  abort(): void { this.controller.abort() }

  finish(): void {
    if (this.finished) return
    this.finished = true
    this.removeCallerAbort?.()
    this.reservation?.release()
    this.onFinish()
  }
}

/** Explicit owner for cancellation and shutdown; importing it performs no network I/O. */
export class ConnectivitySubsystem {
  private state: ConnectivitySubsystemState = 'RUNNING'
  private generation = 0
  private readonly operations = new Set<ConnectivityOperationHandle>()
  private readonly resources = new Set<ResourceEntry>()
  private shutdownPromise?: Promise<void>

  constructor(
    readonly governor: ConnectivityResourceGovernor = new ConnectivityResourceGovernor(),
    private readonly shutdownTimeoutMs = CONNECTIVITY_SHUTDOWN_TIMEOUT_MS
  ) {
    if (!Number.isInteger(shutdownTimeoutMs) || shutdownTimeoutMs < 1 || shutdownTimeoutMs > CONNECTIVITY_SHUTDOWN_TIMEOUT_MS) {
      throw new ConnectivitySubsystemError('CONNECTIVITY_SHUT_DOWN')
    }
  }

  getState(): ConnectivitySubsystemState { return this.state }

  beginConnect(targetServerId: string, callerSignal?: AbortSignal): ConnectivityOperationHandle {
    if (this.state !== 'RUNNING') {
      throw new ConnectivitySubsystemError(this.state === 'SHUTTING_DOWN' ? 'CONNECTIVITY_SHUTTING_DOWN' : 'CONNECTIVITY_SHUT_DOWN')
    }
    const reservation = this.governor.reserveConnectOperation(targetServerId)
    const controller = new AbortController()
    const handle = new ConnectivityOperationHandle(
      OPERATION_TOKEN,
      ++this.generation,
      controller.signal,
      controller,
      reservation,
      callerSignal,
      () => this.operations.delete(handle)
    )
    this.operations.add(handle)
    if (this.state !== 'RUNNING') handle.abort()
    return handle
  }

  beginWork(callerSignal?: AbortSignal): ConnectivityOperationHandle {
    if (this.state !== 'RUNNING') {
      throw new ConnectivitySubsystemError(this.state === 'SHUTTING_DOWN' ? 'CONNECTIVITY_SHUTTING_DOWN' : 'CONNECTIVITY_SHUT_DOWN')
    }
    const controller = new AbortController()
    const handle = new ConnectivityOperationHandle(
      OPERATION_TOKEN,
      ++this.generation,
      controller.signal,
      controller,
      undefined,
      callerSignal,
      () => this.operations.delete(handle)
    )
    this.operations.add(handle)
    return handle
  }

  registerResource(resource: ConnectivityOwnedResource): () => void {
    if (this.state !== 'RUNNING') {
      throw new ConnectivitySubsystemError(this.state === 'SHUTTING_DOWN' ? 'CONNECTIVITY_SHUTTING_DOWN' : 'CONNECTIVITY_SHUT_DOWN')
    }
    const entry = Object.freeze({ resource })
    this.resources.add(entry)
    let removed = false
    return () => {
      if (removed) return
      removed = true
      this.resources.delete(entry)
    }
  }

  shutdown(): Promise<void> {
    if (this.shutdownPromise) return this.shutdownPromise
    this.state = 'SHUTTING_DOWN'
    for (const operation of [...this.operations]) {
      operation.abort()
      operation.finish()
    }
    const resources = [...this.resources]
    this.shutdownPromise = new Promise<void>((resolve) => {
      let settled = false
      const finish = (): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        for (const entry of resources) this.resources.delete(entry)
        this.state = 'SHUT_DOWN'
        resolve()
      }
      const timer = setTimeout(() => {
        for (const { resource } of resources) {
          try { resource.forceClose?.() } catch { /* forced cleanup is best effort */ }
        }
        finish()
      }, this.shutdownTimeoutMs)
      void Promise.allSettled(resources.map(async ({ resource }) => resource.close())).then(finish)
    })
    return this.shutdownPromise
  }
}

export const defaultConnectivitySubsystem = new ConnectivitySubsystem(defaultConnectivityResourceGovernor)

export function shutdownConnectivitySubsystem(): Promise<void> {
  return defaultConnectivitySubsystem.shutdown()
}
