export const MAX_CONCURRENT_CONNECT_OPERATIONS = 8
export const MAX_PENDING_SECURE_CONNECTION_ATTEMPTS = 16
export const MAX_PENDING_UDP_OPERATIONS = 8
export const MAX_GOVERNED_RELAY_CIRCUITS = 32
export const MAX_GOVERNED_RELAY_QUEUED_BYTES = 1024 * 1024
export const MAX_PENDING_RENDEZVOUS_REQUESTS = 32

export type ConnectivityResourceCategory =
  | 'CONNECT_OPERATION'
  | 'SECURE_CONNECTION_ATTEMPT'
  | 'UDP_OPERATION'
  | 'RELAY_CIRCUIT'
  | 'RELAY_QUEUED_BYTES'
  | 'RENDEZVOUS_REQUEST'

export type ConnectivityResourceErrorCode =
  | 'CONNECTIVITY_RESOURCE_LIMIT'
  | 'CONNECT_OPERATION_IN_PROGRESS'
  | 'CONNECTIVITY_RESOURCE_INVALID'

export class ConnectivityResourceError extends Error {
  constructor(readonly code: ConnectivityResourceErrorCode) {
    super(code)
    this.name = 'ConnectivityResourceError'
  }
}

const RESOURCE_TOKEN = Symbol('ConnectivityResourceReservation')
const reservations = new WeakSet<object>()

export class ConnectivityResourceReservation {
  private released = false

  constructor(token: symbol, private readonly releaseOnce: () => void) {
    if (token !== RESOURCE_TOKEN) throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_INVALID')
    reservations.add(this)
  }

  release(): void {
    if (this.released) return
    this.released = true
    this.releaseOnce()
  }

  isReleased(): boolean { return this.released }
}

export function isConnectivityResourceReservation(value: unknown): value is ConnectivityResourceReservation {
  return typeof value === 'object' && value !== null && reservations.has(value)
}

export interface ConnectivityResourceSnapshot {
  readonly counts: Readonly<Record<ConnectivityResourceCategory, number>>
  readonly activeTargets: number
}

const LIMITS: Readonly<Record<ConnectivityResourceCategory, number>> = Object.freeze({
  CONNECT_OPERATION: MAX_CONCURRENT_CONNECT_OPERATIONS,
  SECURE_CONNECTION_ATTEMPT: MAX_PENDING_SECURE_CONNECTION_ATTEMPTS,
  UDP_OPERATION: MAX_PENDING_UDP_OPERATIONS,
  RELAY_CIRCUIT: MAX_GOVERNED_RELAY_CIRCUITS,
  RELAY_QUEUED_BYTES: MAX_GOVERNED_RELAY_QUEUED_BYTES,
  RENDEZVOUS_REQUEST: MAX_PENDING_RENDEZVOUS_REQUESTS
})

/** Process-level accounting only. It never creates or owns network resources. */
export class ConnectivityResourceGovernor {
  private readonly counts: Record<ConnectivityResourceCategory, number> = {
    CONNECT_OPERATION: 0,
    SECURE_CONNECTION_ATTEMPT: 0,
    UDP_OPERATION: 0,
    RELAY_CIRCUIT: 0,
    RELAY_QUEUED_BYTES: 0,
    RENDEZVOUS_REQUEST: 0
  }
  private readonly activeTargets = new Set<string>()

  reserve(category: Exclude<ConnectivityResourceCategory, 'CONNECT_OPERATION'>, amount = 1): ConnectivityResourceReservation {
    if (!Number.isInteger(amount) || amount < 1) throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_INVALID')
    const next = this.counts[category] + amount
    if (next > LIMITS[category]) throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_LIMIT')
    this.counts[category] = next
    return new ConnectivityResourceReservation(RESOURCE_TOKEN, () => {
      const current = this.counts[category]
      if (current < amount) throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_INVALID')
      this.counts[category] = current - amount
    })
  }

  reserveConnectOperation(targetServerId: string): ConnectivityResourceReservation {
    if (!/^sha256:[0-9a-f]{64}$/.test(targetServerId)) throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_INVALID')
    if (this.activeTargets.has(targetServerId)) throw new ConnectivityResourceError('CONNECT_OPERATION_IN_PROGRESS')
    if (this.counts.CONNECT_OPERATION >= MAX_CONCURRENT_CONNECT_OPERATIONS) {
      throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_LIMIT')
    }
    this.activeTargets.add(targetServerId)
    this.counts.CONNECT_OPERATION += 1
    return new ConnectivityResourceReservation(RESOURCE_TOKEN, () => {
      if (!this.activeTargets.delete(targetServerId) || this.counts.CONNECT_OPERATION < 1) {
        throw new ConnectivityResourceError('CONNECTIVITY_RESOURCE_INVALID')
      }
      this.counts.CONNECT_OPERATION -= 1
    })
  }

  snapshot(): ConnectivityResourceSnapshot {
    return Object.freeze({ counts: Object.freeze({ ...this.counts }), activeTargets: this.activeTargets.size })
  }
}

export const defaultConnectivityResourceGovernor = new ConnectivityResourceGovernor()
