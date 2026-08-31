import type { KeyObject } from 'node:crypto'

import {
  EphemeralCandidateSuccessCache,
  isLegitimateServerDialPlan,
  type DialTarget,
  type ServerDialPlan
} from './candidate-aggregation'
import {
  establishSecureServerConnection,
  isClientSecurePreAuthorizationConnection,
  type ClientSecurePreAuthorizationConnection,
  type ClientTcpPeerConnection
} from './tcp-transport'
import {
  ConnectivityResourceError,
  defaultConnectivityResourceGovernor,
  type ConnectivityResourceGovernor
} from './connectivity-resource-governor'

export const CANDIDATE_ATTEMPT_DELAY_MS = 250
export const MIN_CANDIDATE_ATTEMPT_GAP_MS = 100
export const MAX_CANDIDATE_ATTEMPT_DELAY_MS = 2000
export const MAX_CONCURRENT_CANDIDATE_ATTEMPTS = 2
export const DEFAULT_CANDIDATE_RACE_TIMEOUT_MS = 12000
export const MAX_CANDIDATE_RACE_TIMEOUT_MS = 15000

export type CandidateRaceErrorCode =
  | 'CANDIDATE_PLAN_INVALID'
  | 'CANDIDATE_RACE_TIMEOUT'
  | 'CANDIDATE_RACE_ABORTED'
  | 'NO_REACHABLE_SERVER_CANDIDATE'
  | 'CANDIDATE_SECURE_HANDSHAKE_FAILED'

export class CandidateRaceError extends Error {
  constructor(readonly code: CandidateRaceErrorCode) {
    super(code)
    this.name = 'CandidateRaceError'
  }
}

export interface CandidateRaceDeviceIdentity {
  readonly fingerprint: string
  readonly publicKey: Buffer
  readonly privateKey: KeyObject
}

export interface SecureRaceWinner {
  readonly connection: ClientSecurePreAuthorizationConnection
  readonly target: DialTarget
}

export type SecureConnectionAttempt = (
  target: DialTarget,
  options: {
    readonly expectedServerId: string
    readonly expectedServerPublicKey: Buffer
    readonly device: CandidateRaceDeviceIdentity
    readonly signal: AbortSignal
  }
) => Promise<ClientSecurePreAuthorizationConnection>

export interface RaceSecureServerConnectionsOptions {
  readonly plan: ServerDialPlan
  readonly device: CandidateRaceDeviceIdentity
  readonly signal?: AbortSignal
  readonly successCache?: EphemeralCandidateSuccessCache
  readonly attemptDelayMs?: number
  readonly overallTimeoutMs?: number
  readonly nowSeconds?: () => number
  readonly monotonicNowMs?: () => number
  readonly establishConnection?: SecureConnectionAttempt
  readonly resourceGovernor?: ConnectivityResourceGovernor
}

function validateTiming(attemptDelayMs: number, overallTimeoutMs: number): void {
  if (
    !Number.isInteger(attemptDelayMs) ||
    attemptDelayMs < MIN_CANDIDATE_ATTEMPT_GAP_MS ||
    attemptDelayMs > MAX_CANDIDATE_ATTEMPT_DELAY_MS ||
    !Number.isInteger(overallTimeoutMs) ||
    overallTimeoutMs < 1 ||
    overallTimeoutMs > MAX_CANDIDATE_RACE_TIMEOUT_MS
  ) throw new CandidateRaceError('CANDIDATE_PLAN_INVALID')
}

const defaultEstablish: SecureConnectionAttempt = async (target, options) => {
  try {
    return await establishSecureServerConnection({
      endpoint: target,
      expectedServerId: options.expectedServerId,
      expectedServerPublicKey: options.expectedServerPublicKey,
      deviceFingerprint: options.device.fingerprint,
      devicePublicKey: options.device.publicKey,
      devicePrivateKey: options.device.privateKey,
      signal: options.signal
    })
  } catch {
    throw new CandidateRaceError(options.signal.aborted
      ? 'CANDIDATE_RACE_ABORTED'
      : 'CANDIDATE_SECURE_HANDSHAKE_FAILED')
  }
}

/** Races secure handshakes; a raw TCP connect can never resolve this API. */
export function raceSecureServerConnections(
  options: RaceSecureServerConnectionsOptions
): Promise<SecureRaceWinner> {
  if (!isLegitimateServerDialPlan(options.plan)) {
    return Promise.reject(new CandidateRaceError('CANDIDATE_PLAN_INVALID'))
  }
  const attemptDelayMs = options.attemptDelayMs ?? CANDIDATE_ATTEMPT_DELAY_MS
  const overallTimeoutMs = options.overallTimeoutMs ?? DEFAULT_CANDIDATE_RACE_TIMEOUT_MS
  try {
    validateTiming(attemptDelayMs, overallTimeoutMs)
  } catch (error) {
    return Promise.reject(error)
  }
  if (options.signal?.aborted) {
    return Promise.reject(new CandidateRaceError('CANDIDATE_RACE_ABORTED'))
  }

  const targets = options.plan.orderedDialTargets
  const expectedPublicKey = options.plan.getExpectedServerPublicKey()
  const nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1000))
  const monotonicNowMs = options.monotonicNowMs ?? (() => performance.now())
  let lastMonotonicMs = Number.NEGATIVE_INFINITY
  const readMonotonicMs = (): number => {
    const current = monotonicNowMs()
    if (!Number.isFinite(current) || current < lastMonotonicMs) {
      throw new CandidateRaceError('CANDIDATE_PLAN_INVALID')
    }
    lastMonotonicMs = current
    return current
  }
  const establish = options.establishConnection ?? defaultEstablish
  const resourceGovernor = options.resourceGovernor ?? defaultConnectivityResourceGovernor

  return new Promise<SecureRaceWinner>((resolve, reject) => {
    let settled = false
    let nextIndex = 0
    let active = 0
    let lastStartMs = Number.NEGATIVE_INFINITY
    let staggerTimer: ReturnType<typeof setTimeout> | undefined
    const controllers = new Map<number, AbortController>()
    const liveConnections = new Map<number, ClientSecurePreAuthorizationConnection>()

    const clearStagger = (): void => {
      if (staggerTimer !== undefined) clearTimeout(staggerTimer)
      staggerTimer = undefined
    }
    const abortLosers = (winnerIndex?: number): void => {
      for (const [index, controller] of controllers) {
        if (index !== winnerIndex) controller.abort()
      }
      for (const [index, connection] of liveConnections) {
        if (index !== winnerIndex) connection.destroy()
      }
    }
    const cleanup = (winnerIndex?: number): void => {
      clearStagger()
      clearTimeout(overallTimer)
      options.signal?.removeEventListener('abort', onAbort)
      abortLosers(winnerIndex)
    }
    const fail = (error: unknown): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(error)
    }
    const onAbort = (): void => fail(new CandidateRaceError('CANDIDATE_RACE_ABORTED'))
    const overallTimer = setTimeout(
      () => fail(new CandidateRaceError('CANDIDATE_RACE_TIMEOUT')),
      overallTimeoutMs
    )

    const scheduleNext = (fastFailure: boolean): void => {
      if (settled || nextIndex >= targets.length || active >= MAX_CONCURRENT_CANDIDATE_ATTEMPTS) return
      clearStagger()
      let current: number
      try { current = readMonotonicMs() } catch { fail(new CandidateRaceError('CANDIDATE_PLAN_INVALID')); return }
      const elapsed = current - lastStartMs
      const desiredGap = fastFailure ? MIN_CANDIDATE_ATTEMPT_GAP_MS : attemptDelayMs
      const delay = Math.max(0, desiredGap - Math.max(0, elapsed))
      staggerTimer = setTimeout(() => {
        staggerTimer = undefined
        launchNext()
      }, delay)
    }

    const attemptFinished = (): void => {
      active -= 1
      if (settled) return
      if (nextIndex >= targets.length && active === 0) {
        fail(new CandidateRaceError('NO_REACHABLE_SERVER_CANDIDATE'))
        return
      }
      scheduleNext(true)
    }

    const launchNext = (): void => {
      if (settled || active >= MAX_CONCURRENT_CANDIDATE_ATTEMPTS) return
      let target: DialTarget | undefined
      let attemptIndex = -1
      while (nextIndex < targets.length) {
        attemptIndex = nextIndex
        const candidate = targets[nextIndex++]
        if (candidate && nowSeconds() < candidate.descriptorExpiresAt) {
          target = candidate
          break
        }
      }
      if (!target) {
        if (active === 0) fail(new CandidateRaceError('NO_REACHABLE_SERVER_CANDIDATE'))
        return
      }

      let startedAt: number
      try { startedAt = readMonotonicMs() } catch { fail(new CandidateRaceError('CANDIDATE_PLAN_INVALID')); return }
      const controller = new AbortController()
      let attemptReservation
      try {
        attemptReservation = resourceGovernor.reserve('SECURE_CONNECTION_ATTEMPT')
      } catch (error) {
        fail(error)
        return
      }
      controllers.set(attemptIndex, controller)
      active += 1
      lastStartMs = startedAt
      scheduleNext(false)

      void Promise.resolve().then(async () => {
        if (controller.signal.aborted) throw new CandidateRaceError('CANDIDATE_RACE_ABORTED')
        return establish(target!, {
          expectedServerId: options.plan.expectedServerId,
          expectedServerPublicKey: expectedPublicKey,
          device: options.device,
          signal: controller.signal
        })
      }).then((connection) => {
        active -= 1
        if (
          !isClientSecurePreAuthorizationConnection(connection) ||
          connection.expectedServerId !== options.plan.expectedServerId
        ) {
          if (isClientSecurePreAuthorizationConnection(connection)) connection.destroy()
          if (!settled) scheduleNext(true)
          if (!settled && nextIndex >= targets.length && active === 0) {
            fail(new CandidateRaceError('NO_REACHABLE_SERVER_CANDIDATE'))
          }
          return
        }
        liveConnections.set(attemptIndex, connection)
        if (settled) {
          connection.destroy()
          return
        }
        let completedAt: number
        try { completedAt = readMonotonicMs() } catch {
          connection.destroy()
          fail(new CandidateRaceError('CANDIDATE_PLAN_INVALID'))
          return
        }
        options.successCache?.recordCryptographicSuccess(
          options.plan.expectedServerId,
          target!.endpointKey,
          connection,
          completedAt - startedAt
        )
        settled = true
        cleanup(attemptIndex)
        resolve(Object.freeze({ connection, target: target! }))
      }).catch((cause) => {
        controllers.get(attemptIndex)?.abort()
        if (
          cause instanceof CandidateRaceError &&
          (cause.code === 'CANDIDATE_SECURE_HANDSHAKE_FAILED' || cause.code === 'CANDIDATE_RACE_ABORTED')
        ) attemptFinished()
        else if (cause instanceof ConnectivityResourceError) fail(cause)
        else fail(new CandidateRaceError('CANDIDATE_PLAN_INVALID'))
      }).finally(() => attemptReservation.release())
    }

    options.signal?.addEventListener('abort', onAbort, { once: true })
    launchNext()
  })
}

export type CandidateAuthorization =
  | { readonly mode: 'admission'; readonly invite: string }
  | { readonly mode: 'reconnect' }

export interface ConnectToServerUsingCandidatesOptions extends RaceSecureServerConnectionsOptions {
  readonly authorization: CandidateAuthorization
}

/** Selects one cryptographic winner, then performs exactly one authorization. */
export async function connectToServerUsingCandidates(
  options: ConnectToServerUsingCandidatesOptions
): Promise<ClientTcpPeerConnection> {
  const winner = await raceSecureServerConnections(options)
  const onAbort = (): void => winner.connection.destroy()
  options.signal?.addEventListener('abort', onAbort, { once: true })
  try {
    if (options.signal?.aborted) throw new CandidateRaceError('CANDIDATE_RACE_ABORTED')
    const result = options.authorization.mode === 'admission'
      ? await winner.connection.authorizeWithInvite(options.authorization.invite)
      : await winner.connection.authorizeExistingMember()
    return result.connection
  } catch (error) {
    winner.connection.destroy()
    throw error
  } finally {
    options.signal?.removeEventListener('abort', onAbort)
  }
}
