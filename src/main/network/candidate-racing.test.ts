import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  aggregateServerCandidates,
  dialEndpointKey,
  EphemeralCandidateSuccessCache,
  type ServerDialPlan
} from './candidate-aggregation'
import {
  CANDIDATE_ATTEMPT_DELAY_MS,
  CandidateRaceError,
  connectToServerUsingCandidates,
  MAX_CONCURRENT_CANDIDATE_ATTEMPTS,
  MIN_CANDIDATE_ATTEMPT_GAP_MS,
  raceSecureServerConnections,
  type SecureConnectionAttempt
} from './candidate-racing'
import {
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  type ConnectivityCandidate
} from './connectivity-descriptor'
import {
  tcpTransportTestOnly,
  type ClientSecurePreAuthorizationConnection
} from './tcp-transport'

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

const server = identity()
const devicePair = generateKeyPairSync('ed25519')
const devicePublicKey = Buffer.from(devicePair.publicKey.export({ format: 'der', type: 'spki' }))
const device = {
  fingerprint: `sha256:${createHash('sha256').update(devicePublicKey).digest('hex')}`,
  publicKey: devicePublicKey,
  privateKey: devicePair.privateKey
}

function mapped(address: string, port: number): ConnectivityCandidate {
  return { candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP, family: 4, address, port }
}

function makePlan(
  candidates: readonly ConnectivityCandidate[] = [mapped('8.8.8.8', 45000)],
  issuedAt = NOW
): ServerDialPlan {
  const encoded = createSignedConnectivityDescriptor({
    serverId: server.serverId,
    serverPublicKey: server.publicKey,
    serverPrivateKey: server.privateKey,
    candidates,
    customIssuedAt: issuedAt,
    lifetimeSeconds: 300,
    allowRawCandidatesForTesting: true
  })
  const verified = verifySignedConnectivityDescriptor({
    encodedDescriptor: encoded,
    expectedServerId: server.serverId,
    nowSeconds: issuedAt
  })
  return aggregateServerCandidates({
    expectedServerId: server.serverId,
    expectedServerPublicKey: server.publicKey,
    descriptors: [verified],
    nowSeconds: NOW
  })
}

function secure(
  expectedServerId = server.serverId,
  options: Parameters<typeof tcpTransportTestOnly.createSecurePreAuthorizationConnection>[0] = { expectedServerId }
): ClientSecurePreAuthorizationConnection {
  return tcpTransportTestOnly.createSecurePreAuthorizationConnection({ ...options, expectedServerId })
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

describe('bounded cryptographic candidate racing', () => {
  afterEach(() => vi.useRealTimers())

  it('does not launch I/O when the deadline expires in the queued attempt microtask', async () => {
    vi.useFakeTimers()
    let now = 0
    const establish = vi.fn()
    const race = raceSecureServerConnections({
      plan: makePlan(), device, overallTimeoutMs: 100,
      monotonicNowMs: () => now, establishConnection: establish
    })
    now = 100
    await expect(race).rejects.toMatchObject({ code: 'CANDIDATE_RACE_TIMEOUT' })
    expect(establish).not.toHaveBeenCalled()
  })

  it('destroys an expired secure winner before the timeout timer runs and records no success', async () => {
    vi.useFakeTimers()
    let now = 0
    const connection = secure()
    const successCache = new EphemeralCandidateSuccessCache()
    const record = vi.spyOn(successCache, 'recordCryptographicSuccess')
    const establish = vi.fn(async () => { now = 100; return connection })
    await expect(raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      overallTimeoutMs: 100, monotonicNowMs: () => now, successCache,
      establishConnection: establish
    })).rejects.toMatchObject({ code: 'CANDIDATE_RACE_TIMEOUT' })
    expect(connection.isDestroyed()).toBe(true)
    expect(record).not.toHaveBeenCalled()
    expect(establish).toHaveBeenCalledTimes(1)
  })

  it('does not start a staggered candidate after the monotonic deadline', async () => {
    vi.useFakeTimers()
    let now = 0
    const pending = deferred<ClientSecurePreAuthorizationConnection>()
    const establish = vi.fn(() => pending.promise)
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      overallTimeoutMs: 1000, monotonicNowMs: () => now, establishConnection: establish
    })
    const expectation = expect(race).rejects.toMatchObject({ code: 'CANDIDATE_RACE_TIMEOUT' })
    await vi.advanceTimersByTimeAsync(0)
    now = 1000
    await vi.advanceTimersByTimeAsync(CANDIDATE_ATTEMPT_DELAY_MS)
    await expectation
    expect(establish).toHaveBeenCalledTimes(1)
    const connection = secure()
    pending.resolve(connection)
    await vi.advanceTimersByTimeAsync(0)
    expect(connection.isDestroyed()).toBe(true)
  })

  it('starts the first attempt immediately and staggers the second by 250 ms', async () => {
    vi.useFakeTimers()
    const starts: number[] = []
    const pending = [deferred<ClientSecurePreAuthorizationConnection>(), deferred<ClientSecurePreAuthorizationConnection>()]
    const attempt: SecureConnectionAttempt = () => {
      starts.push(Date.now())
      return pending[starts.length - 1]!.promise
    }
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('8.8.8.8', 1), mapped('1.1.1.1', 2)]), device,
      establishConnection: attempt
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(starts).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(CANDIDATE_ATTEMPT_DELAY_MS - 1)
    expect(starts).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(starts).toHaveLength(2)
    pending[1]!.resolve(secure())
    await expect(race).resolves.toBeDefined()
  })

  it('never exceeds two concurrent attempts', async () => {
    vi.useFakeTimers()
    let active = 0
    let maximum = 0
    const pending = Array.from({ length: 4 }, () => deferred<ClientSecurePreAuthorizationConnection>())
    let calls = 0
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2), mapped('9.9.9.9', 3), mapped('11.0.0.1', 4)]),
      device,
      establishConnection: () => {
        const current = calls++
        active += 1
        maximum = Math.max(maximum, active)
        return pending[current]!.promise.finally(() => { active -= 1 })
      }
    })
    await vi.advanceTimersByTimeAsync(2000)
    expect(calls).toBe(MAX_CONCURRENT_CANDIDATE_ATTEMPTS)
    pending[0]!.reject(new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED'))
    await vi.advanceTimersByTimeAsync(MIN_CANDIDATE_ATTEMPT_GAP_MS)
    expect(calls).toBe(3)
    pending[2]!.resolve(secure())
    await expect(race).resolves.toBeDefined()
    expect(maximum).toBe(2)
  })

  it('accelerates clear failure but preserves the 100 ms minimum gap', async () => {
    vi.useFakeTimers()
    const starts: number[] = []
    const attempt: SecureConnectionAttempt = () => {
      starts.push(Date.now())
      return starts.length === 1
        ? Promise.reject(new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED'))
        : Promise.resolve(secure())
    }
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      establishConnection: attempt
    })
    await vi.advanceTimersByTimeAsync(MIN_CANDIDATE_ATTEMPT_GAP_MS - 1)
    expect(starts).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    await expect(race).resolves.toBeDefined()
    expect(starts[1]! - starts[0]!).toBe(MIN_CANDIDATE_ATTEMPT_GAP_MS)
  })

  it('rejects forged plans and caller-controlled connection storms', async () => {
    await expect(raceSecureServerConnections({ plan: {} as ServerDialPlan, device })).rejects.toMatchObject({
      code: 'CANDIDATE_PLAN_INVALID'
    })
    await expect(raceSecureServerConnections({
      plan: makePlan(), device, attemptDelayMs: 0
    })).rejects.toMatchObject({ code: 'CANDIDATE_PLAN_INVALID' })
  })

  it('does not accept a wrong Server Identity and continues to the correct server', async () => {
    vi.useFakeTimers()
    const wrong = identity()
    let wrongDestroyed = 0
    let calls = 0
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      establishConnection: async () => ++calls === 1
        ? secure(wrong.serverId, { expectedServerId: wrong.serverId, onDestroy: () => { wrongDestroyed += 1 } })
        : secure()
    })
    await vi.advanceTimersByTimeAsync(MIN_CANDIDATE_ATTEMPT_GAP_MS)
    await expect(race).resolves.toMatchObject({ connection: { expectedServerId: server.serverId } })
    expect(wrongDestroyed).toBe(1)
  })

  it('selects one winner, cancels losers, and destroys a late success', async () => {
    vi.useFakeTimers()
    const first = deferred<ClientSecurePreAuthorizationConnection>()
    const second = deferred<ClientSecurePreAuthorizationConnection>()
    let firstDestroyed = 0
    let calls = 0
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      establishConnection: () => calls++ === 0 ? first.promise : second.promise
    })
    await vi.advanceTimersByTimeAsync(250)
    second.resolve(secure())
    await expect(race).resolves.toBeDefined()
    first.resolve(secure(server.serverId, { expectedServerId: server.serverId, onDestroy: () => { firstDestroyed += 1 } }))
    await vi.advanceTimersByTimeAsync(0)
    expect(firstDestroyed).toBe(1)
  })

  it('performs exactly one admission and exposes the invite only to the winner', async () => {
    const seen: Array<{ mode: string; invite?: string }> = []
    let attempts = 0
    const connection = await connectToServerUsingCandidates({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      authorization: { mode: 'admission', invite: 'MQR1-secret' },
      establishConnection: async () => {
        attempts += 1
        return secure(server.serverId, {
          expectedServerId: server.serverId,
          onAuthorize: async (mode, invite) => {
            seen.push({ mode, ...(invite === undefined ? {} : { invite }) })
            return { status: 'admitted' }
          }
        })
      }
    })
    expect(connection).toBeDefined()
    expect(attempts).toBe(1)
    expect(seen).toEqual([{ mode: 'admission', invite: 'MQR1-secret' }])
  })

  it('sends reconnect only on the secure winner', async () => {
    const modes: string[] = []
    await connectToServerUsingCandidates({
      plan: makePlan(), device, authorization: { mode: 'reconnect' },
      establishConnection: async () => secure(server.serverId, {
        expectedServerId: server.serverId,
        onAuthorize: async (mode) => {
          modes.push(mode)
          return { status: 'authorized' }
        }
      })
    })
    expect(modes).toEqual(['reconnect'])
  })

  it('does not restart racing after authorization rejection', async () => {
    let attempts = 0
    let authorizations = 0
    await expect(connectToServerUsingCandidates({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      authorization: { mode: 'admission', invite: 'bad' },
      establishConnection: async () => {
        attempts += 1
        return secure(server.serverId, {
          expectedServerId: server.serverId,
          onAuthorize: async () => {
            authorizations += 1
            throw new Error('REJECTED')
          }
        })
      }
    })).rejects.toThrow('REJECTED')
    expect(attempts).toBe(1)
    expect(authorizations).toBe(1)
  })

  it('times out hanging attempts and aborts every resource', async () => {
    vi.useFakeTimers()
    let aborted = 0
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      overallTimeoutMs: 500,
      establishConnection: (_target, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => { aborted += 1; reject(new Error('aborted')) }, { once: true })
      })
    })
    const expectation = expect(race).rejects.toMatchObject({ code: 'CANDIDATE_RACE_TIMEOUT' })
    await vi.advanceTimersByTimeAsync(500)
    await expectation
    expect(aborted).toBe(2)
  })

  it('honors caller abort with no late authorization', async () => {
    const controller = new AbortController()
    let aborted = 0
    const race = raceSecureServerConnections({
      plan: makePlan(), device, signal: controller.signal,
      establishConnection: (_target, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => { aborted += 1; reject(new Error('abort')) }, { once: true })
      })
    })
    const expectation = expect(race).rejects.toMatchObject({ code: 'CANDIDATE_RACE_ABORTED' })
    controller.abort()
    await expectation
    expect(aborted).toBe(0)
  })

  it('destroys a secure winner when abort happens during authorization', async () => {
    const controller = new AbortController()
    const authorization = deferred<{ status: 'authorized' }>()
    let destroyed = 0
    let authorizationCalls = 0
    const operation = connectToServerUsingCandidates({
      plan: makePlan(), device, signal: controller.signal,
      authorization: { mode: 'reconnect' },
      establishConnection: async () => secure(server.serverId, {
        expectedServerId: server.serverId,
        onDestroy: () => { destroyed += 1 },
        onAuthorize: async () => {
          authorizationCalls += 1
          return authorization.promise
        }
      })
    })
    await new Promise<void>((resolve) => setImmediate(resolve))
    expect(authorizationCalls).toBe(1)
    controller.abort()
    authorization.reject(new Error('authorization aborted'))
    await expect(operation).rejects.toThrow('authorization aborted')
    expect(destroyed).toBeGreaterThanOrEqual(1)
  })

  it('skips a descriptor that expires before start but allows one started while fresh to win later', async () => {
    vi.useFakeTimers()
    let now = NOW
    const first = deferred<ClientSecurePreAuthorizationConnection>()
    let calls = 0
    const expiringPlan = makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)], NOW - 299)
    const race = raceSecureServerConnections({
      plan: expiringPlan, device, nowSeconds: () => now,
      establishConnection: () => { calls += 1; return first.promise }
    })
    await vi.advanceTimersByTimeAsync(0)
    now = NOW + 2
    first.resolve(secure())
    await expect(race).resolves.toBeDefined()
    expect(calls).toBe(1)
  })

  it('does not start the next candidate after its descriptor expires', async () => {
    vi.useFakeTimers()
    let now = NOW
    const first = deferred<ClientSecurePreAuthorizationConnection>()
    let calls = 0
    const race = raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)], NOW - 299),
      device,
      nowSeconds: () => now,
      establishConnection: () => { calls += 1; return first.promise }
    })
    const expectation = expect(race).rejects.toMatchObject({ code: 'NO_REACHABLE_SERVER_CANDIDATE' })
    await vi.advanceTimersByTimeAsync(0)
    now = NOW + 2
    first.reject(new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED'))
    await vi.advanceTimersByTimeAsync(MIN_CANDIDATE_ATTEMPT_GAP_MS)
    await expectation
    expect(calls).toBe(1)
  })

  it('returns one bounded semantic error after all candidates fail and retries on a future race', async () => {
    const plan = makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)])
    let calls = 0
    const fail: SecureConnectionAttempt = async () => { calls += 1; throw new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED') }
    await expect(raceSecureServerConnections({
      plan, device, establishConnection: fail, attemptDelayMs: 100
    })).rejects.toEqual(new CandidateRaceError('NO_REACHABLE_SERVER_CANDIDATE'))
    await expect(raceSecureServerConnections({
      plan, device, establishConnection: fail, attemptDelayMs: 100
    })).rejects.toMatchObject({ code: 'NO_REACHABLE_SERVER_CANDIDATE' })
    expect(calls).toBe(4)
  })

  it('keeps the public error bounded across sixteen failures', async () => {
    vi.useFakeTimers()
    const candidates = Array.from({ length: 16 }, (_, index) => mapped(`11.0.0.${index + 1}`, 1000 + index))
    const race = raceSecureServerConnections({
      plan: makePlan(candidates), device, attemptDelayMs: 100,
      establishConnection: async () => { throw new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED') }
    })
    const expectation = expect(race).rejects.toMatchObject({ code: 'NO_REACHABLE_SERVER_CANDIDATE' })
    await vi.runAllTimersAsync()
    await expectation
    try {
      await race
    } catch (error) {
      expect(Object.keys(error as object).sort()).toEqual(['code', 'name'])
      expect(String(error)).not.toContain('11.0.0.')
      expect(String(error)).not.toContain('private topology')
    }
  })

  it('fails closed on an unknown attempt error instead of treating it as reachable-path fallback', async () => {
    let calls = 0
    await expect(raceSecureServerConnections({
      plan: makePlan([mapped('1.1.1.1', 1), mapped('8.8.8.8', 2)]), device,
      establishConnection: async () => { calls += 1; throw new Error('foreign detail') }
    })).rejects.toMatchObject({ code: 'CANDIDATE_PLAN_INVALID' })
    expect(calls).toBe(1)
  })

  it('fails closed when a supplied monotonic clock regresses', async () => {
    const readings = [100, 99]
    await expect(raceSecureServerConnections({
      plan: makePlan(), device,
      monotonicNowMs: () => readings.shift() ?? 99,
      establishConnection: async () => secure()
    })).rejects.toMatchObject({ code: 'CANDIDATE_PLAN_INVALID' })
  })

  it('records success only after secure completion and only for the current server endpoint', async () => {
    const cache = new EphemeralCandidateSuccessCache()
    const plan = makePlan()
    await raceSecureServerConnections({ plan, device, successCache: cache, establishConnection: async () => secure() })
    expect(cache.hasFresh(server.serverId, plan.orderedDialTargets[0]!.endpointKey)).toBe(true)
    expect(cache.hasFresh(identity().serverId, plan.orderedDialTargets[0]!.endpointKey)).toBe(false)
    expect(cache.hasFresh(server.serverId, dialEndpointKey({ family: 4, address: '1.1.1.1', port: 1 }))).toBe(false)
  })
})
