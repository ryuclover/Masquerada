import { describe, expect, it } from 'vitest'

import {
  ConnectivityResourceGovernor,
  isConnectivityResourceReservation,
  MAX_CONCURRENT_CONNECT_OPERATIONS,
  MAX_PENDING_SECURE_CONNECTION_ATTEMPTS
} from './connectivity-resource-governor'

const serverId = (index: number): string => `sha256:${index.toString(16).padStart(64, '0')}`

describe('global connectivity resource governor', () => {
  it('enforces global and per-target connect-operation limits and restores capacity', () => {
    const governor = new ConnectivityResourceGovernor()
    const reservations = Array.from({ length: MAX_CONCURRENT_CONNECT_OPERATIONS }, (_, index) =>
      governor.reserveConnectOperation(serverId(index + 1)))
    expect(() => governor.reserveConnectOperation(serverId(99))).toThrowError(
      expect.objectContaining({ code: 'CONNECTIVITY_RESOURCE_LIMIT' })
    )
    reservations[0]!.release()
    expect(() => governor.reserveConnectOperation(serverId(2))).toThrowError(
      expect.objectContaining({ code: 'CONNECT_OPERATION_IN_PROGRESS' })
    )
    const replacement = governor.reserveConnectOperation(serverId(99))
    replacement.release()
    for (const reservation of reservations) reservation.release()
    expect(governor.snapshot().counts.CONNECT_OPERATION).toBe(0)
  })

  it('bounds secure attempts and release is runtime-branded/exactly-once', () => {
    const governor = new ConnectivityResourceGovernor()
    const reservations = Array.from({ length: MAX_PENDING_SECURE_CONNECTION_ATTEMPTS }, () =>
      governor.reserve('SECURE_CONNECTION_ATTEMPT'))
    expect(isConnectivityResourceReservation(reservations[0])).toBe(true)
    expect(isConnectivityResourceReservation({ release() {} })).toBe(false)
    expect(() => governor.reserve('SECURE_CONNECTION_ATTEMPT')).toThrowError(
      expect.objectContaining({ code: 'CONNECTIVITY_RESOURCE_LIMIT' })
    )
    reservations[0]!.release(); reservations[0]!.release()
    expect(governor.snapshot().counts.SECURE_CONNECTION_ATTEMPT).toBe(MAX_PENDING_SECURE_CONNECTION_ATTEMPTS - 1)
    governor.reserve('SECURE_CONNECTION_ATTEMPT').release()
    for (const reservation of reservations) reservation.release()
    expect(governor.snapshot().counts.SECURE_CONNECTION_ATTEMPT).toBe(0)
  })

  it('preserves non-negative bounded counts under seeded acquire/release permutations', () => {
    const governor = new ConnectivityResourceGovernor()
    const live: ReturnType<typeof governor.reserve>[] = []
    let seed = 0x12345678
    for (let index = 0; index < 2000; index++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0
      if ((seed & 1) === 0 && live.length > 0) live.splice(seed % live.length, 1)[0]!.release()
      else {
        try { live.push(governor.reserve('UDP_OPERATION')) } catch { /* expected at hard cap */ }
      }
      const count = governor.snapshot().counts.UDP_OPERATION
      expect(count).toBeGreaterThanOrEqual(0)
      expect(count).toBeLessThanOrEqual(8)
    }
    for (const reservation of live) reservation.release()
    expect(governor.snapshot().counts.UDP_OPERATION).toBe(0)
  })
})
