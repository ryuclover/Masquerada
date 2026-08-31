import { describe, expect, it, vi } from 'vitest'

import { ConnectivityResourceGovernor } from './connectivity-resource-governor'
import { ConnectivitySubsystem } from './connectivity-subsystem'

const target = `sha256:${'a'.repeat(64)}`

describe('connectivity subsystem lifecycle coordinator', () => {
  it('blocks duplicate target operations while allowing another target', () => {
    const subsystem = new ConnectivitySubsystem()
    const first = subsystem.beginConnect(target)
    expect(() => subsystem.beginConnect(target)).toThrowError(expect.objectContaining({ code: 'CONNECT_OPERATION_IN_PROGRESS' }))
    const other = subsystem.beginConnect(`sha256:${'b'.repeat(64)}`)
    first.finish(); other.finish()
  })

  it('shutdown aborts in-flight work, closes resources, blocks new work and is idempotent', async () => {
    const subsystem = new ConnectivitySubsystem()
    const operation = subsystem.beginConnect(target)
    let closes = 0
    subsystem.registerResource({ close: () => { closes += 1 } })
    const first = subsystem.shutdown()
    const second = subsystem.shutdown()
    expect(first).toBe(second)
    await first
    expect(operation.signal.aborted).toBe(true)
    expect(closes).toBe(1)
    expect(subsystem.getState()).toBe('SHUT_DOWN')
    expect(() => subsystem.beginConnect(`sha256:${'c'.repeat(64)}`)).toThrowError(
      expect.objectContaining({ code: 'CONNECTIVITY_SHUT_DOWN' })
    )
  })

  it('forces unresponsive resources at the bounded deadline without leaking reservations', async () => {
    vi.useFakeTimers()
    const governor = new ConnectivityResourceGovernor()
    const subsystem = new ConnectivitySubsystem(governor, 10)
    subsystem.beginConnect(target)
    let forced = 0
    subsystem.registerResource({ close: () => new Promise<void>(() => {}), forceClose: () => { forced += 1 } })
    const shutdown = subsystem.shutdown()
    await vi.advanceTimersByTimeAsync(10)
    await shutdown
    expect(forced).toBe(1)
    expect(governor.snapshot().counts.CONNECT_OPERATION).toBe(0)
    vi.useRealTimers()
  })
})
