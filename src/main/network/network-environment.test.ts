import type { NetworkInterfaceInfo } from 'node:os'
import { describe, expect, it } from 'vitest'

import { NetworkEnvironmentTracker, sameNetworkGeneration } from './network-environment'

const info = (address: string, family: 'IPv4' | 'IPv6', internal = false): NetworkInterfaceInfo => family === 'IPv4'
  ? { address, family, internal, netmask: '255.255.255.0', cidr: `${address}/24`, mac: '00:11:22:33:44:55' }
  : { address, family, internal, netmask: 'ffff:ffff:ffff:ffff::', cidr: `${address}/64`, mac: '00:11:22:33:44:55', scopeid: 0 }

describe('canonical network environment generation', () => {
  it('ignores OS enumeration order and duplicates', () => {
    let reversed = false
    const provider = () => reversed
      ? { Ethernet: [info('192.168.1.2', 'IPv4'), info('192.168.1.2', 'IPv4')], WiFi: [info('2001:4860::1', 'IPv6')] }
      : { WiFi: [info('2001:4860::1', 'IPv6')], Ethernet: [info('192.168.1.2', 'IPv4')] }
    const tracker = new NetworkEnvironmentTracker(provider)
    const first = tracker.snapshot()
    reversed = true
    const second = tracker.refresh()
    expect(second).toBe(first)
    expect(second.addresses).toHaveLength(2)
  })

  it('increments generation for relevant address addition/removal and never revives old generation', () => {
    let addresses = [info('10.0.0.2', 'IPv4')]
    const tracker = new NetworkEnvironmentTracker(() => ({ Ethernet: addresses }))
    const first = tracker.snapshot()
    addresses = [...addresses, info('2001:4860::2', 'IPv6')]
    const second = tracker.refresh()
    expect(second.generation).toBe(first.generation + 1)
    expect(sameNetworkGeneration(first, second)).toBe(false)
    addresses = [info('10.0.0.2', 'IPv4')]
    const third = tracker.refresh()
    expect(third.generation).toBe(second.generation + 1)
    expect(sameNetworkGeneration(first, third)).toBe(false)
  })
})
