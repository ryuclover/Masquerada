import { type NetworkInterfaceInfo } from 'node:os'
import { describe, expect, it } from 'vitest'

import {
  classifyNetworkAddress,
  enumerateNetworkAddresses
} from './network-interfaces'

describe('network-interfaces: classificação de endereços e enumeração segura', () => {
  describe('classifyNetworkAddress: IPv4', () => {
    it('classifica corretamente endereços Loopback (127.0.0.0/8)', () => {
      expect(classifyNetworkAddress('127.0.0.1').scope).toBe('LOOPBACK')
      expect(classifyNetworkAddress('127.0.0.1').isSelectableForLan).toBe(false)
      expect(classifyNetworkAddress('127.0.0.1').isGloballyRoutableWan).toBe(false)
      expect(classifyNetworkAddress('127.255.255.254').scope).toBe('LOOPBACK')
    })

    it('classifica corretamente 10.0.0.0/8 como LAN_PRIVATE', () => {
      const c1 = classifyNetworkAddress('10.0.0.1')
      expect(c1.scope).toBe('LAN_PRIVATE')
      expect(c1.isSelectableForLan).toBe(true)
      expect(c1.isGloballyRoutableWan).toBe(false)

      const c2 = classifyNetworkAddress('10.255.255.254')
      expect(c2.scope).toBe('LAN_PRIVATE')
      expect(c2.isSelectableForLan).toBe(true)
      expect(c2.isGloballyRoutableWan).toBe(false)
    })

    it('(52) classifica estritamente CGNAT 100.64.0.0/10 e valida limites', () => {
      // Abaixo do range (100.63.255.255 -> GLOBAL)
      const outBelow = classifyNetworkAddress('100.63.255.255')
      expect(outBelow.scope).toBe('GLOBAL')
      expect(outBelow.isGloballyRoutableWan).toBe(true)

      // Limite inferior exato (100.64.0.0 -> CGNAT)
      const inLow = classifyNetworkAddress('100.64.0.0')
      expect(inLow.scope).toBe('CGNAT')
      expect(inLow.isSelectableForLan).toBe(false)
      expect(inLow.isGloballyRoutableWan).toBe(false)

      // Intermediário (100.64.0.1 e 100.100.50.25 -> CGNAT)
      expect(classifyNetworkAddress('100.64.0.1').scope).toBe('CGNAT')
      expect(classifyNetworkAddress('100.100.50.25').scope).toBe('CGNAT')

      // Limite superior exato (100.127.255.255 -> CGNAT)
      const inHigh = classifyNetworkAddress('100.127.255.255')
      expect(inHigh.scope).toBe('CGNAT')
      expect(inHigh.isSelectableForLan).toBe(false)
      expect(inHigh.isGloballyRoutableWan).toBe(false)

      // Acima do range (100.128.0.0 -> GLOBAL)
      const outAbove = classifyNetworkAddress('100.128.0.0')
      expect(outAbove.scope).toBe('GLOBAL')
      expect(outAbove.isGloballyRoutableWan).toBe(true)
    })

    it('(54) classifica estritamente o range 172.16.0.0/12 (RFC 1918)', () => {
      // Fora do range (172.15.x.x -> GLOBAL)
      const outBelow = classifyNetworkAddress('172.15.255.255')
      expect(outBelow.scope).toBe('GLOBAL')
      expect(outBelow.isSelectableForLan).toBe(false)
      expect(outBelow.isGloballyRoutableWan).toBe(true)

      // Limite inferior exato (172.16.0.0 -> LAN_PRIVATE)
      const inLow = classifyNetworkAddress('172.16.0.0')
      expect(inLow.scope).toBe('LAN_PRIVATE')
      expect(inLow.isSelectableForLan).toBe(true)
      expect(inLow.isGloballyRoutableWan).toBe(false)

      // Intermediário (172.24.10.5 -> LAN_PRIVATE)
      const inMid = classifyNetworkAddress('172.24.10.5')
      expect(inMid.scope).toBe('LAN_PRIVATE')
      expect(inMid.isSelectableForLan).toBe(true)
      expect(inMid.isGloballyRoutableWan).toBe(false)

      // Limite superior exato (172.31.255.255 -> LAN_PRIVATE)
      const inHigh = classifyNetworkAddress('172.31.255.255')
      expect(inHigh.scope).toBe('LAN_PRIVATE')
      expect(inHigh.isSelectableForLan).toBe(true)
      expect(inHigh.isGloballyRoutableWan).toBe(false)

      // Fora do range (172.32.0.0 -> GLOBAL)
      const outAbove = classifyNetworkAddress('172.32.0.0')
      expect(outAbove.scope).toBe('GLOBAL')
      expect(outAbove.isSelectableForLan).toBe(false)
      expect(outAbove.isGloballyRoutableWan).toBe(true)
    })

    it('classifica corretamente 192.168.0.0/16 como LAN_PRIVATE', () => {
      const c1 = classifyNetworkAddress('192.168.1.1')
      expect(c1.scope).toBe('LAN_PRIVATE')
      expect(c1.isSelectableForLan).toBe(true)
      expect(c1.isGloballyRoutableWan).toBe(false)

      const c2 = classifyNetworkAddress('192.168.255.254')
      expect(c2.scope).toBe('LAN_PRIVATE')
      expect(c2.isSelectableForLan).toBe(true)

      // Fora de 192.168
      const c3 = classifyNetworkAddress('192.169.1.1')
      expect(c3.scope).toBe('GLOBAL')
      expect(c3.isSelectableForLan).toBe(false)
      expect(c3.isGloballyRoutableWan).toBe(true)
    })

    it('classifica 169.254.0.0/16 como LINK_LOCAL', () => {
      const c = classifyNetworkAddress('169.254.10.20')
      expect(c.scope).toBe('LINK_LOCAL')
      expect(c.isSelectableForLan).toBe(true)
      expect(c.isGloballyRoutableWan).toBe(false)
    })

    it('(55) classifica ranges de documentação TEST-NET-1/2/3 como DOCUMENTATION', () => {
      expect(classifyNetworkAddress('192.0.2.1').scope).toBe('DOCUMENTATION')
      expect(classifyNetworkAddress('192.0.2.1').isGloballyRoutableWan).toBe(false)

      expect(classifyNetworkAddress('198.51.100.1').scope).toBe('DOCUMENTATION')
      expect(classifyNetworkAddress('198.51.100.1').isGloballyRoutableWan).toBe(false)

      expect(classifyNetworkAddress('203.0.113.1').scope).toBe('DOCUMENTATION')
      expect(classifyNetworkAddress('203.0.113.1').isGloballyRoutableWan).toBe(false)
    })

    it('(56) classifica 198.18.0.0/15 como BENCHMARK', () => {
      const c1 = classifyNetworkAddress('198.18.0.1')
      expect(c1.scope).toBe('BENCHMARK')
      expect(c1.isGloballyRoutableWan).toBe(false)

      const c2 = classifyNetworkAddress('198.19.255.254')
      expect(c2.scope).toBe('BENCHMARK')
      expect(c2.isGloballyRoutableWan).toBe(false)
    })

    it('(57) classifica 0.0.0.0, 224/4, 240/4, 255.255.255.255 como não-globais', () => {
      expect(classifyNetworkAddress('0.0.0.0').scope).toBe('UNSPECIFIED')
      expect(classifyNetworkAddress('0.0.0.0').isGloballyRoutableWan).toBe(false)

      expect(classifyNetworkAddress('224.0.0.1').scope).toBe('MULTICAST')
      expect(classifyNetworkAddress('224.0.0.1').isGloballyRoutableWan).toBe(false)

      expect(classifyNetworkAddress('240.0.0.1').scope).toBe('RESERVED')
      expect(classifyNetworkAddress('240.0.0.1').isGloballyRoutableWan).toBe(false)

      expect(classifyNetworkAddress('255.255.255.255').scope).toBe('RESERVED')
      expect(classifyNetworkAddress('255.255.255.255').isGloballyRoutableWan).toBe(false)
    })

    it('(62) classifica IPs públicos reais como GLOBAL e isGloballyRoutableWan true', () => {
      const c1 = classifyNetworkAddress('8.8.8.8')
      expect(c1.scope).toBe('GLOBAL')
      expect(c1.isGloballyRoutableWan).toBe(true)

      const c2 = classifyNetworkAddress('1.1.1.1')
      expect(c2.scope).toBe('GLOBAL')
      expect(c2.isGloballyRoutableWan).toBe(true)

      const c3 = classifyNetworkAddress('203.0.114.1')
      expect(c3.scope).toBe('GLOBAL')
      expect(c3.isGloballyRoutableWan).toBe(true)
    })
  })

  describe('classifyNetworkAddress: IPv6', () => {
    it('(61) classifica ::1 como LOOPBACK e :: como UNSPECIFIED', () => {
      const cLoop = classifyNetworkAddress('::1')
      expect(cLoop.scope).toBe('LOOPBACK')
      expect(cLoop.isGloballyRoutableWan).toBe(false)

      const cUnspec = classifyNetworkAddress('::')
      expect(cUnspec.scope).toBe('UNSPECIFIED')
      expect(cUnspec.isGloballyRoutableWan).toBe(false)
    })

    it('(58) classifica ULA fc00::/7 como LAN_PRIVATE e não WAN', () => {
      const c1 = classifyNetworkAddress('fd12:3456:789a:1::1')
      expect(c1.scope).toBe('LAN_PRIVATE')
      expect(c1.isSelectableForLan).toBe(true)
      expect(c1.isGloballyRoutableWan).toBe(false)

      const c2 = classifyNetworkAddress('fc00::1')
      expect(c2.scope).toBe('LAN_PRIVATE')
      expect(c2.isSelectableForLan).toBe(true)
      expect(c2.isGloballyRoutableWan).toBe(false)
    })

    it('(59) classifica IPv6 link-local fe80::/10', () => {
      const cWithoutScope = classifyNetworkAddress('fe80::1ff:fe00:3a60')
      expect(cWithoutScope.scope).toBe('LINK_LOCAL')
      expect(cWithoutScope.isSelectableForLan).toBe(false)
      expect(cWithoutScope.isGloballyRoutableWan).toBe(false)

      const cWithScope = classifyNetworkAddress('fe80::1ff:fe00:3a60', 12)
      expect(cWithScope.scope).toBe('LINK_LOCAL')
      expect(cWithScope.isSelectableForLan).toBe(true)
      expect(cWithScope.isGloballyRoutableWan).toBe(false)
    })

    it('(60) classifica 2001:db8::/32 como DOCUMENTATION e não WAN', () => {
      const c = classifyNetworkAddress('2001:db8::1')
      expect(c.scope).toBe('DOCUMENTATION')
      expect(c.isGloballyRoutableWan).toBe(false)
    })

    it('(61) classifica IPv6 multicast ff00::/8', () => {
      const c = classifyNetworkAddress('ff02::1')
      expect(c.scope).toBe('MULTICAST')
      expect(c.isGloballyRoutableWan).toBe(false)
    })

    it('(63) classifica IPv6 Global Unicast 2000::/3 legítimo como GLOBAL e isGloballyRoutableWan true', () => {
      const c1 = classifyNetworkAddress('2600::1')
      expect(c1.scope).toBe('GLOBAL')
      expect(c1.isGloballyRoutableWan).toBe(true)

      const c2 = classifyNetworkAddress('2001:4860:4860::8888')
      expect(c2.scope).toBe('GLOBAL')
      expect(c2.isGloballyRoutableWan).toBe(true)
    })

    it('classifica IPv4-mapped IPv6 coerentemente', () => {
      const cPrivate = classifyNetworkAddress('::ffff:192.168.1.50')
      expect(cPrivate.scope).toBe('LAN_PRIVATE')
      expect(cPrivate.isSelectableForLan).toBe(true)
      expect(cPrivate.isGloballyRoutableWan).toBe(false)

      const cGlobal = classifyNetworkAddress('::ffff:8.8.8.8')
      expect(cGlobal.scope).toBe('GLOBAL')
      expect(cGlobal.isSelectableForLan).toBe(false)
      expect(cGlobal.isGloballyRoutableWan).toBe(true)
    })
  })

  describe('enumerateNetworkAddresses', () => {
    it('enumera e classifica mock controlado de interfaces', () => {
      const mockProvider = () => ({
        eth0: [
          {
            address: '192.168.1.100',
            netmask: '255.255.255.0',
            family: 'IPv4',
            mac: '00:11:22:33:44:55',
            internal: false,
            cidr: '192.168.1.100/24'
          } as unknown as NetworkInterfaceInfo,
          {
            address: 'fe80::abcd',
            netmask: 'ffff:ffff:ffff:ffff::',
            family: 'IPv6',
            mac: '00:11:22:33:44:55',
            internal: false,
            cidr: 'fe80::abcd/64',
            scopeid: 2
          } as unknown as NetworkInterfaceInfo
        ],
        lo: [
          {
            address: '127.0.0.1',
            netmask: '255.0.0.0',
            family: 'IPv4',
            mac: '00:00:00:00:00:00',
            internal: true,
            cidr: '127.0.0.1/8'
          } as unknown as NetworkInterfaceInfo
        ]
      })

      const addrs = enumerateNetworkAddresses(mockProvider)
      expect(addrs).toHaveLength(3)

      const v4Private = addrs.find((a) => a.address === '192.168.1.100')
      expect(v4Private).toBeDefined()
      expect(v4Private?.scope).toBe('LAN_PRIVATE')
      expect(v4Private?.isSelectableForLan).toBe(true)

      const v6LinkLocal = addrs.find((a) => a.address === 'fe80::abcd')
      expect(v6LinkLocal).toBeDefined()
      expect(v6LinkLocal?.scope).toBe('LINK_LOCAL')
      expect(v6LinkLocal?.isSelectableForLan).toBe(true)
      expect(v6LinkLocal?.scopeId).toBe(2)

      const loopback = addrs.find((a) => a.address === '127.0.0.1')
      expect(loopback).toBeDefined()
      expect(loopback?.scope).toBe('LOOPBACK')
      expect(loopback?.isSelectableForLan).toBe(false)
    })
  })
})
