import { isIP } from 'node:net'
import { networkInterfaces, type NetworkInterfaceInfo } from 'node:os'

export type AddressScope =
  | 'LOOPBACK'
  | 'LAN_PRIVATE'
  | 'LINK_LOCAL'
  | 'GLOBAL'
  | 'CGNAT'
  | 'DOCUMENTATION'
  | 'BENCHMARK'
  | 'UNSPECIFIED'
  | 'MULTICAST'
  | 'RESERVED'
  | 'UNSUPPORTED'

export interface LocalNetworkAddress {
  readonly interfaceName: string
  readonly family: 'IPv4' | 'IPv6'
  readonly address: string
  readonly cidr: string | null
  readonly scope: AddressScope
  readonly internal: boolean
  readonly scopeId?: number
  readonly isSelectableForLan: boolean
}

export interface EligibleDirectGlobalIpv6Address {
  readonly address: string
  readonly interfaceName: string
}

export type NetworkInterfaceProvider = () => NodeJS.Dict<NetworkInterfaceInfo[]>

const MAX_INTERFACE_NAME_LENGTH = 128
const MAX_INTERFACES_COUNT = 64
const MAX_ADDRESSES_COUNT = 256

export interface AddressClassification {
  readonly scope: AddressScope
  readonly family: 'IPv4' | 'IPv6' | 'UNKNOWN'
  readonly isSelectableForLan: boolean
  readonly isGloballyRoutableWan: boolean
  readonly normalizedAddress: string
}

/**
 * Converte e valida IPv4 em inteiro de 32 bits sem sinal.
 * Retorna null se não for IPv4 válido ou tiver formato inesperado.
 */
function parseIpv4ToUint32(address: string): number | null {
  const parts = address.split('.')
  if (parts.length !== 4) return null

  let uint32 = 0
  for (let i = 0; i < 4; i++) {
    const part = parts[i]
    if (!part || !/^\d+$/.test(part)) return null
    if (part.length > 1 && part.startsWith('0')) return null // Rejeita leading zeros
    const num = Number(part)
    if (num < 0 || num > 255) return null
    uint32 = (uint32 << 8) | num
  }
  return uint32 >>> 0
}

/**
 * Classifica um endereço IPv4 com base em RFC 1918, RFC 3927, RFC 5737, RFC 6598, RFC 2544, etc.
 */
function classifyIpv4(address: string): AddressClassification {
  const ipUint = parseIpv4ToUint32(address)
  if (ipUint === null) {
    return {
      scope: 'UNSUPPORTED',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 0.0.0.0/8 (Current network / Unspecified)
  if (((ipUint & 0xff000000) >>> 0) === 0x00000000) {
    return {
      scope: 'UNSPECIFIED',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: '0.0.0.0'
    }
  }

  // 127.0.0.0/8 (Loopback: 127.0.0.0 a 127.255.255.255)
  if (((ipUint & 0xff000000) >>> 0) === 0x7f000000) {
    return {
      scope: 'LOOPBACK',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 10.0.0.0/8 (RFC 1918: 10.0.0.0 a 10.255.255.255)
  if (((ipUint & 0xff000000) >>> 0) === 0x0a000000) {
    return {
      scope: 'LAN_PRIVATE',
      family: 'IPv4',
      isSelectableForLan: true,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 100.64.0.0/10 (RFC 6598: Shared Address Space / CGNAT: 100.64.0.0 a 100.127.255.255)
  if (((ipUint & 0xffc00000) >>> 0) === 0x64400000) {
    return {
      scope: 'CGNAT',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 172.16.0.0/12 (RFC 1918: 172.16.0.0 a 172.31.255.255)
  if (((ipUint & 0xfff00000) >>> 0) === 0xac100000) {
    return {
      scope: 'LAN_PRIVATE',
      family: 'IPv4',
      isSelectableForLan: true,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 169.254.0.0/16 (RFC 3927: Link-Local)
  if (((ipUint & 0xffff0000) >>> 0) === 0xa9fe0000) {
    return {
      scope: 'LINK_LOCAL',
      family: 'IPv4',
      isSelectableForLan: true,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 192.0.0.0/24 (RFC 6890: IETF Protocol Assignments)
  if (((ipUint & 0xffffff00) >>> 0) === 0xc0000000) {
    return {
      scope: 'RESERVED',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 192.0.2.0/24 (RFC 5737: TEST-NET-1 Documentation)
  if (((ipUint & 0xffffff00) >>> 0) === 0xc0000200) {
    return {
      scope: 'DOCUMENTATION',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 192.88.99.0/24 (RFC 3068 / RFC 7526: 6to4 Relay Anycast)
  if (((ipUint & 0xffffff00) >>> 0) === 0xc0586300) {
    return {
      scope: 'RESERVED',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 192.168.0.0/16 (RFC 1918: 192.168.0.0 a 192.168.255.255)
  if (((ipUint & 0xffff0000) >>> 0) === 0xc0a80000) {
    return {
      scope: 'LAN_PRIVATE',
      family: 'IPv4',
      isSelectableForLan: true,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 198.18.0.0/15 (RFC 2544 / RFC 6890: Benchmark: 198.18.0.0 a 198.19.255.255)
  if (((ipUint & 0xfffe0000) >>> 0) === 0xc6120000) {
    return {
      scope: 'BENCHMARK',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 198.51.100.0/24 (RFC 5737: TEST-NET-2 Documentation)
  if (((ipUint & 0xffffff00) >>> 0) === 0xc6336400) {
    return {
      scope: 'DOCUMENTATION',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 203.0.113.0/24 (RFC 5737: TEST-NET-3 Documentation)
  if (((ipUint & 0xffffff00) >>> 0) === 0xcb007100) {
    return {
      scope: 'DOCUMENTATION',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 224.0.0.0/4 (Multicast: 224.0.0.0 a 239.255.255.255)
  if (((ipUint & 0xf0000000) >>> 0) === 0xe0000000) {
    return {
      scope: 'MULTICAST',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // 240.0.0.0/4 (RFC 1112: Reserved for future use / Broadcast 255.255.255.255)
  if (((ipUint & 0xf0000000) >>> 0) === 0xf0000000) {
    return {
      scope: 'RESERVED',
      family: 'IPv4',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  // Endereço IPv4 globalmente roteável (Global Unicast)
  return {
    scope: 'GLOBAL',
    family: 'IPv4',
    isSelectableForLan: false,
    isGloballyRoutableWan: true,
    normalizedAddress: address
  }
}

/**
 * Converte um endereço IPv6 em 8 palavras de 16 bits (0..65535).
 * Retorna null se for inválido ou malformado.
 */
function parseIpv6ToWords(rawAddress: string): number[] | null {
  const address = rawAddress.toLowerCase().trim()
  if (isIP(address) !== 6) return null

  // Trata separação por "::"
  const doubleColonCount = (address.match(/::/g) || []).length
  if (doubleColonCount > 1) return null

  let parts: string[]
  if (doubleColonCount === 1) {
    const [head, tail] = address.split('::')
    const headParts = head ? head.split(':') : []
    const tailParts = tail ? tail.split(':') : []
    const missing = 8 - (headParts.length + tailParts.length)
    if (missing < 1) return null
    parts = [...headParts, ...Array(missing).fill('0'), ...tailParts]
  } else {
    parts = address.split(':')
  }

  if (parts.length !== 8) return null

  const words: number[] = []
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/i.test(part)) return null
    const num = parseInt(part, 16)
    if (isNaN(num) || num < 0 || num > 0xffff) return null
    words.push(num)
  }

  return words
}

/**
 * Formata deterministamente 8 palavras de IPv6 segundo RFC 5952.
 */
function formatCanonicalIpv6(words: number[]): string {
  // Localiza a maior sequência contínua de zeros (mínimo 2 grupos)
  let bestStart = -1
  let bestLen = 0
  let curStart = -1
  let curLen = 0

  for (let i = 0; i < 8; i++) {
    if (words[i] === 0) {
      if (curStart === -1) {
        curStart = i
        curLen = 1
      } else {
        curLen++
      }
      if (curLen > bestLen) {
        bestLen = curLen
        bestStart = curStart
      }
    } else {
      curStart = -1
      curLen = 0
    }
  }

  if (bestLen < 2) {
    return words.map((w) => w.toString(16)).join(':')
  }

  const head = words.slice(0, bestStart).map((w) => w.toString(16)).join(':')
  const tail = words.slice(bestStart + bestLen).map((w) => w.toString(16)).join(':')

  if (!head && !tail) return '::'
  if (!head) return `::${tail}`
  if (!tail) return `${head}::`
  return `${head}::${tail}`
}

/**
 * Normaliza e classifica um endereço IPv6 com suporte a ULA, Link-Local, Loopback, Documentação e Global.
 */
function classifyIpv6(rawAddress: string, scopeId?: number): AddressClassification {
  let address = rawAddress.toLowerCase().trim()

  // Remove eventual prefixo ou sufixo com %scopeId no string se existir
  const percentIndex = address.indexOf('%')
  let parsedScopeId = scopeId
  if (percentIndex !== -1) {
    const scopeStr = address.slice(percentIndex + 1)
    address = address.slice(0, percentIndex)
    if (parsedScopeId === undefined && /^\d+$/.test(scopeStr)) {
      parsedScopeId = parseInt(scopeStr, 10)
    }
  }

  // IPv4-mapped IPv6 (::ffff:x.x.x.x)
  if (address.startsWith('::ffff:')) {
    const mappedIpv4 = address.slice(7)
    if (isIP(mappedIpv4) === 4) {
      const ipv4Class = classifyIpv4(mappedIpv4)
      return {
        scope: ipv4Class.scope,
        family: 'IPv6',
        isSelectableForLan: ipv4Class.isSelectableForLan,
        isGloballyRoutableWan: ipv4Class.isGloballyRoutableWan,
        normalizedAddress: `::ffff:${ipv4Class.normalizedAddress}`
      }
    }
  }

  const words = parseIpv6ToWords(address)
  if (!words || words.length !== 8) {
    return {
      scope: 'UNSUPPORTED',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: address
    }
  }

  const canonicalAddress = formatCanonicalIpv6(words)
  const isAllZero = words.every((w) => w === 0)

  // Unspecified ::
  if (isAllZero) {
    return {
      scope: 'UNSPECIFIED',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: '::'
    }
  }

  // Loopback ::1
  if (words.slice(0, 7).every((w) => w === 0) && words[7] === 1) {
    return {
      scope: 'LOOPBACK',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: '::1'
    }
  }

  // IPv4-mapped IPv6 (::ffff:x.x.x.x ou ::ffff:0:0/96)
  if (words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff) {
    const w6 = words[6] ?? 0
    const w7 = words[7] ?? 0
    const ipv4Uint = ((w6 << 16) | w7) >>> 0
    const p1 = (ipv4Uint >>> 24) & 0xff
    const p2 = (ipv4Uint >>> 16) & 0xff
    const p3 = (ipv4Uint >>> 8) & 0xff
    const p4 = ipv4Uint & 0xff
    const ipv4Str = `${p1}.${p2}.${p3}.${p4}`
    const ipv4Class = classifyIpv4(ipv4Str)

    return {
      scope: ipv4Class.scope,
      family: 'IPv6',
      isSelectableForLan: ipv4Class.isSelectableForLan,
      isGloballyRoutableWan: ipv4Class.isGloballyRoutableWan,
      normalizedAddress: `::ffff:${ipv4Class.normalizedAddress}`
    }
  }

  const w0 = words[0] ?? 0
  const w1 = words[1] ?? 0

  // Multicast ff00::/8
  if ((w0 & 0xff00) === 0xff00) {
    return {
      scope: 'MULTICAST',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // ULA fc00::/7 (fc00::/8 e fd00::/8)
  if ((w0 & 0xfe00) === 0xfc00) {
    return {
      scope: 'LAN_PRIVATE',
      family: 'IPv6',
      isSelectableForLan: true,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // Link-Local fe80::/10 (fe80..febf)
  if ((w0 & 0xffc0) === 0xfe80) {
    const hasValidScope = typeof parsedScopeId === 'number' && parsedScopeId >= 0
    return {
      scope: 'LINK_LOCAL',
      family: 'IPv6',
      isSelectableForLan: hasValidScope,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // Site-Local deprecated fec0::/10 (RFC 3879)
  if ((w0 & 0xffc0) === 0xfec0) {
    return {
      scope: 'RESERVED',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // Documentation 2001:db8::/32 (RFC 3849)
  if (w0 === 0x2001 && w1 === 0x0db8) {
    return {
      scope: 'DOCUMENTATION',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // Benchmarking 2001:2::/48 (RFC 5180)
  if (w0 === 0x2001 && w1 === 0x0002) {
    return {
      scope: 'BENCHMARK',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // ORCHID 2001:10::/28 (RFC 4843) e 2001:20::/28 (RFC 7343)
  if (w0 === 0x2001 && ((w1 & 0xfff0) === 0x0010 || (w1 & 0xfff0) === 0x0020)) {
    return {
      scope: 'RESERVED',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // 6to4 2002::/16 (RFC 3056)
  if (w0 === 0x2002) {
    return {
      scope: 'RESERVED',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: canonicalAddress
    }
  }

  // Global Unicast 2000::/3 (RFC 4291)
  if ((w0 & 0xe000) === 0x2000) {
    return {
      scope: 'GLOBAL',
      family: 'IPv6',
      isSelectableForLan: false,
      isGloballyRoutableWan: true,
      normalizedAddress: canonicalAddress
    }
  }

  // Qualquer outro IPv6 não alocado / reservado
  return {
    scope: 'RESERVED',
    family: 'IPv6',
    isSelectableForLan: false,
    isGloballyRoutableWan: false,
    normalizedAddress: canonicalAddress
  }
}

/**
 * Classifica deterministamente qualquer endereço IP ou string fornecida.
 */
export function classifyNetworkAddress(
  address: string,
  scopeId?: number
): AddressClassification {
  if (typeof address !== 'string') {
    return {
      scope: 'UNSUPPORTED',
      family: 'UNKNOWN',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: ''
    }
  }

  const trimmed = address.trim()
  if (trimmed.length === 0) {
    return {
      scope: 'UNSUPPORTED',
      family: 'UNKNOWN',
      isSelectableForLan: false,
      isGloballyRoutableWan: false,
      normalizedAddress: ''
    }
  }

  const ipVer = isIP(trimmed)
  if (ipVer === 4) {
    return classifyIpv4(trimmed)
  }

  if (ipVer === 6 || trimmed.includes(':')) {
    return classifyIpv6(trimmed, scopeId)
  }

  return {
    scope: 'UNSUPPORTED',
    family: 'UNKNOWN',
    isSelectableForLan: false,
    isGloballyRoutableWan: false,
    normalizedAddress: trimmed
  }
}

/**
 * Valida o nome de uma interface de rede para proteção contra nomes maliciosos ou excessivos.
 */
function isValidInterfaceName(name: string): boolean {
  if (typeof name !== 'string') return false
  if (name.length === 0 || name.length > MAX_INTERFACE_NAME_LENGTH) return false
  for (let i = 0; i < name.length; i++) {
    const code = name.charCodeAt(i)
    if (code < 32 || code === 127) return false
  }
  return true
}

/**
 * Enumera e classifica todas as interfaces de rede locais ativas.
 * Rejeita interfaces ilegítimas, wildcards e endereços com formato inválido.
 */
export function enumerateNetworkAddresses(
  provider: NetworkInterfaceProvider = networkInterfaces
): readonly LocalNetworkAddress[] {
  let rawInterfaces: NodeJS.Dict<NetworkInterfaceInfo[]>

  try {
    rawInterfaces = provider()
  } catch {
    return []
  }

  if (!rawInterfaces || typeof rawInterfaces !== 'object') {
    return []
  }

  const result: LocalNetworkAddress[] = []
  const interfaceNames = Object.keys(rawInterfaces).slice(0, MAX_INTERFACES_COUNT)

  for (const name of interfaceNames) {
    if (!isValidInterfaceName(name)) {
      continue
    }

    const infos = rawInterfaces[name]
    if (!Array.isArray(infos)) {
      continue
    }

    for (const info of infos) {
      if (!info || typeof info !== 'object') continue
      if (typeof info.address !== 'string') continue

      const infoFamily = (info as { family: unknown }).family
      const family: 'IPv4' | 'IPv6' | null =
        infoFamily === 'IPv4' || infoFamily === 4
          ? 'IPv4'
          : infoFamily === 'IPv6' || infoFamily === 6
            ? 'IPv6'
            : null

      if (!family) continue

      const classification = classifyNetworkAddress(info.address, info.scopeid)
      if (classification.scope === 'UNSUPPORTED' || classification.scope === 'UNSPECIFIED') {
        continue
      }
      if (classification.family !== family) continue

      result.push({
        interfaceName: name,
        family,
        address: classification.normalizedAddress,
        cidr: typeof info.cidr === 'string' ? info.cidr : null,
        scope: classification.scope,
        internal: Boolean(info.internal),
        scopeId: typeof info.scopeid === 'number' ? info.scopeid : undefined,
        isSelectableForLan: classification.isSelectableForLan
      })

      if (result.length >= MAX_ADDRESSES_COUNT) {
        return Object.freeze(result)
      }
    }
  }

  return Object.freeze(result)
}

export const listLocalNetworkInterfaces = enumerateNetworkAddresses

/**
 * Retorna um snapshot deduplicado dos IPv6 globais elegíveis. O snapshot é
 * apenas informação local e deliberadamente não constitui uma capability.
 * Endereços presentes em mais de uma interface são omitidos por ambiguidade.
 */
export function listEligibleDirectGlobalIpv6Addresses(
  provider: NetworkInterfaceProvider = networkInterfaces
): readonly EligibleDirectGlobalIpv6Address[] {
  const byAddress = new Map<string, {
    readonly interfaces: Map<string, LocalNetworkAddress>
    hasInternal: boolean
  }>()

  for (const entry of enumerateNetworkAddresses(provider)) {
    if (
      entry.family !== 'IPv6' ||
      entry.scope !== 'GLOBAL' ||
      entry.address.startsWith('::ffff:')
    ) {
      continue
    }

    const classification = classifyNetworkAddress(entry.address)
    if (
      classification.family !== 'IPv6' ||
      classification.scope !== 'GLOBAL' ||
      !classification.isGloballyRoutableWan
    ) {
      continue
    }

    let group = byAddress.get(classification.normalizedAddress)
    if (!group) {
      group = { interfaces: new Map(), hasInternal: false }
      byAddress.set(classification.normalizedAddress, group)
    }
    group.hasInternal ||= entry.internal
    group.interfaces.set(entry.interfaceName, entry)
  }

  const result: EligibleDirectGlobalIpv6Address[] = []
  for (const [address, group] of byAddress) {
    if (group.hasInternal || group.interfaces.size !== 1) continue
    const [entry] = group.interfaces.values()
    if (!entry || entry.internal) continue
    result.push(Object.freeze({ address, interfaceName: entry.interfaceName }))
  }

  result.sort((a, b) => a.address.localeCompare(b.address))
  return Object.freeze(result)
}

/** Busca uma atribuição IPv6 global não ambígua no snapshot atual do SO. */
export function findAssignedGlobalIpv6Address(
  address: string,
  provider: NetworkInterfaceProvider = networkInterfaces
): EligibleDirectGlobalIpv6Address | null {
  if (typeof address !== 'string' || address.includes('%')) return null
  const classification = classifyNetworkAddress(address)
  if (
    classification.family !== 'IPv6' ||
    classification.scope !== 'GLOBAL' ||
    !classification.isGloballyRoutableWan ||
    classification.normalizedAddress.startsWith('::ffff:')
  ) {
    return null
  }

  return listEligibleDirectGlobalIpv6Addresses(provider).find(
    (entry) => entry.address === classification.normalizedAddress
  ) ?? null
}
