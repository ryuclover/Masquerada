import { createHash } from 'node:crypto'

import {
  listLocalNetworkInterfaces,
  type LocalNetworkAddress,
  type NetworkInterfaceProvider
} from './network-interfaces'

export interface CanonicalNetworkAddress {
  readonly interfaceName: string
  readonly family: 'IPv4' | 'IPv6'
  readonly address: string
  readonly internal: boolean
  readonly scopeId?: number
}

export interface NetworkEnvironmentGeneration {
  readonly generation: number
  readonly fingerprint: string
  readonly addresses: readonly CanonicalNetworkAddress[]
}

const generations = new WeakSet<object>()

function canonicalize(addresses: readonly LocalNetworkAddress[]): readonly CanonicalNetworkAddress[] {
  const unique = new Map<string, CanonicalNetworkAddress>()
  for (const address of addresses) {
    const item = Object.freeze({
      interfaceName: address.interfaceName,
      family: address.family,
      address: address.address,
      internal: address.internal,
      ...(address.scopeId === undefined ? {} : { scopeId: address.scopeId })
    })
    const key = `${item.family}|${item.address}|${item.internal ? 1 : 0}|${item.scopeId ?? ''}|${item.interfaceName}`
    unique.set(key, item)
  }
  return Object.freeze([...unique.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value))
}

function createGeneration(generation: number, addresses: readonly CanonicalNetworkAddress[]): NetworkEnvironmentGeneration {
  const fingerprint = createHash('sha256').update(JSON.stringify(addresses)).digest('hex')
  const value = Object.freeze({ generation, fingerprint, addresses })
  generations.add(value)
  return value
}

export function isNetworkEnvironmentGeneration(value: unknown): value is NetworkEnvironmentGeneration {
  return typeof value === 'object' && value !== null && generations.has(value)
}

/** Explicitly refreshed snapshot; it installs no watcher and starts no background I/O. */
export class NetworkEnvironmentTracker {
  private current: NetworkEnvironmentGeneration

  constructor(private readonly provider?: NetworkInterfaceProvider) {
    this.current = createGeneration(1, canonicalize(listLocalNetworkInterfaces(provider)))
  }

  snapshot(): NetworkEnvironmentGeneration { return this.current }

  refresh(): NetworkEnvironmentGeneration {
    const nextAddresses = canonicalize(listLocalNetworkInterfaces(this.provider))
    const candidate = createGeneration(this.current.generation + 1, nextAddresses)
    if (candidate.fingerprint === this.current.fingerprint) return this.current
    this.current = candidate
    return this.current
  }
}

export function sameNetworkGeneration(
  left: NetworkEnvironmentGeneration | undefined,
  right: NetworkEnvironmentGeneration | undefined
): boolean {
  return left !== undefined && right !== undefined &&
    isNetworkEnvironmentGeneration(left) && isNetworkEnvironmentGeneration(right) &&
    left.generation === right.generation && left.fingerprint === right.fingerprint
}
