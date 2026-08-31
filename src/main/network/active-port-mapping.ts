import type { BoundTcpEndpoint, DirectTcpEndpoint } from './lan-transport'

/**
 * Superfície semântica comum de uma lease de port mapping. O protocolo que
 * sustenta a lease é deliberadamente ausente: ele é metadata local de lifecycle.
 */
export abstract class ActivePortMappingSource {
  protected constructor() {
    legitimateMappings.add(this)
  }

  abstract isActive(): boolean
  abstract getExternalEndpoint(): DirectTcpEndpoint
  abstract getExpiresAt(): number
  abstract getGrantedLifetime(): number
  abstract getInternalEndpoint(): BoundTcpEndpoint
  abstract close(): Promise<void>
}

const legitimateMappings = new WeakSet<object>()

export function isLegitimateActivePortMapping(
  mapping: unknown
): mapping is ActivePortMappingSource {
  return typeof mapping === 'object' && mapping !== null && legitimateMappings.has(mapping)
}

export const MIN_MAPPING_REMAINING_FOR_DESCRIPTOR_SECONDS = 15
