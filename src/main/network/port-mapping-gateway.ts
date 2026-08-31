import { execFile } from 'node:child_process'
import { isIP } from 'node:net'
import { promisify } from 'node:util'

import { classifyNetworkAddress } from './network-interfaces'

const execFileAsync = promisify(execFile)

/** Proveniência local compartilhada por PCP e NAT-PMP. */
export interface PortMappingGatewayProvider {
  resolveGatewayForLocalAddress(localIp: string): Promise<string | null>
}

/**
 * Descobre a default route no Windows e falha fechado nas demais plataformas.
 * Não faz scan de gateways e não persiste capabilities do roteador.
 */
export function createDefaultPortMappingGatewayProvider(): PortMappingGatewayProvider {
  return {
    async resolveGatewayForLocalAddress(localIp: string): Promise<string | null> {
      if (process.platform !== 'win32') return null

      try {
        const { stdout } = await execFileAsync('route', ['print', '0.0.0.0'], {
          timeout: 3000,
          maxBuffer: 64 * 1024
        })

        for (const line of stdout.split('\n')) {
          const parts = line.trim().split(/\s+/)
          if (parts.length < 4 || parts[0] !== '0.0.0.0' || parts[1] !== '0.0.0.0') {
            continue
          }

          const gateway = parts[2]
          const routeInterface = parts[3]
          if (!gateway || routeInterface !== localIp || isIP(gateway) !== 4) continue

          const classification = classifyNetworkAddress(gateway)
          if (classification.scope === 'LAN_PRIVATE' || classification.scope === 'LINK_LOCAL') {
            return classification.normalizedAddress
          }
        }
      } catch {
        // Route discovery é fail-closed.
      }

      return null
    }
  }
}
