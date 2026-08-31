/**
 * PcpFirstOrchestrator — Etapa 7.3
 *
 * Tenta PCP (Version 2 MAP) primeiro; faz fallback para NAT-PMP (RFC 6886) apenas quando
 * o gateway retorna Result Code UNSUPP_VERSION (1) de forma autentica.
 *
 * Regras de downgrade:
 *   - Downgrade e permitido SOMENTE se a resposta PCP vier do gateway esperado
 *     E contiver Version=1 e Result Code=1 (UNSUPP_VERSION).
 *   - Qualquer outro erro PCP (timeout, network failure, etc.) NAO faz fallback para NAT-PMP.
 *   - NAT-PMP NUNCA é tentado se o gateway PCP nao responder (protecao contra spoofing).
 *
 * Invariante: o resultado e sempre um ActivePortMapping nao-forjavel,
 * semanticamente identico independente do protocolo usado.
 */

import {
  createPcpPortMapping,
  PcpError,
  type CreatePcpPortMappingOptions,
  type PcpGatewayProvider,
  type MonotonicClockProvider
} from './pcp-client'
import {
  createNatPmpPortMapping,
  type NatPmpGatewayProvider,
  type CreateNatPmpPortMappingOptions
} from './nat-pmp-client'
import { type LanTcpServerHandle } from './lan-transport'
import {
  isLegitimateActivePortMapping,
  type ActivePortMappingSource
} from './active-port-mapping'
import {
  createDefaultPortMappingGatewayProvider,
  type PortMappingGatewayProvider
} from './port-mapping-gateway'

export { isLegitimateActivePortMapping }

export type PortMappingProtocol = 'PCP' | 'NAT_PMP'

export interface PortMappingResult {
  readonly mapping: ActivePortMappingSource
  readonly protocol: PortMappingProtocol
}

export interface CreatePcpFirstPortMappingOptions {
  readonly listener: LanTcpServerHandle
  readonly requestedLifetimeSeconds?: number
  readonly pcpGatewayProvider?: PcpGatewayProvider
  readonly natPmpGatewayProvider?: NatPmpGatewayProvider
  readonly gatewayProvider?: PortMappingGatewayProvider
  readonly customGatewayAddress?: string
  readonly customGatewayPort?: number
  readonly timeoutMs?: number
  readonly maxRetransmissions?: number
  readonly monotonicClock?: MonotonicClockProvider
  /**
   * Se true, NUNCA tenta NAT-PMP, mesmo em caso de UNSUPP_VERSION.
   * Util para testes ou contextos onde NAT-PMP e indesejado.
   */
  readonly disableNatPmpFallback?: boolean
}

/**
 * Realiza o mapeamento de porta tentando PCP primeiro.
 * Se o gateway responder com UNSUPP_VERSION (Result Code 1), tenta NAT-PMP.
 * Qualquer outro erro PCP e propagado diretamente sem fallback.
 */
export async function createPcpFirstPortMapping(
  options: CreatePcpFirstPortMappingOptions
): Promise<PortMappingResult> {
  const resolvedGateway = options.customGatewayAddress ?? await (
    options.gatewayProvider ??
    options.pcpGatewayProvider ??
    options.natPmpGatewayProvider ??
    createDefaultPortMappingGatewayProvider()
  ).resolveGatewayForLocalAddress(options.listener.endpoint.address)

  // --- Tentativa PCP ---
  try {
    const mapping = await createPcpPortMapping({
      listener: options.listener,
      requestedLifetimeSeconds: options.requestedLifetimeSeconds,
      gatewayProvider: options.pcpGatewayProvider,
      customGatewayAddress: resolvedGateway ?? undefined,
      customGatewayPort: options.customGatewayPort,
      timeoutMs: options.timeoutMs,
      maxRetransmissions: options.maxRetransmissions,
      monotonicClock: options.monotonicClock
    } as CreatePcpPortMappingOptions)

    return { mapping, protocol: 'PCP' }
  } catch (err) {
    // Fallback para NAT-PMP SOMENTE se o erro for UNSUPP_VERSION do servidor PCP
    if (
      err instanceof PcpError &&
      err.code === 'PCP_UNSUPPORTED_VERSION' &&
      !options.disableNatPmpFallback
    ) {
      // PCP retornou UNSUPP_VERSION (1) — gateway nao suporta PCP v2
      // Fallback legitimo para NAT-PMP
      const mapping = await createNatPmpPortMapping({
        listener: options.listener,
        requestedLifetimeSeconds: options.requestedLifetimeSeconds,
        gatewayProvider: options.natPmpGatewayProvider,
        customGatewayAddress: resolvedGateway ?? undefined,
        customGatewayPort: options.customGatewayPort,
        initialTimeoutMs: options.timeoutMs,
        maxRetransmissions: options.maxRetransmissions,
        monotonicClock: options.monotonicClock
      } as CreateNatPmpPortMappingOptions)

      return { mapping, protocol: 'NAT_PMP' }
    }

    // Qualquer outro erro PCP (timeout, NOT_AUTHORIZED, NETWORK_FAILURE, etc.)
    // e propagado sem fallback para NAT-PMP
    throw err
  }
}
