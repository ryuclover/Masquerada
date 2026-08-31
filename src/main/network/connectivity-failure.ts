import { CandidateRaceError } from './candidate-racing'
import { LanDiscoveryError } from './lan-discovery'
import { PeerRelayError } from './peer-relay'
import { PeerRendezvousError } from './peer-rendezvous'
import { PortMappingStrategyError } from './port-mapping-strategy'
import { StunObservationError } from './stun-observation'
import { ConnectivityResourceError } from './connectivity-resource-governor'
import { ConnectivitySubsystemError } from './connectivity-subsystem'

export type ConnectivityFailureClass =
  | 'TRANSIENT_REACHABILITY'
  | 'TARGET_IDENTITY_MISMATCH'
  | 'TARGET_AUTHORIZATION_FAILURE'
  | 'STALE_ROUTING_STATE'
  | 'LOCAL_NETWORK_CHANGED'
  | 'RESOURCE_LIMIT'
  | 'REMOTE_RESOURCE_LIMIT'
  | 'PROTOCOL_INVALID'
  | 'SECURITY_INVARIANT_FAILURE'
  | 'ABORTED'
  | 'SHUTTING_DOWN'
  | 'INTERNAL_FAILURE'

export type ConnectivityContinuationDecision =
  | 'CONTINUE_CURRENT_PHASE'
  | 'NEXT_DIRECT_SOURCE'
  | 'NEXT_RENDEZVOUS'
  | 'NEXT_RELAY'
  | 'TERMINAL_AUTH'
  | 'TERMINAL_ABORT'
  | 'TERMINAL_SECURITY'
  | 'TERMINAL_RESOURCE'
  | 'TERMINAL_SHUTDOWN'

export type ConnectivityFailurePhase = 'DIRECT' | 'RENDEZVOUS' | 'RELAY' | 'AUTHORIZATION' | 'LOCAL_SETUP'

export interface ClassifiedConnectivityFailure {
  readonly failureClass: ConnectivityFailureClass
  readonly known: boolean
}

const known = (failureClass: ConnectivityFailureClass): ClassifiedConnectivityFailure =>
  Object.freeze({ failureClass, known: true })

/** Semantic classification only: no error-message, error-name or regex matching. */
export function classifyConnectivityFailure(error: unknown): ClassifiedConnectivityFailure {
  if (error instanceof ConnectivityResourceError) return known('RESOURCE_LIMIT')
  if (error instanceof ConnectivitySubsystemError) return known('SHUTTING_DOWN')
  if (error instanceof CandidateRaceError) {
    switch (error.code) {
      case 'CANDIDATE_RACE_ABORTED': return known('ABORTED')
      case 'CANDIDATE_PLAN_INVALID': return known('SECURITY_INVARIANT_FAILURE')
      case 'CANDIDATE_RACE_TIMEOUT':
      case 'NO_REACHABLE_SERVER_CANDIDATE': return known('TRANSIENT_REACHABILITY')
      case 'CANDIDATE_SECURE_HANDSHAKE_FAILED': return known('TARGET_IDENTITY_MISMATCH')
    }
  }
  if (error instanceof PeerRendezvousError) {
    switch (error.code) {
      case 'RENDEZVOUS_ABORTED': return known('ABORTED')
      case 'RENDEZVOUS_RATE_LIMITED':
      case 'RENDEZVOUS_OUTSTANDING_LIMIT':
      case 'RENDEZVOUS_STORE_FULL': return known('REMOTE_RESOURCE_LIMIT')
      case 'RENDEZVOUS_DESCRIPTOR_INVALID':
      case 'RENDEZVOUS_DESCRIPTOR_NOT_SHAREABLE':
      case 'RENDEZVOUS_NONCE_MISMATCH':
      case 'RENDEZVOUS_SERVER_MISMATCH':
      case 'RENDEZVOUS_PROTOCOL_INVALID': return known('PROTOCOL_INVALID')
      case 'RENDEZVOUS_NOT_AVAILABLE':
      case 'RENDEZVOUS_TIMEOUT':
      case 'RENDEZVOUS_CHANNEL_CLOSED':
      case 'RENDEZVOUS_NOT_AUTHORIZED': return known('TRANSIENT_REACHABILITY')
    }
  }
  if (error instanceof PeerRelayError) {
    switch (error.code) {
      case 'RELAY_OPEN_ABORTED': return known('ABORTED')
      case 'RELAY_CIRCUIT_LIMIT':
      case 'RELAY_RESOURCE_LIMIT': return known('REMOTE_RESOURCE_LIMIT')
      case 'RELAY_PROTOCOL_INVALID':
      case 'RELAY_REGISTRATION_PROOF_INVALID': return known('PROTOCOL_INVALID')
      case 'RELAY_REGISTRATION_INVALID': return known('SECURITY_INVARIANT_FAILURE')
      case 'RELAY_TARGET_NOT_AVAILABLE':
      case 'RELAY_REGISTRATION_CHALLENGE_EXPIRED':
      case 'RELAY_REGISTRATION_EXPIRED':
      case 'RELAY_OPEN_TIMEOUT':
      case 'RELAY_CIRCUIT_INVALID':
      case 'RELAY_CIRCUIT_CLOSED':
      case 'RELAY_PAYLOAD_TOO_LARGE':
      case 'RELAY_IDLE_TIMEOUT':
      case 'RELAY_LIFETIME_EXCEEDED':
      case 'RELAY_CHANNEL_CLOSED':
      case 'RELAY_NOT_AUTHORIZED': return known('TRANSIENT_REACHABILITY')
    }
  }
  if (error instanceof StunObservationError) {
    switch (error.code) {
      case 'STUN_ABORTED': return known('ABORTED')
      case 'STUN_TIMEOUT':
      case 'STUN_SOCKET_ERROR':
      case 'STUN_SERVER_ERROR': return known('TRANSIENT_REACHABILITY')
      case 'STUN_LOCAL_ADDRESS_NOT_ASSIGNED': return known('LOCAL_NETWORK_CHANGED')
      case 'STUN_TARGET_INVALID':
      case 'STUN_LOCAL_ADDRESS_INVALID': return known('SECURITY_INVARIANT_FAILURE')
      default: return known('PROTOCOL_INVALID')
    }
  }
  if (error instanceof LanDiscoveryError) {
    switch (error.code) {
      case 'DISCOVERY_ABORTED': return known('ABORTED')
      case 'DISCOVERY_INTERFACE_UNAVAILABLE': return known('LOCAL_NETWORK_CHANGED')
      case 'DISCOVERY_TIMEOUT':
      case 'DISCOVERY_CLOSED':
      case 'DISCOVERY_SOCKET_ERROR': return known('TRANSIENT_REACHABILITY')
      case 'DISCOVERY_PORT_IN_USE':
      case 'DISCOVERY_NO_ACTIVE_LISTENERS': return known('RESOURCE_LIMIT')
      default: return known('PROTOCOL_INVALID')
    }
  }
  if (error instanceof PortMappingStrategyError) {
    switch (error.code) {
      case 'PORT_MAPPING_ABORTED': return known('ABORTED')
      case 'PORT_MAPPING_OPERATION_IN_PROGRESS':
      case 'PORT_MAPPING_ALREADY_ACTIVE': return known('RESOURCE_LIMIT')
      case 'PORT_MAPPING_LISTENER_CLOSED': return known('LOCAL_NETWORK_CHANGED')
      case 'NO_PORT_MAPPING_AVAILABLE': return known('TRANSIENT_REACHABILITY')
      case 'PORT_MAPPING_DENIED': return known('REMOTE_RESOURCE_LIMIT')
      case 'PORT_MAPPING_TOPOLOGY_INVALID': return known('STALE_ROUTING_STATE')
      case 'PORT_MAPPING_LISTENER_INVALID':
      case 'PORT_MAPPING_LOCAL_UNSUPPORTED':
      case 'PORT_MAPPING_NOT_ACTIVE': return known('SECURITY_INVARIANT_FAILURE')
      case 'PORT_MAPPING_INTERNAL_FAILURE': return known('INTERNAL_FAILURE')
    }
  }
  return Object.freeze({ failureClass: 'INTERNAL_FAILURE', known: false })
}

export function decideConnectivityContinuation(options: {
  readonly failure: ClassifiedConnectivityFailure
  readonly phase: ConnectivityFailurePhase
  readonly authorizationStarted: boolean
}): ConnectivityContinuationDecision {
  const kind = options.failure.failureClass
  if (kind === 'SHUTTING_DOWN') return 'TERMINAL_SHUTDOWN'
  if (kind === 'ABORTED') return 'TERMINAL_ABORT'
  if (options.authorizationStarted || kind === 'TARGET_AUTHORIZATION_FAILURE') return 'TERMINAL_AUTH'
  if (kind === 'RESOURCE_LIMIT' || kind === 'REMOTE_RESOURCE_LIMIT') return 'TERMINAL_RESOURCE'
  if (kind === 'SECURITY_INVARIANT_FAILURE' || kind === 'INTERNAL_FAILURE') return 'TERMINAL_SECURITY'
  if (options.phase === 'DIRECT') return 'NEXT_DIRECT_SOURCE'
  if (options.phase === 'RENDEZVOUS') return 'NEXT_RENDEZVOUS'
  if (options.phase === 'RELAY') return 'NEXT_RELAY'
  return 'CONTINUE_CURRENT_PHASE'
}
