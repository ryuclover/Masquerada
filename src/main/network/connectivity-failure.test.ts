import { describe, expect, it } from 'vitest'

import { CandidateRaceError } from './candidate-racing'
import {
  classifyConnectivityFailure,
  decideConnectivityContinuation,
  type ConnectivityFailureClass
} from './connectivity-failure'
import { ConnectivityResourceError } from './connectivity-resource-governor'
import { LanDiscoveryError } from './lan-discovery'
import { PeerRelayError } from './peer-relay'
import { PeerRendezvousError } from './peer-rendezvous'
import { PortMappingStrategyError } from './port-mapping-strategy'
import { StunObservationError } from './stun-observation'

describe('global connectivity failure matrix', () => {
  it.each<[unknown, ConnectivityFailureClass]>([
    [new CandidateRaceError('CANDIDATE_RACE_TIMEOUT'), 'TRANSIENT_REACHABILITY'],
    [new CandidateRaceError('CANDIDATE_SECURE_HANDSHAKE_FAILED'), 'TARGET_IDENTITY_MISMATCH'],
    [new CandidateRaceError('CANDIDATE_PLAN_INVALID'), 'SECURITY_INVARIANT_FAILURE'],
    [new CandidateRaceError('CANDIDATE_RACE_ABORTED'), 'ABORTED'],
    [new PeerRendezvousError('RENDEZVOUS_NOT_AVAILABLE'), 'TRANSIENT_REACHABILITY'],
    [new PeerRendezvousError('RENDEZVOUS_DESCRIPTOR_INVALID'), 'PROTOCOL_INVALID'],
    [new PeerRelayError('RELAY_TARGET_NOT_AVAILABLE'), 'TRANSIENT_REACHABILITY'],
    [new PeerRelayError('RELAY_RESOURCE_LIMIT'), 'REMOTE_RESOURCE_LIMIT'],
    [new StunObservationError('STUN_LOCAL_ADDRESS_NOT_ASSIGNED'), 'LOCAL_NETWORK_CHANGED'],
    [new LanDiscoveryError('DISCOVERY_INTERFACE_UNAVAILABLE'), 'LOCAL_NETWORK_CHANGED'],
    [new PortMappingStrategyError('PORT_MAPPING_TOPOLOGY_INVALID'), 'STALE_ROUTING_STATE'],
    [new ConnectivityResourceError('CONNECTIVITY_RESOURCE_LIMIT'), 'RESOURCE_LIMIT']
  ])('classifies known typed errors without text matching', (error, expected) => {
    expect(classifyConnectivityFailure(error)).toEqual({ failureClass: expected, known: true })
  })

  it.each([null, undefined, 'timeout', 7, {}, { code: 'CANDIDATE_RACE_TIMEOUT' }, new Error('timeout')])(
    'classifies unknown/foreign value %p as terminal internal failure', (value) => {
      const classified = classifyConnectivityFailure(value)
      expect(classified).toEqual({ failureClass: 'INTERNAL_FAILURE', known: false })
      expect(decideConnectivityContinuation({ failure: classified, phase: 'RELAY', authorizationStarted: false }))
        .toBe('TERMINAL_SECURITY')
    }
  )

  it('never permits fallback after authorization starts', () => {
    for (const failureClass of [
      'TRANSIENT_REACHABILITY', 'TARGET_IDENTITY_MISMATCH', 'PROTOCOL_INVALID', 'REMOTE_RESOURCE_LIMIT'
    ] as const) {
      expect(decideConnectivityContinuation({
        failure: { failureClass, known: true }, phase: 'RELAY', authorizationStarted: true
      })).toBe('TERMINAL_AUTH')
    }
  })

  it('encodes the bounded direct/rendezvous/relay continuation matrix', () => {
    const transient = { failureClass: 'TRANSIENT_REACHABILITY' as const, known: true }
    expect(decideConnectivityContinuation({ failure: transient, phase: 'DIRECT', authorizationStarted: false })).toBe('NEXT_DIRECT_SOURCE')
    expect(decideConnectivityContinuation({ failure: transient, phase: 'RENDEZVOUS', authorizationStarted: false })).toBe('NEXT_RENDEZVOUS')
    expect(decideConnectivityContinuation({ failure: transient, phase: 'RELAY', authorizationStarted: false })).toBe('NEXT_RELAY')
    expect(decideConnectivityContinuation({ failure: { failureClass: 'RESOURCE_LIMIT', known: true }, phase: 'DIRECT', authorizationStarted: false })).toBe('TERMINAL_RESOURCE')
  })
})
