import { describe, expect, it } from 'vitest'

import { DATABASE_SCHEMA_VERSION } from '../servers/server-database'
import {
  CONNECTIVITY_DESCRIPTOR_VERSION,
  ConnectivityCandidateType
} from './connectivity-descriptor'
import {
  decideConnectivityContinuation,
  type ConnectivityFailureClass,
  type ConnectivityFailurePhase
} from './connectivity-failure'
import { ConnectivityResourceGovernor } from './connectivity-resource-governor'
import { ConnectivitySubsystem } from './connectivity-subsystem'

describe('phase 7 final hardening invariants', () => {
  it('keeps schema v6, descriptor v1 and exactly the three established candidate types', () => {
    expect(DATABASE_SCHEMA_VERSION).toBe(6)
    expect(CONNECTIVITY_DESCRIPTOR_VERSION).toBe(1)
    expect(Object.entries(ConnectivityCandidateType)
      .filter(([, value]) => typeof value === 'number')
      .map(([name]) => name)).toEqual(['LAN_TCP', 'PORT_MAPPED_TCP', 'DIRECT_GLOBAL_TCP'])
  })

  it('fresh subsystem instances contain no restored topology, operation or resource state', () => {
    const first = new ConnectivitySubsystem(new ConnectivityResourceGovernor())
    const second = new ConnectivitySubsystem(new ConnectivityResourceGovernor())
    expect(first.getState()).toBe('RUNNING')
    expect(second.getState()).toBe('RUNNING')
    expect(first.governor.snapshot()).toEqual(second.governor.snapshot())
    expect(first.governor.snapshot().activeTargets).toBe(0)
    expect(Object.values(first.governor.snapshot().counts).every((count) => count === 0)).toBe(true)
  })

  it('seeded state-machine permutations never reactivate terminal state or fallback after auth', () => {
    const classes: ConnectivityFailureClass[] = [
      'TRANSIENT_REACHABILITY', 'TARGET_IDENTITY_MISMATCH', 'TARGET_AUTHORIZATION_FAILURE',
      'STALE_ROUTING_STATE', 'LOCAL_NETWORK_CHANGED', 'RESOURCE_LIMIT', 'REMOTE_RESOURCE_LIMIT',
      'PROTOCOL_INVALID', 'SECURITY_INVARIANT_FAILURE', 'ABORTED', 'SHUTTING_DOWN', 'INTERNAL_FAILURE'
    ]
    const phases: ConnectivityFailurePhase[] = ['DIRECT', 'RENDEZVOUS', 'RELAY', 'AUTHORIZATION', 'LOCAL_SETUP']
    let seed = 0x7a12c0de
    let terminal = false
    for (let index = 0; index < 1000; index++) {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0
      const failureClass = classes[seed % classes.length]!
      const phase = phases[(seed >>> 8) % phases.length]!
      const authorizationStarted = terminal || ((seed >>> 16) & 1) === 1
      const decision = decideConnectivityContinuation({
        failure: { failureClass, known: true }, phase, authorizationStarted
      })
      if (authorizationStarted) expect(decision.startsWith('NEXT_')).toBe(false)
      if (decision.startsWith('TERMINAL_')) terminal = true
      if (terminal) expect(authorizationStarted || decision.startsWith('TERMINAL_')).toBe(true)
    }
  })
})
