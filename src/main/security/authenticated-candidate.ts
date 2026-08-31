import type { KeyObject } from 'node:crypto'

export interface AuthenticatedCandidateDevice {
  readonly fingerprint: string
  readonly publicKey: Buffer
}

export interface AuthenticatedServerIdentity {
  readonly serverId: string
  readonly publicKey: Buffer
}

export interface EstablishedClientHandshakeContext {
  readonly role: 'client'
  readonly transcriptHash: Buffer
  readonly server: AuthenticatedServerIdentity
  readonly deviceFingerprint: string
  readonly devicePublicKey: Buffer
  readonly devicePrivateKey: KeyObject
}

export interface EstablishedServerHandshakeContext {
  readonly role: 'server'
  readonly transcriptHash: Buffer
  readonly candidate: AuthenticatedCandidateDevice
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverPrivateKey: KeyObject
}

const authenticatedDevices = new WeakSet<object>()
const authenticatedServers = new WeakSet<object>()
const authenticatedClientContexts = new WeakSet<object>()
const authenticatedServerContexts = new WeakSet<object>()

export function createAuthenticatedCandidateDevice(
  fingerprint: string,
  publicKey: Buffer
): AuthenticatedCandidateDevice {
  const instance = Object.freeze({
    fingerprint,
    get publicKey(): Buffer {
      return Buffer.from(publicKey)
    }
  })
  authenticatedDevices.add(instance)
  return instance
}

export function isAuthenticatedCandidateDevice(
  value: unknown
): value is AuthenticatedCandidateDevice {
  return typeof value === 'object' && value !== null && authenticatedDevices.has(value)
}

export function createAuthenticatedServerIdentity(
  serverId: string,
  publicKey: Buffer
): AuthenticatedServerIdentity {
  const instance = Object.freeze({
    serverId,
    get publicKey(): Buffer {
      return Buffer.from(publicKey)
    }
  })
  authenticatedServers.add(instance)
  return instance
}

export function isAuthenticatedServerIdentity(
  value: unknown
): value is AuthenticatedServerIdentity {
  return typeof value === 'object' && value !== null && authenticatedServers.has(value)
}

export function createEstablishedClientHandshakeContext(options: {
  transcriptHash: Buffer
  server: AuthenticatedServerIdentity
  deviceFingerprint: string
  devicePublicKey: Buffer
  devicePrivateKey: KeyObject
}): EstablishedClientHandshakeContext {
  const transcriptHash = Buffer.from(options.transcriptHash)
  const devicePublicKey = Buffer.from(options.devicePublicKey)

  const instance: EstablishedClientHandshakeContext = Object.freeze({
    role: 'client' as const,
    get transcriptHash(): Buffer {
      return Buffer.from(transcriptHash)
    },
    server: options.server,
    deviceFingerprint: options.deviceFingerprint,
    get devicePublicKey(): Buffer {
      return Buffer.from(devicePublicKey)
    },
    devicePrivateKey: options.devicePrivateKey
  })

  authenticatedClientContexts.add(instance)
  return instance
}

export function isEstablishedClientHandshakeContext(
  value: unknown
): value is EstablishedClientHandshakeContext {
  return (
    typeof value === 'object' &&
    value !== null &&
    authenticatedClientContexts.has(value)
  )
}

export function createEstablishedServerHandshakeContext(options: {
  transcriptHash: Buffer
  candidate: AuthenticatedCandidateDevice
  serverId: string
  serverPublicKey: Buffer
  serverPrivateKey: KeyObject
}): EstablishedServerHandshakeContext {
  const transcriptHash = Buffer.from(options.transcriptHash)
  const serverPublicKey = Buffer.from(options.serverPublicKey)

  const instance: EstablishedServerHandshakeContext = Object.freeze({
    role: 'server' as const,
    get transcriptHash(): Buffer {
      return Buffer.from(transcriptHash)
    },
    candidate: options.candidate,
    serverId: options.serverId,
    get serverPublicKey(): Buffer {
      return Buffer.from(serverPublicKey)
    },
    serverPrivateKey: options.serverPrivateKey
  })

  authenticatedServerContexts.add(instance)
  return instance
}

export function isEstablishedServerHandshakeContext(
  value: unknown
): value is EstablishedServerHandshakeContext {
  return (
    typeof value === 'object' &&
    value !== null &&
    authenticatedServerContexts.has(value)
  )
}
