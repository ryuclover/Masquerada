import { app, safeStorage } from 'electron'
import { randomUUID } from 'node:crypto'

import type { DeviceIdentity } from '../security/device-identity'
import {
  createLocalServerStorage,
  type LocalServer
} from './local-server-storage'

import type {
  AuthenticatedCandidateDevice,
  Member,
  StoredInvite
} from './server-database'
import type { CreateServerInviteOptions, ServerInvite } from './server-invite'

let storage: ReturnType<typeof createLocalServerStorage> | undefined
let deviceFingerprint: string | undefined

export function initializeLocalServers(deviceIdentity: DeviceIdentity): void {
  if (storage) {
    throw new Error('O storage local de servidores já foi inicializado.')
  }

  storage = createLocalServerStorage(app.getPath('userData'), safeStorage, deviceIdentity)
  deviceFingerprint = deviceIdentity.fingerprint
}

export async function createLocalServer(displayName: string): Promise<LocalServer> {
  return getStorage().createLocalServer(displayName)
}

export async function loadLocalServer(localStorageId: string): Promise<LocalServer> {
  return getStorage().loadLocalServer(localStorageId)
}

export async function listLocalServers() {
  return getStorage().listLocalServers()
}

export async function listLocalServerChannels(localStorageId: string) {
  return getStorage().listLocalServerChannels(localStorageId)
}

export async function listLocalServerMembers(localStorageId: string) {
  return getStorage().listLocalServerMembers(localStorageId)
}

export async function listLocalServerInvites(localStorageId: string) {
  return getStorage().listLocalServerInvites(localStorageId)
}

export async function createInvite(localStorageId: string, maxUses: number) {
  return getStorage().createLocalServerInvite(localStorageId, {
    expiresAt: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
    maxUses
  })
}

export async function createLocalServerChannel(localStorageId: string, name: string) {
  return getStorage().createLocalServerChannel(localStorageId, {
    name,
    actorFingerprint: getDeviceFingerprint()
  })
}

export async function listLocalServerMessages(localStorageId: string, channelId: string) {
  return getStorage().listLocalServerMessages(localStorageId, { channelId, limit: 100 })
}

export async function sendLocalServerMessage(localStorageId: string, channelId: string, content: string) {
  return getStorage().createLocalServerMessage(localStorageId, {
    channelId,
    content,
    clientMessageId: randomUUID().replaceAll('-', ''),
    actorFingerprint: getDeviceFingerprint()
  })
}

function getDeviceFingerprint(): string {
  if (!deviceFingerprint) throw new Error('A identidade do dispositivo não foi inicializada.')
  return deviceFingerprint
}

export async function createLocalServerInvite(
  localStorageId: string,
  options: CreateServerInviteOptions
): Promise<{ invite: ServerInvite; encoded: string }> {
  return getStorage().createLocalServerInvite(localStorageId, options)
}

export async function consumeLocalServerInvite(
  localStorageId: string,
  inviteOrEncoded: ServerInvite | string,
  options: { nowSeconds?: number } = {}
): Promise<void> {
  return getStorage().consumeLocalServerInvite(localStorageId, inviteOrEncoded, options)
}

export async function revokeLocalServerInvite(
  localStorageId: string,
  inviteId: string
): Promise<void> {
  return getStorage().revokeLocalServerInvite(localStorageId, inviteId)
}

export async function getStoredInvite(
  localStorageId: string,
  inviteId: string,
  nowSeconds?: number
): Promise<StoredInvite | undefined> {
  return getStorage().getStoredInvite(localStorageId, inviteId, nowSeconds)
}

export async function admitLocalServerMemberWithInvite(
  localStorageId: string,
  inviteOrEncoded: ServerInvite | string,
  candidateDevice: AuthenticatedCandidateDevice,
  options: { nowSeconds?: number } = {}
): Promise<Member> {
  return getStorage().admitLocalServerMemberWithInvite(localStorageId, inviteOrEncoded, candidateDevice, options)
}

function getStorage(): ReturnType<typeof createLocalServerStorage> {
  if (!storage) {
    throw new Error('O storage local de servidores não foi inicializado.')
  }

  return storage
}
