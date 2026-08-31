import { app, safeStorage } from 'electron'

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

export function initializeLocalServers(deviceIdentity: DeviceIdentity): void {
  if (storage) {
    throw new Error('O storage local de servidores já foi inicializado.')
  }

  storage = createLocalServerStorage(app.getPath('userData'), safeStorage, deviceIdentity)
}

export async function createLocalServer(displayName: string): Promise<LocalServer> {
  return getStorage().createLocalServer(displayName)
}

export async function loadLocalServer(localStorageId: string): Promise<LocalServer> {
  return getStorage().loadLocalServer(localStorageId)
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
