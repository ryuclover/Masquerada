import { contextBridge, ipcRenderer } from 'electron'

export interface DesktopSource {
  id: string
  name: string
  thumbnail: string
  appIcon?: string | null
}

export interface MasqueradaApi {
  listServers(): Promise<readonly { localStorageId: string; serverId: string; displayName: string }[]>
  createServer(displayName: string): Promise<{ localStorageId: string; serverId: string; displayName: string }>
  listChannels(localStorageId: string): Promise<readonly { channelId: string; name: string; archived: boolean; type?: 'text' | 'voice' }[]>
  createChannel(localStorageId: string, name: string, type?: 'text' | 'voice'): Promise<{ channelId: string; name: string; archived: boolean; type?: 'text' | 'voice' }>
  listMessages(localStorageId: string, channelId: string): Promise<readonly unknown[]>
  sendMessage(localStorageId: string, channelId: string, content: string): Promise<unknown>
  listMembers(localStorageId: string): Promise<readonly unknown[]>
  listInvites(localStorageId: string): Promise<readonly unknown[]>
  createInvite(localStorageId: string, maxUses: number): Promise<{ encoded: string }>
  getDesktopSources?(options?: { types?: ('window' | 'screen')[]; thumbnailSize?: { width: number; height: number } }): Promise<readonly DesktopSource[]>
}

const api: MasqueradaApi = {
  listServers: () => ipcRenderer.invoke('server:list'),
  createServer: (displayName) => ipcRenderer.invoke('server:create', displayName),
  listChannels: (localStorageId) => ipcRenderer.invoke('channel:list', localStorageId),
  createChannel: (localStorageId, name, type) => ipcRenderer.invoke('channel:create', localStorageId, name, type),
  listMessages: (localStorageId, channelId) => ipcRenderer.invoke('message:list', localStorageId, channelId),
  sendMessage: (localStorageId, channelId, content) => ipcRenderer.invoke('message:send', localStorageId, channelId, content),
  listMembers: (localStorageId) => ipcRenderer.invoke('member:list', localStorageId),
  listInvites: (localStorageId) => ipcRenderer.invoke('invite:list', localStorageId),
  createInvite: (localStorageId, maxUses) => ipcRenderer.invoke('invite:create', localStorageId, maxUses),
  getDesktopSources: (options) => ipcRenderer.invoke('desktop:sources', options)
}

contextBridge.exposeInMainWorld('masquerada', api)

