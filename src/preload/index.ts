import { contextBridge, ipcRenderer } from 'electron'

export interface MasqueradaApi {
  listServers(): Promise<readonly { localStorageId: string; serverId: string; displayName: string }[]>
  createServer(displayName: string): Promise<{ localStorageId: string; serverId: string; displayName: string }>
  listChannels(localStorageId: string): Promise<readonly { channelId: string; name: string; archived: boolean }[]>
  createChannel(localStorageId: string, name: string): Promise<{ channelId: string; name: string; archived: boolean }>
  listMessages(localStorageId: string, channelId: string): Promise<readonly unknown[]>
  sendMessage(localStorageId: string, channelId: string, content: string): Promise<unknown>
  listMembers(localStorageId: string): Promise<readonly unknown[]>
  listInvites(localStorageId: string): Promise<readonly unknown[]>
  createInvite(localStorageId: string, maxUses: number): Promise<{ encoded: string }>
}

const api: MasqueradaApi = {
  listServers: () => ipcRenderer.invoke('server:list'),
  createServer: (displayName) => ipcRenderer.invoke('server:create', displayName),
  listChannels: (localStorageId) => ipcRenderer.invoke('channel:list', localStorageId),
  createChannel: (localStorageId, name) => ipcRenderer.invoke('channel:create', localStorageId, name),
  listMessages: (localStorageId, channelId) => ipcRenderer.invoke('message:list', localStorageId, channelId),
  sendMessage: (localStorageId, channelId, content) => ipcRenderer.invoke('message:send', localStorageId, channelId, content)
  ,listMembers: (localStorageId) => ipcRenderer.invoke('member:list', localStorageId)
  ,listInvites: (localStorageId) => ipcRenderer.invoke('invite:list', localStorageId)
  ,createInvite: (localStorageId, maxUses) => ipcRenderer.invoke('invite:create', localStorageId, maxUses)
}

contextBridge.exposeInMainWorld('masquerada', api)
