import { contextBridge, ipcRenderer } from 'electron'

export interface MasqueradaApi {
  createServer(displayName: string): Promise<{ localStorageId: string; serverId: string; displayName: string }>
  listChannels(localStorageId: string): Promise<readonly { channelId: string; name: string; archived: boolean }[]>
  createChannel(localStorageId: string, name: string): Promise<{ channelId: string; name: string; archived: boolean }>
  listMessages(localStorageId: string, channelId: string): Promise<readonly unknown[]>
  sendMessage(localStorageId: string, channelId: string, content: string): Promise<unknown>
}

const api: MasqueradaApi = {
  createServer: (displayName) => ipcRenderer.invoke('server:create', displayName),
  listChannels: (localStorageId) => ipcRenderer.invoke('channel:list', localStorageId),
  createChannel: (localStorageId, name) => ipcRenderer.invoke('channel:create', localStorageId, name),
  listMessages: (localStorageId, channelId) => ipcRenderer.invoke('message:list', localStorageId, channelId),
  sendMessage: (localStorageId, channelId, content) => ipcRenderer.invoke('message:send', localStorageId, channelId, content)
}

contextBridge.exposeInMainWorld('masquerada', api)
