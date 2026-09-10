import { app, BrowserWindow, ipcMain, safeStorage } from 'electron'
import { join } from 'node:path'

import {
  DeviceIdentityError,
  loadOrCreateDeviceIdentity
} from './security/device-identity'
import { initializeLocalServers } from './servers/local-servers'
import {
  createLocalServer,
  createLocalServerChannel,
  listLocalServerChannels,
  listLocalServerMessages,
  listLocalServers,
  listLocalServerMembers,
  listLocalServerInvites,
  createInvite,
  sendLocalServerMessage
} from './servers/local-servers'
import { createMainWindowOptions } from './window-options'

function createWindow(): void {
  const window = new BrowserWindow(createMainWindowOptions())

  window.once('ready-to-show', () => {
    window.show()
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    void window.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    void window.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

function registerIpc(): void {
  ipcMain.handle('server:list', async () => {
    const servers = await listLocalServers()
    return servers.map((server: { localStorageId: string; serverId: string; displayName: string }) => ({ localStorageId: server.localStorageId, serverId: server.serverId, displayName: server.displayName }))
  })
  ipcMain.handle('server:create', async (_event, displayName: unknown) => {
    if (typeof displayName !== 'string' || displayName.length === 0 || displayName.length > 100) {
      throw new Error('INVALID_SERVER_NAME')
    }
    const server = await createLocalServer(displayName)
    return { localStorageId: server.localStorageId, serverId: server.serverId, displayName: server.displayName }
  })
  ipcMain.handle('channel:list', async (_event, storageId: unknown) => {
    if (typeof storageId !== 'string') throw new Error('INVALID_STORAGE_ID')
    return listLocalServerChannels(storageId)
  })
  ipcMain.handle('channel:create', async (_event, storageId: unknown, name: unknown) => {
    if (typeof storageId !== 'string' || typeof name !== 'string') throw new Error('INVALID_ARGUMENT')
    return createLocalServerChannel(storageId, name)
  })
  ipcMain.handle('message:list', async (_event, storageId: unknown, channelId: unknown) => {
    if (typeof storageId !== 'string' || typeof channelId !== 'string') throw new Error('INVALID_ARGUMENT')
    return listLocalServerMessages(storageId, channelId)
  })
  ipcMain.handle('message:send', async (_event, storageId: unknown, channelId: unknown, content: unknown) => {
    if (typeof storageId !== 'string' || typeof channelId !== 'string' || typeof content !== 'string') {
      throw new Error('INVALID_ARGUMENT')
    }
    return sendLocalServerMessage(storageId, channelId, content)
  })
  ipcMain.handle('member:list', async (_event, storageId: unknown) => {
    if (typeof storageId !== 'string') throw new Error('INVALID_STORAGE_ID')
    return listLocalServerMembers(storageId)
  })
  ipcMain.handle('invite:list', async (_event, storageId: unknown) => {
    if (typeof storageId !== 'string') throw new Error('INVALID_STORAGE_ID')
    return listLocalServerInvites(storageId)
  })
  ipcMain.handle('invite:create', async (_event, storageId: unknown, maxUses: unknown) => {
    if (typeof storageId !== 'string' || typeof maxUses !== 'number' || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 100) {
      throw new Error('INVALID_ARGUMENT')
    }
    return createInvite(storageId, maxUses)
  })
}

const hasSingleInstanceLock = app.requestSingleInstanceLock()

if (!hasSingleInstanceLock) {
  app.quit()
} else {
  app.whenReady().then(async () => {
    const deviceIdentity = await loadOrCreateDeviceIdentity(
      join(app.getPath('userData'), 'identity'),
      safeStorage
    )
    initializeLocalServers(deviceIdentity)
    registerIpc()
    createWindow()

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow()
      }
    })
  }).catch((error: unknown) => {
    const errorCode =
      error instanceof DeviceIdentityError ? error.code : 'IDENTITY_INITIALIZATION_FAILED'
    console.error(`Falha ao inicializar a identidade do dispositivo (${errorCode}).`)
    app.quit()
  })

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
      app.quit()
    }
  })
}
