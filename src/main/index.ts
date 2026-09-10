import { app, BrowserWindow, desktopCapturer, dialog, ipcMain, Menu, safeStorage } from 'electron'
import { appendFileSync } from 'node:fs'
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

let mainWindow: BrowserWindow | null = null

function logStartup(msg: string): void {
  try {
    const logPath = join(app.getPath('temp'), 'masquerada-startup.log')
    appendFileSync(logPath, `[${new Date().toISOString()}] ${msg}\n`, 'utf-8')
  } catch {}
}

function createWindow(): BrowserWindow {
  const window = new BrowserWindow(createMainWindowOptions())
  mainWindow = window
  window.setMenuBarVisibility(false)

  window.on('maximize', () => {
    window.webContents.send('window:maximize-changed', true)
  })
  window.on('unmaximize', () => {
    window.webContents.send('window:maximize-changed', false)
  })

  window.once('ready-to-show', () => {
    window.show()
  })

  window.on('closed', () => {
    mainWindow = null
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    void window.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    void window.loadFile(join(__dirname, '../renderer/index.html'))
  }

  return window
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
    try {
      await createLocalServerChannel(server.localStorageId, 'geral')
      await createLocalServerChannel(server.localStorageId, 'voz-geral')
    } catch {
      // Ignora caso canais iniciais já existam
    }
    return { localStorageId: server.localStorageId, serverId: server.serverId, displayName: server.displayName }
  })
  ipcMain.handle('channel:list', async (_event, storageId: unknown) => {
    if (typeof storageId !== 'string') throw new Error('INVALID_STORAGE_ID')
    const channels = await listLocalServerChannels(storageId)
    return channels.map((channel: { channelId: string; name: string; createdAt: number; createdBy: string; archived: boolean }) => ({
      channelId: channel.channelId,
      name: channel.name,
      createdAt: channel.createdAt,
      createdBy: channel.createdBy,
      archived: channel.archived,
      type: channel.name.startsWith('voz-') ? ('voice' as const) : ('text' as const)
    }))
  })
  ipcMain.handle('channel:create', async (_event, storageId: unknown, name: unknown, type?: unknown) => {
    if (typeof storageId !== 'string' || typeof name !== 'string') throw new Error('INVALID_ARGUMENT')
    const finalName = type === 'voice' && !name.startsWith('voz-') ? `voz-${name}` : name
    const created = await createLocalServerChannel(storageId, finalName)
    return {
      channelId: created.channelId,
      name: created.name,
      createdAt: created.createdAt,
      createdBy: created.createdBy,
      archived: created.archived,
      type: (type === 'voice' || created.name.startsWith('voz-')) ? ('voice' as const) : ('text' as const)
    }
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
  ipcMain.handle('desktop:sources', async (_event, options?: { types?: ('window' | 'screen')[]; thumbnailSize?: { width: number; height: number } }) => {
    const types = options?.types || ['screen', 'window']
    const thumbnailSize = options?.thumbnailSize || { width: 320, height: 180 }
    const sources = await desktopCapturer.getSources({
      types,
      thumbnailSize,
      fetchWindowIcons: true
    })
    return sources.map((s) => ({
      id: s.id,
      name: s.name,
      thumbnail: s.thumbnail.toDataURL(),
      appIcon: s.appIcon ? s.appIcon.toDataURL() : null
    }))
  })
  ipcMain.handle('window:minimize', () => {
    if (mainWindow) mainWindow.minimize()
  })
  ipcMain.handle('window:toggle-maximize', () => {
    if (!mainWindow) return false
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize()
      return false
    } else {
      mainWindow.maximize()
      return true
    }
  })
  ipcMain.handle('window:is-maximized', () => {
    return mainWindow ? mainWindow.isMaximized() : false
  })
  ipcMain.handle('window:close', () => {
    if (mainWindow) mainWindow.close()
  })
}

logStartup(`Inicializando processo Masquerada (PID: ${process.pid}, exec: ${process.execPath})`)

const hasSingleInstanceLock = app.requestSingleInstanceLock()

if (!hasSingleInstanceLock) {
  logStartup(`Outra instância já está em execução. Encerrando instância redundante (PID: ${process.pid}).`)
  app.quit()
} else {
  app.on('second-instance', () => {
    logStartup(`Segunda instância detectada. Focando janela principal existente.`)
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })

  app.whenReady().then(async () => {
    Menu.setApplicationMenu(null)
    logStartup(`App ready recebido. Carregando identidade em: ${join(app.getPath('userData'), 'identity')}`)
    const deviceIdentity = await loadOrCreateDeviceIdentity(
      join(app.getPath('userData'), 'identity'),
      safeStorage
    )
    logStartup(`Identidade carregada com sucesso. Inicializando servidores locais...`)
    initializeLocalServers(deviceIdentity)
    registerIpc()
    createWindow()
    logStartup(`Janela principal criada com sucesso.`)

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow()
      }
    })
  }).catch((error: unknown) => {
    const errorCode =
      error instanceof DeviceIdentityError ? error.code : 'IDENTITY_INITIALIZATION_FAILED'
    const errorMsg = error instanceof Error ? error.stack || error.message : String(error)
    logStartup(`ERRO FATAL ao inicializar (${errorCode}): ${errorMsg}`)
    console.error(`Falha ao inicializar a identidade do dispositivo (${errorCode}).`, error)
    dialog.showErrorBox(
      'Erro ao Iniciar o Masquerada',
      `Ocorreu um erro ao inicializar os dados locais do aplicativo:\n\n${errorCode}\n\nDetalhes:\n${errorMsg}`
    )
    app.quit()
  })

  app.on('window-all-closed', () => {
    logStartup(`Todas as janelas foram fechadas. Encerrando app.`)
    if (process.platform !== 'darwin') {
      app.quit()
    }
  })
}
