import { app, BrowserWindow, safeStorage } from 'electron'
import { join } from 'node:path'

import {
  DeviceIdentityError,
  loadOrCreateDeviceIdentity
} from './security/device-identity'
import { initializeLocalServers } from './servers/local-servers'
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
