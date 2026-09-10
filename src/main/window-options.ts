import { join } from 'node:path'
import type { BrowserWindowConstructorOptions } from 'electron'

export function createMainWindowOptions(): BrowserWindowConstructorOptions {
  return {
    width: 1200,
    height: 780,
    minWidth: 800,
    minHeight: 520,
    show: false,
    frame: false,
    titleBarStyle: 'hidden',
    autoHideMenuBar: true,
    backgroundColor: '#0d0b12',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      preload: join(__dirname, '../preload/index.js')
    }
  }
}
