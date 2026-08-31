import type { BrowserWindowConstructorOptions } from 'electron'

export function createMainWindowOptions(): BrowserWindowConstructorOptions {
  return {
    width: 1000,
    height: 700,
    minWidth: 640,
    minHeight: 480,
    show: false,
    backgroundColor: '#111827',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true
    }
  }
}
