import { describe, expect, it } from 'vitest'

import { createMainWindowOptions } from './window-options'

describe('configuração de segurança da janela principal', () => {
  const webPreferences = createMainWindowOptions().webPreferences

  it('desabilita a integração com Node.js', () => {
    expect(webPreferences?.nodeIntegration).toBe(false)
  })

  it('isola o contexto do renderer', () => {
    expect(webPreferences?.contextIsolation).toBe(true)
  })

  it('executa o renderer no sandbox', () => {
    expect(webPreferences?.sandbox).toBe(true)
  })

  it('mantém as proteções web habilitadas', () => {
    expect(webPreferences?.webSecurity).toBe(true)
  })
})
