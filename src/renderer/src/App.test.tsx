import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import App from './App'

describe('App', () => {
  it('exibe o onboarding local-first', () => {
    const html = renderToStaticMarkup(<App />)

    expect(html).toContain('Masquerada')
    expect(html).toContain('Criar servidor')
    expect(html).toContain('Converse sem abrir mão do controle.')
  })
})

