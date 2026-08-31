import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import App from './App'

describe('App', () => {
  it('exibe a confirmação de inicialização', () => {
    const html = renderToStaticMarkup(<App />)

    expect(html).toContain('P2P Server')
    expect(html).toContain('Aplicação iniciada com sucesso.')
  })
})

