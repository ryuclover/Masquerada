import { describe, it, expect } from 'vitest'
import { voiceSfx } from './voice-sfx'

describe('voiceSfx (Web Audio API Synthesizer)', () => {
  it('executa playJoinSound sem lançar exceções mesmo sem AudioContext nativo no ambiente de teste', () => {
    expect(() => {
      voiceSfx.playJoinSound()
    }).not.toThrow()
  })

  it('executa playLeaveSound sem erros', () => {
    expect(() => {
      voiceSfx.playLeaveSound()
    }).not.toThrow()
  })

  it('executa playMuteSound e playUnmuteSound com sucesso', () => {
    expect(() => {
      voiceSfx.playMuteSound()
      voiceSfx.playUnmuteSound()
    }).not.toThrow()
  })

  it('inicia e interrompe o ringtone de chamada de forma idempotente', () => {
    expect(() => {
      voiceSfx.startRinging()
      voiceSfx.startRinging() // Segunda chamada não gera vazamento de intervalos
      voiceSfx.stopRinging()
      voiceSfx.stopRinging()
    }).not.toThrow()
  })
})
