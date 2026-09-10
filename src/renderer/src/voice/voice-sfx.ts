/**
 * voice-sfx.ts
 * Sintetizador procedural de efeitos sonoros com Web Audio API.
 * 100% puro TypeScript, zero dependência de arquivos externos,
 * zero latência e total conformidade com a política CSP estrita.
 */

class VoiceSoundEffects {
  private ctx: AudioContext | null = null
  private ringInterval: ReturnType<typeof setInterval> | null = null
  private isMutedSound = false

  private getAudioContext(): AudioContext | null {
    if (typeof window === 'undefined') return null
    try {
      if (!this.ctx) {
        const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext
        if (AudioCtx) {
          this.ctx = new AudioCtx()
        }
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        void this.ctx.resume().catch(() => {})
      }
      return this.ctx
    } catch {
      return null
    }
  }

  /**
   * Som de entrada na chamada (dois tons harmônicos ascendentes estilo Discord)
   */
  playJoinSound(): void {
    if (this.isMutedSound) return
    const ctx = this.getAudioContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime

      // Nota 1: C5 (523.25 Hz)
      const osc1 = ctx.createOscillator()
      const gain1 = ctx.createGain()
      osc1.type = 'sine'
      osc1.frequency.setValueAtTime(523.25, now)
      gain1.gain.setValueAtTime(0.001, now)
      gain1.gain.exponentialRampToValueAtTime(0.18, now + 0.04)
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.16)
      osc1.connect(gain1)
      gain1.connect(ctx.destination)
      osc1.start(now)
      osc1.stop(now + 0.18)

      // Nota 2: G5 (783.99 Hz)
      const osc2 = ctx.createOscillator()
      const gain2 = ctx.createGain()
      osc2.type = 'sine'
      osc2.frequency.setValueAtTime(783.99, now + 0.14)
      gain2.gain.setValueAtTime(0.001, now + 0.14)
      gain2.gain.exponentialRampToValueAtTime(0.22, now + 0.18)
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.42)
      osc2.connect(gain2)
      gain2.connect(ctx.destination)
      osc2.start(now + 0.14)
      osc2.stop(now + 0.45)
    } catch {
      // Ignora silenciosamente se o navegador bloquear autoplay
    }
  }

  /**
   * Som de saída da chamada (dois tons harmônicos descendentes)
   */
  playLeaveSound(): void {
    if (this.isMutedSound) return
    const ctx = this.getAudioContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime

      // Nota 1: G5 (783.99 Hz)
      const osc1 = ctx.createOscillator()
      const gain1 = ctx.createGain()
      osc1.type = 'sine'
      osc1.frequency.setValueAtTime(783.99, now)
      gain1.gain.setValueAtTime(0.001, now)
      gain1.gain.exponentialRampToValueAtTime(0.18, now + 0.04)
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.16)
      osc1.connect(gain1)
      gain1.connect(ctx.destination)
      osc1.start(now)
      osc1.stop(now + 0.18)

      // Nota 2: D5 (587.33 Hz)
      const osc2 = ctx.createOscillator()
      const gain2 = ctx.createGain()
      osc2.type = 'sine'
      osc2.frequency.setValueAtTime(587.33, now + 0.13)
      gain2.gain.setValueAtTime(0.001, now + 0.13)
      gain2.gain.exponentialRampToValueAtTime(0.16, now + 0.17)
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.38)
      osc2.connect(gain2)
      gain2.connect(ctx.destination)
      osc2.start(now + 0.13)
      osc2.stop(now + 0.40)
    } catch {
      // Ignora silenciosamente
    }
  }

  /**
   * Som de microfone mutado (tom grave sutil)
   */
  playMuteSound(): void {
    if (this.isMutedSound) return
    const ctx = this.getAudioContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'triangle'
      osc.frequency.setValueAtTime(320, now)
      osc.frequency.exponentialRampToValueAtTime(220, now + 0.08)
      gain.gain.setValueAtTime(0.12, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.10)
      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.start(now)
      osc.stop(now + 0.11)
    } catch {
      // Ignora silenciosamente
    }
  }

  /**
   * Som de microfone desmutado (tom agudo sutil)
   */
  playUnmuteSound(): void {
    if (this.isMutedSound) return
    const ctx = this.getAudioContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'triangle'
      osc.frequency.setValueAtTime(360, now)
      osc.frequency.exponentialRampToValueAtTime(540, now + 0.08)
      gain.gain.setValueAtTime(0.12, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.10)
      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.start(now)
      osc.stop(now + 0.11)
    } catch {
      // Ignora silenciosamente
    }
  }

  /**
   * Inicia o ringtone de chamada pulsante
   */
  startRinging(): void {
    this.stopRinging()
    const playPulse = (): void => {
      const ctx = this.getAudioContext()
      if (!ctx) return
      try {
        const now = ctx.currentTime
        const osc1 = ctx.createOscillator()
        const osc2 = ctx.createOscillator()
        const gain = ctx.createGain()

        osc1.type = 'sine'
        osc1.frequency.setValueAtTime(440, now) // A4
        osc2.type = 'sine'
        osc2.frequency.setValueAtTime(480, now) // Dual-tone telefônico suave

        gain.gain.setValueAtTime(0.001, now)
        gain.gain.exponentialRampToValueAtTime(0.12, now + 0.1)
        gain.gain.setValueAtTime(0.12, now + 0.8)
        gain.gain.exponentialRampToValueAtTime(0.001, now + 1.1)

        osc1.connect(gain)
        osc2.connect(gain)
        gain.connect(ctx.destination)

        osc1.start(now)
        osc2.start(now)
        osc1.stop(now + 1.15)
        osc2.stop(now + 1.15)
      } catch {
        // Ignora silenciosamente
      }
    }

    playPulse()
    this.ringInterval = setInterval(playPulse, 2800)
  }

  /**
   * Para o ringtone de chamada
   */
  stopRinging(): void {
    if (this.ringInterval) {
      clearInterval(this.ringInterval)
      this.ringInterval = null
    }
  }
}

export const voiceSfx = new VoiceSoundEffects()
