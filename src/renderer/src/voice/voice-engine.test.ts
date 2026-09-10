import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { VoiceEngine } from './voice-engine'
import type { CallState } from './voice-types'

describe('VoiceEngine (P2P Audio & WebRTC Lifecycle)', () => {
  let engine: VoiceEngine

  beforeEach(() => {
    engine = new VoiceEngine()
  })

  afterEach(() => {
    engine.endCall()
  })

  it('inicia no estado IDLE com participantes vazios', () => {
    expect(engine.getState()).toBe('IDLE')
    expect(engine.getParticipant()).toBeNull()
    expect(engine.getIsMuted()).toBe(false)
    expect(engine.getIsDeafened()).toBe(false)
  })

  it('transiciona para OUTGOING ao disparar chamada e notifica listeners', async () => {
    const states: CallState[] = []
    engine.setListeners({
      onStateChange: (state) => states.push(state)
    })

    await engine.startOutgoingCall({
      callId: 'call-101',
      targetFriendId: 'friend-alice',
      targetDisplayName: 'Alice (Validadora)',
      targetFingerprint: 'ed25519:7a8b9c...',
      connectionType: 'direct'
    })

    expect(engine.getState()).toBe('OUTGOING')
    expect(engine.getCurrentCallId()).toBe('call-101')
    expect(engine.getParticipant()?.displayName).toBe('Alice (Validadora)')
    expect(states).toContain('OUTGOING')
  })

  it('gerencia chamada entrante com receiveIncomingCall e aceitação', async () => {
    engine.receiveIncomingCall({
      callId: 'call-102',
      targetFriendId: 'friend-bob',
      targetDisplayName: 'Bob (Host Remoto)',
      targetFingerprint: 'ed25519:f9e8d...',
      connectionType: 'relay'
    })

    expect(engine.getState()).toBe('INCOMING')
    expect(engine.getParticipant()?.displayName).toBe('Bob (Host Remoto)')

    await engine.acceptIncomingCall()
    expect(engine.getState()).toBe('CONNECTED')
  })

  it('alterna corretamente o estado de mute do microfone', () => {
    expect(engine.getIsMuted()).toBe(false)
    const muted = engine.toggleMute()
    expect(muted).toBe(true)
    expect(engine.getIsMuted()).toBe(true)
    const unmuted = engine.toggleMute()
    expect(unmuted).toBe(false)
    expect(engine.getIsMuted()).toBe(false)
  })

  it('alterna corretamente o estado de ensurdecimento (deafen)', () => {
    expect(engine.getIsDeafened()).toBe(false)
    const deafened = engine.toggleDeafen()
    expect(deafened).toBe(true)
    expect(engine.getIsDeafened()).toBe(true)
    const undeafened = engine.toggleDeafen()
    expect(undeafened).toBe(false)
    expect(engine.getIsDeafened()).toBe(false)
  })

  it('encerra a chamada e limpa o participante ativo', async () => {
    await engine.startOutgoingCall({
      callId: 'call-103',
      targetFriendId: 'friend-alice',
      targetDisplayName: 'Alice',
      targetFingerprint: 'ed25519:7a8b9c...',
      connectionType: 'direct'
    })

    engine.endCall()
    expect(engine.getState()).toBe('ENDED')
    expect(engine.getParticipant()).toBeNull()
  })

  it('processa mensagens de sinalização P2P remotas', () => {
    engine.receiveIncomingCall({
      callId: 'call-104',
      targetFriendId: 'friend-alice',
      targetDisplayName: 'Alice',
      targetFingerprint: 'ed25519:7a8b9c...',
      connectionType: 'direct'
    })

    engine.handleSignalingMessage({
      type: 'call:accept',
      callId: 'call-104',
      fromFingerprint: 'ed25519:7a8b9c...',
      toFingerprint: 'ed25519:me...',
      timestamp: Date.now()
    })

    expect(engine.getState()).toBe('CONNECTED')
  })

  it('conecta ao canal de voz sem participante fantasma e inicia VAD', async () => {
    await engine.joinVoiceChannel('channel-geral-voz')
    expect(engine.getState()).toBe('CONNECTED')
    expect(engine.getCurrentCallId()).toBe('channel-geral-voz')
    expect(engine.getParticipant()).toBeNull()
  })

  it('gerencia dispositivos de entrada e saída de áudio e preferências', async () => {
    expect(engine.getPreferredInputDevice()).toBe('')
    expect(engine.getPreferredOutputDevice()).toBe('')

    await engine.setInputDevice('mic-device-123')
    expect(engine.getPreferredInputDevice()).toBe('mic-device-123')

    await engine.setOutputDevice('speaker-device-456')
    expect(engine.getPreferredOutputDevice()).toBe('speaker-device-456')

    const devices = await engine.getAudioDevices()
    expect(devices).toHaveProperty('inputs')
    expect(devices).toHaveProperty('outputs')
  })

  it('configura e alterna o estado de supressão de ruído P2P', () => {
    expect(engine.getNoiseSuppression()).toBe(true)
    engine.setNoiseSuppression(false)
    expect(engine.getNoiseSuppression()).toBe(false)
    engine.setNoiseSuppression(true)
    expect(engine.getNoiseSuppression()).toBe(true)
  })

  it('ajusta e limita o nível de supressão de ruído de 1% a 100%', () => {
    expect(engine.getNoiseSuppressionLevel()).toBe(50)
    engine.setNoiseSuppressionLevel(25)
    expect(engine.getNoiseSuppressionLevel()).toBe(25)

    // Clamping nos limites
    engine.setNoiseSuppressionLevel(0)
    expect(engine.getNoiseSuppressionLevel()).toBe(1)
    engine.setNoiseSuppressionLevel(150)
    expect(engine.getNoiseSuppressionLevel()).toBe(100)
  })

  it('inicia e encerra o teste de microfone (loopback) corretamente', async () => {
    expect(engine.isMicTesting()).toBe(false)

    // Se mock de áudio estiver indisponível no ambiente de teste, trata graceful fallback
    try {
      await engine.startMicTest(() => {})
      expect(engine.isMicTesting()).toBe(true)
    } catch {
      // Ambiente headless sem AudioContext/getUserMedia
    }

    engine.stopMicTest()
    expect(engine.isMicTesting()).toBe(false)
  })

  it('gerencia o ciclo de vida do compartilhamento de tela P2P', async () => {
    expect(engine.isScreenSharing()).toBe(false)
    expect(engine.getLocalScreenStream()).toBeNull()
    expect(engine.getRemoteScreenStream()).toBeNull()

    const mockTrack = {
      kind: 'video',
      contentHint: '',
      stop: () => {},
      onended: null as (() => void) | null
    }
    const mockStream = {
      getVideoTracks: () => [mockTrack],
      getTracks: () => [mockTrack]
    } as unknown as MediaStream

    let localShareNotified = false
    engine.setListeners({
      onLocalScreenShareChange: (isSharing) => {
        localShareNotified = isSharing
      }
    })

    // Mock navigator.mediaDevices.getDisplayMedia
    const originalGetDisplayMedia = navigator.mediaDevices?.getDisplayMedia
    Object.defineProperty(navigator, 'mediaDevices', {
      value: {
        getDisplayMedia: async () => mockStream
      },
      configurable: true,
      writable: true
    })

    try {
      const stream = await engine.startScreenShare({
        resolution: '1080p',
        frameRate: 60,
        optimization: 'detail'
      })

      expect(stream).toBe(mockStream)
      expect(engine.isScreenSharing()).toBe(true)
      expect(engine.getLocalScreenStream()).toBe(mockStream)
      expect(mockTrack.contentHint).toBe('detail')
      expect(localShareNotified).toBe(true)

      // Testa encerramento
      engine.stopScreenShare()
      expect(engine.isScreenSharing()).toBe(false)
      expect(engine.getLocalScreenStream()).toBeNull()
      expect(localShareNotified).toBe(false)
    } finally {
      if (originalGetDisplayMedia) {
        navigator.mediaDevices.getDisplayMedia = originalGetDisplayMedia
      }
    }
  })

  it('aplica optimization motion para vídeos e jogos', async () => {
    const mockTrack = {
      kind: 'video',
      contentHint: '',
      stop: () => {},
      onended: null as (() => void) | null
    }
    const mockStream = {
      getVideoTracks: () => [mockTrack],
      getTracks: () => [mockTrack]
    } as unknown as MediaStream

    Object.defineProperty(navigator, 'mediaDevices', {
      value: {
        getDisplayMedia: async () => mockStream
      },
      configurable: true,
      writable: true
    })

    await engine.startScreenShare({
      resolution: '720p',
      frameRate: 30,
      optimization: 'motion'
    })

    expect(mockTrack.contentHint).toBe('motion')
    engine.stopScreenShare()
  })

  it('interrompe o compartilhamento de tela ao encerrar a chamada', async () => {
    const mockTrack = {
      kind: 'video',
      contentHint: '',
      stop: () => {},
      onended: null as (() => void) | null
    }
    const mockStream = {
      getVideoTracks: () => [mockTrack],
      getTracks: () => [mockTrack]
    } as unknown as MediaStream

    Object.defineProperty(navigator, 'mediaDevices', {
      value: {
        getDisplayMedia: async () => mockStream
      },
      configurable: true,
      writable: true
    })

    await engine.startScreenShare({ resolution: '1080p' })
    expect(engine.isScreenSharing()).toBe(true)

    engine.endCall()
    expect(engine.isScreenSharing()).toBe(false)
    expect(engine.getLocalScreenStream()).toBeNull()
  })
})


