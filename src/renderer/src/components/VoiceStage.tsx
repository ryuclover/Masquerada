import React, { useEffect, useRef } from 'react'
import type { CallParticipant, CallState } from '../voice/voice-types'

interface VoiceStageProps {
  callState: CallState
  participant: CallParticipant | null
  isMuted: boolean
  isDeafened: boolean
  isLocalSpeaking: boolean
  isRemoteSpeaking: boolean
  isScreenSharing: boolean
  screenStream: MediaStream | null
  channelName?: string
  localDisplayName?: string
  localAvatarColor?: string
  onToggleMute: () => void
  onToggleDeafen: () => void
  onDisconnect: () => void
  onMinimize: () => void
  onStartScreenShare: () => void
  onStopScreenShare: () => void
}

function IconMic({ muted }: { muted: boolean }): React.JSX.Element {
  if (muted) {
    return (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="1" y1="1" x2="23" y2="23" />
        <path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6" />
        <path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23" />
        <line x1="12" y1="19" x2="12" y2="23" />
        <line x1="8" y1="23" x2="16" y2="23" />
      </svg>
    )
  }
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z" />
      <path d="M19 10v2a7 7 0 0 1-14 0v-2" />
      <line x1="12" y1="19" x2="12" y2="23" />
      <line x1="8" y1="23" x2="16" y2="23" />
    </svg>
  )
}

function IconHeadphones({ deafened }: { deafened: boolean }): React.JSX.Element {
  if (deafened) {
    return (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="1" y1="1" x2="23" y2="23" />
        <path d="M3 14h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a9 9 0 0 1 15.36-6.36" />
        <path d="M21 14h-3a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-7a9 9 0 0 0-2.64-6.36" />
      </svg>
    )
  }
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 18v-6a9 9 0 0 1 18 0v6" />
      <path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z" />
    </svg>
  )
}

function IconScreenShare({ active }: { active: boolean }): React.JSX.Element {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
      {active && <circle cx="12" cy="10" r="3" fill="currentColor" />}
    </svg>
  )
}

function IconPhoneOff(): React.JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.68 13.31a16 16 0 0 0 3.41 2.6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7 2 2 0 0 1 1.72 2v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.42 19.42 0 0 1-6-6 19.8 19.8 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91" />
      <line x1="23" y1="1" x2="1" y2="23" />
    </svg>
  )
}

function IconMinimize(): React.JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 14 10 14 10 20" />
      <polyline points="20 10 14 10 14 4" />
      <line x1="14" y1="10" x2="21" y2="3" />
      <line x1="3" y1="21" x2="10" y2="14" />
    </svg>
  )
}

function IconFullscreen(): React.JSX.Element {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3" />
    </svg>
  )
}

function IconPip(): React.JSX.Element {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <rect x="12" y="11" width="8" height="7" rx="1" fill="currentColor" fillOpacity="0.3" stroke="currentColor" />
    </svg>
  )
}

export function VoiceStage({
  callState,
  participant,
  isMuted,
  isDeafened,
  isLocalSpeaking,
  isRemoteSpeaking,
  isScreenSharing,
  screenStream,
  channelName,
  localDisplayName,
  localAvatarColor,
  onToggleMute,
  onToggleDeafen,
  onDisconnect,
  onMinimize,
  onStartScreenShare,
  onStopScreenShare
}: VoiceStageProps): React.JSX.Element {
  const isOutgoing = callState === 'OUTGOING'
  const isConnecting = callState === 'CONNECTING'
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const videoContainerRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (videoRef.current && screenStream) {
      videoRef.current.srcObject = screenStream
    }
  }, [screenStream])

  let callStatusBadge = '● RTC P2P Conectado (Opus 48kHz)'
  if (isOutgoing) {
    callStatusBadge = '● Chamando @' + (participant?.displayName ?? 'Amigo') + '...'
  } else if (isConnecting) {
    callStatusBadge = '● Negociando Criptografia P2P...'
  } else if (channelName && !participant) {
    callStatusBadge = `● Conectado a #${channelName} (Opus 48kHz)`
  }

  const stageTitle = channelName ? `🔊 ${channelName}` : 'Palco de Voz P2P'

  const handleToggleFullscreen = (): void => {
    if (!videoContainerRef.current) return
    if (!document.fullscreenElement) {
      void videoContainerRef.current.requestFullscreen().catch(() => {})
    } else {
      void document.exitFullscreen().catch(() => {})
    }
  }

  const handleTogglePip = async (): Promise<void> => {
    if (!videoRef.current) return
    try {
      if (document.pictureInPictureElement) {
        await document.exitPictureInPicture()
      } else if (videoRef.current.requestPictureInPicture) {
        await videoRef.current.requestPictureInPicture()
      }
    } catch (err) {
      console.warn('Picture-in-picture não suportado ou negado:', err)
    }
  }

  return (
    <div className={`voice-stage ${screenStream ? 'has-screen-share' : ''}`}>
      <header className="voice-stage-header">
        <div className="voice-stage-title-group">
          <h2>{stageTitle}</h2>
          <span className="voice-stage-status-badge">{callStatusBadge}</span>
          {screenStream && (
            <span className="voice-stage-live-tag">
              <span className="live-dot" /> AO VIVO
            </span>
          )}
        </div>
        <button className="voice-btn-minimize" onClick={onMinimize} title="Minimizar Palco e Ver Chat">
          <IconMinimize />
          <span>Ver Chat</span>
        </button>
      </header>

      {/* Se houver compartilhamento de tela ativo, exibe o Cinema Stage */}
      {screenStream ? (
        <div className="voice-stage-cinema-layout">
          <div className="screen-share-video-container" ref={videoContainerRef}>
            <video
              ref={videoRef}
              autoPlay
              playsInline
              muted
              className="screen-share-video-element"
            />
            <div className="screen-share-overlay-controls">
              <div className="screen-share-presenter-badge">
                <span className="live-pill">AO VIVO</span>
                <span>{isScreenSharing ? `${localDisplayName ?? 'Você'} (Sua Transmissão)` : `${participant?.displayName ?? 'Amigo'} (Apresentando)`}</span>
              </div>
              <div className="screen-share-action-buttons">
                <button
                  type="button"
                  className="screen-overlay-btn"
                  onClick={handleTogglePip}
                  title="Picture-in-Picture"
                >
                  <IconPip />
                </button>
                <button
                  type="button"
                  className="screen-overlay-btn"
                  onClick={handleToggleFullscreen}
                  title="Tela Cheia"
                >
                  <IconFullscreen />
                </button>
                {isScreenSharing && (
                  <button
                    type="button"
                    className="screen-overlay-btn stop-btn"
                    onClick={onStopScreenShare}
                    title="Parar de Compartilhar Tela"
                  >
                    Parar Transmissão
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Mini-grid de participantes durante o compartilhamento */}
          <div className="voice-stage-cinema-strip">
            <div className={`participant-card mini ${isLocalSpeaking && !isMuted ? 'speaking' : ''}`}>
              <div className="participant-avatar-wrapper">
                <div
                  className={`participant-avatar mini local ${isLocalSpeaking && !isMuted ? 'speaking-ring' : ''} avatar-color-${localAvatarColor ?? 'blurple'}`}
                >
                  {localDisplayName ? localDisplayName.slice(0, 1).toUpperCase() : 'V'}
                </div>
                {isMuted && <span className="participant-mute-badge mini" title="Você está mutado">🔇</span>}
              </div>
              <span className="participant-mini-name">{localDisplayName ?? 'Você'}</span>
            </div>

            {participant && (
              <div className={`participant-card mini ${isRemoteSpeaking ? 'speaking' : ''}`}>
                <div className="participant-avatar-wrapper">
                  <div className={`participant-avatar mini remote ${isRemoteSpeaking ? 'speaking-ring' : ''}`}>
                    {participant.displayName.slice(0, 1).toUpperCase()}
                  </div>
                  {participant.isMuted && <span className="participant-mute-badge mini" title="Amigo mutado">🔇</span>}
                </div>
                <span className="participant-mini-name">{participant.displayName}</span>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="voice-stage-grid">
          {/* Card: Você */}
          <div className={`participant-card ${isLocalSpeaking && !isMuted ? 'speaking' : ''}`}>
            <div className="participant-avatar-wrapper">
              <div
                className={`participant-avatar local ${isLocalSpeaking && !isMuted ? 'speaking-ring' : ''} avatar-color-${localAvatarColor ?? 'blurple'}`}
              >
                {localDisplayName ? localDisplayName.slice(0, 1).toUpperCase() : 'V'}
              </div>
              {isMuted && <span className="participant-mute-badge" title="Você está mutado">🔇</span>}
            </div>
            <div className="participant-info">
              <h3>{localDisplayName ?? 'Você'}</h3>
              <span className="participant-sub">
                {isMuted ? 'Microfone Mutado' : isLocalSpeaking ? 'Falando...' : 'Microfone Ativo'}
              </span>
            </div>
          </div>

          {/* Card: Participante Remoto REAL */}
          {participant ? (
            <div className={`participant-card ${isRemoteSpeaking ? 'speaking' : ''}`}>
              <div className="participant-avatar-wrapper">
                <div className={`participant-avatar remote ${isRemoteSpeaking ? 'speaking-ring' : ''}`}>
                  {participant.displayName.slice(0, 1).toUpperCase()}
                </div>
                {isOutgoing && <div className="calling-radar-pulse" />}
                {participant.isMuted && (
                  <span className="participant-mute-badge" title="Amigo está mutado">
                    🔇
                  </span>
                )}
              </div>
              <div className="participant-info">
                <h3>{participant.displayName}</h3>
                <span className="participant-sub">
                  {isOutgoing
                    ? 'Tocando chamada...'
                    : isConnecting
                    ? 'Conectando...'
                    : isRemoteSpeaking
                    ? 'Falando...'
                    : 'Conectado'}
                </span>
                <span className="participant-fp">{participant.deviceFingerprint}</span>
              </div>
            </div>
          ) : (
            <div className="voice-empty-room-card">
              <div className="voice-empty-room-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                  <circle cx="9" cy="7" r="4" />
                  <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                  <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                </svg>
              </div>
              <h4>Você está sozinho na sala</h4>
              <p>Aguardando outros membros entrarem no canal de voz. Sua transmissão permanece ativa.</p>
            </div>
          )}
        </div>
      )}

      {/* Dock Inferior Centralizado de Controles Estilo Discord */}
      <div className="voice-stage-dock">
        <button
          className={`dock-btn ${isMuted ? 'active-mute' : ''}`}
          onClick={onToggleMute}
          title={isMuted ? 'Desmutar Microfone' : 'Mutar Microfone'}
        >
          <IconMic muted={isMuted} />
          <span>{isMuted ? 'Desmutar' : 'Mutar'}</span>
        </button>

        <button
          className={`dock-btn ${isDeafened ? 'active-mute' : ''}`}
          onClick={onToggleDeafen}
          title={isDeafened ? 'Desativar Silenciamento' : 'Silenciar Fone'}
        >
          <IconHeadphones deafened={isDeafened} />
          <span>{isDeafened ? 'Ouvir' : 'Silenciar'}</span>
        </button>

        {/* Botão de Compartilhar Tela */}
        <button
          className={`dock-btn ${isScreenSharing ? 'active-share' : ''}`}
          onClick={isScreenSharing ? onStopScreenShare : onStartScreenShare}
          title={isScreenSharing ? 'Parar de Compartilhar Tela' : 'Compartilhar sua Tela'}
        >
          <IconScreenShare active={isScreenSharing} />
          <span>{isScreenSharing ? 'Parar Tela' : 'Tela'}</span>
        </button>

        <button
          className="dock-btn hangup"
          onClick={onDisconnect}
          title="Desconectar da Chamada"
        >
          <IconPhoneOff />
          <span>Desconectar</span>
        </button>
      </div>
    </div>
  )
}
