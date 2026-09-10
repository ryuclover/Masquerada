import React from 'react'
import type { CallParticipant, CallState } from '../voice/voice-types'

interface VoiceBarProps {
  callState: CallState
  participant: CallParticipant | null
  isMuted: boolean
  isDeafened: boolean
  isLocalSpeaking: boolean
  isScreenSharing?: boolean
  channelName?: string
  pingMs?: number
  onToggleMute: () => void
  onToggleDeafen: () => void
  onToggleScreenShare?: () => void
  onDisconnect: () => void
  onOpenStage: () => void
}

function IconScreenShare({ active }: { active: boolean }): React.JSX.Element {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
      {active && <circle cx="12" cy="10" r="3" fill="currentColor" />}
    </svg>
  )
}

function IconMic({ muted }: { muted: boolean }): React.JSX.Element {
  if (muted) {
    return (
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="1" y1="1" x2="23" y2="23" />
        <path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6" />
        <path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23" />
        <line x1="12" y1="19" x2="12" y2="23" />
        <line x1="8" y1="23" x2="16" y2="23" />
      </svg>
    )
  }
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
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
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="1" y1="1" x2="23" y2="23" />
        <path d="M3 14h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a9 9 0 0 1 15.36-6.36" />
        <path d="M21 14h-3a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-7a9 9 0 0 0-2.64-6.36" />
      </svg>
    )
  }
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 18v-6a9 9 0 0 1 18 0v6" />
      <path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z" />
    </svg>
  )
}

function IconPhoneOff(): React.JSX.Element {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.68 13.31a16 16 0 0 0 3.41 2.6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7 2 2 0 0 1 1.72 2v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.42 19.42 0 0 1-6-6 19.8 19.8 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91" />
      <line x1="23" y1="1" x2="1" y2="23" />
    </svg>
  )
}

function IconMaximize(): React.JSX.Element {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="15 3 21 3 21 9" />
      <polyline points="9 21 3 21 3 15" />
      <line x1="21" y1="3" x2="14" y2="10" />
      <line x1="3" y1="21" x2="10" y2="14" />
    </svg>
  )
}

export function VoiceBar({
  callState,
  participant,
  isMuted,
  isDeafened,
  isLocalSpeaking,
  isScreenSharing = false,
  channelName,
  pingMs = 16,
  onToggleMute,
  onToggleDeafen,
  onToggleScreenShare,
  onDisconnect,
  onOpenStage
}: VoiceBarProps): React.JSX.Element | null {
  if (callState === 'IDLE' || callState === 'ENDED') {
    return null
  }

  const isOutgoing = callState === 'OUTGOING'
  const isConnecting = callState === 'CONNECTING'

  let statusText = 'Voz Conectada'
  let statusSub = `RTC P2P Direto (Opus 48kHz) · ${pingMs}ms`
  let dotClass = 'online'

  if (isOutgoing) {
    statusText = 'Chamando...'
    statusSub = 'Aguardando resposta do par'
    dotClass = 'calling'
  } else if (isConnecting) {
    statusText = 'Conectando...'
    statusSub = 'Negociando SDP & ICE P2P'
    dotClass = 'connecting'
  }

  return (
    <div className="voice-bar">
      <div className="voice-bar-info" onClick={onOpenStage} role="button" tabIndex={0} title="Abrir Palco de Voz">
        <div className="voice-bar-title-row">
          <span className={`voice-status-dot ${dotClass}`} />
          <span className="voice-status-title">{statusText}</span>
          <button className="voice-btn-expand" onClick={(e) => { e.stopPropagation(); onOpenStage(); }} title="Expandir Palco">
            <IconMaximize />
          </button>
        </div>
        <div className="voice-bar-details">
          <span className="voice-bar-friend">
            {channelName ? `🔊 ${channelName}` : `@${participant?.displayName ?? 'Amigo'}`}
          </span>
          <span className="voice-bar-sub">{statusSub}</span>
        </div>
      </div>

      <div className="voice-bar-controls">
        <button
          className={`voice-action-btn ${isMuted ? 'active-mute' : ''} ${isLocalSpeaking && !isMuted ? 'speaking' : ''}`}
          onClick={onToggleMute}
          title={isMuted ? 'Desmutar Microfone' : 'Mutar Microfone'}
          aria-label={isMuted ? 'Desmutar Microfone' : 'Mutar Microfone'}
        >
          <IconMic muted={isMuted} />
        </button>

        <button
          className={`voice-action-btn ${isDeafened ? 'active-mute' : ''}`}
          onClick={onToggleDeafen}
          title={isDeafened ? 'Desativar Silenciamento' : 'Silenciar Áudio'}
          aria-label={isDeafened ? 'Desativar Silenciamento' : 'Silenciar Áudio'}
        >
          <IconHeadphones deafened={isDeafened} />
        </button>

        {onToggleScreenShare && (
          <button
            className={`voice-action-btn ${isScreenSharing ? 'active-share' : ''}`}
            onClick={onToggleScreenShare}
            title={isScreenSharing ? 'Parar Compartilhamento de Tela' : 'Compartilhar Tela'}
            aria-label={isScreenSharing ? 'Parar Compartilhamento de Tela' : 'Compartilhar Tela'}
          >
            <IconScreenShare active={isScreenSharing} />
          </button>
        )}

        <button
          className="voice-action-btn hangup"
          onClick={onDisconnect}
          title="Desconectar Chamada"
          aria-label="Desconectar Chamada"
        >
          <IconPhoneOff />
        </button>
      </div>
    </div>
  )
}
