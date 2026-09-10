/**
 * Definições de tipos e interfaces para o subsistema de Voz P2P do Masquerada.
 */

export type CallState =
  | 'IDLE'        // Sem chamada ativa
  | 'OUTGOING'    // Chamando amigo (tocando toque de discagem)
  | 'INCOMING'    // Recebendo chamada de amigo (tocando ringtone)
  | 'CONNECTING'  // Negociando SDP e candidatos ICE via P2P
  | 'CONNECTED'   // Chamada de voz conectada (áudio bidirecional fluindo)
  | 'ENDED'       // Chamada finalizada

export interface CallParticipant {
  readonly id: string
  readonly displayName: string
  readonly deviceFingerprint: string
  readonly isLocal: boolean
  readonly isMuted: boolean
  readonly isDeafened: boolean
  readonly isSpeaking: boolean
  readonly connectionType: 'direct' | 'relay' | 'lan'
  readonly pingMs?: number
}

export type VoiceSignalType =
  | 'call:invite'
  | 'call:accept'
  | 'call:reject'
  | 'call:ice-candidate'
  | 'call:state-sync'
  | 'call:screen-share-start'
  | 'call:screen-share-stop'
  | 'call:end'

export type ScreenShareResolution = '720p' | '1080p' | 'source'
export type ScreenShareFps = 15 | 30 | 60
export type ScreenShareOptimization = 'detail' | 'motion'

export interface ScreenShareOptions {
  resolution?: ScreenShareResolution
  frameRate?: ScreenShareFps
  optimization?: ScreenShareOptimization
  sourceId?: string
  withAudio?: boolean
}

export interface VoiceSignalMessage {
  readonly type: VoiceSignalType
  readonly callId: string
  readonly fromFingerprint: string
  readonly toFingerprint: string
  readonly sdp?: string
  readonly candidate?: RTCIceCandidateInit
  readonly isMuted?: boolean
  readonly isDeafened?: boolean
  readonly isScreenSharing?: boolean
  readonly reason?: string
  readonly timestamp: number
}

export interface VoiceEngineEvents {
  onStateChange: (state: CallState, error?: string) => void
  onLocalSpeaking: (isSpeaking: boolean) => void
  onRemoteSpeaking: (isSpeaking: boolean) => void
  onParticipantUpdate: (participant: CallParticipant) => void
  onStatsUpdate: (stats: { pingMs: number; packetsLost: number; bitrateKbps: number }) => void
  onLocalScreenShareChange?: (isSharing: boolean, stream: MediaStream | null) => void
  onRemoteScreenShareChange?: (isSharing: boolean, stream: MediaStream | null) => void
}
