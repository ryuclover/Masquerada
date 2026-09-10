import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { VoiceBar } from './components/VoiceBar'
import { VoiceStage } from './components/VoiceStage'
import { ScreenShareModal } from './components/ScreenShareModal'
import { IncomingCallModal } from './components/IncomingCallModal'
import { voiceEngine } from './voice/voice-engine'
import type { CallParticipant, CallState, ScreenShareOptions } from './voice/voice-types'

export interface Friend {
  friendId: string
  displayName: string
  deviceFingerprint: string
  connectionType: 'direct' | 'relay' | 'lan'
  status: 'online' | 'idle' | 'offline'
  customStatus?: string
}

export interface DirectMessage {
  sequence: number
  author: string
  content: string
  time: string
}

export type ProfileBannerColor = 'blurple' | 'gold' | 'emerald' | 'crimson' | 'cyan' | 'midnight'
export type ProfileAvatarColor = 'blurple' | 'gold' | 'emerald' | 'crimson' | 'cyan' | 'purple'
export type UserPresenceStatus = 'online' | 'idle' | 'dnd' | 'offline'

export interface UserProfile {
  displayName: string
  username: string
  customStatus: string
  status: UserPresenceStatus
  bio: string
  bannerColor: ProfileBannerColor
  avatarColor: ProfileAvatarColor
}

declare global {
  interface Window {
    masquerada?: {
      createServer(name: string): Promise<{ localStorageId: string; serverId: string; displayName: string }>
      listServers(): Promise<readonly { localStorageId: string; serverId: string; displayName: string }[]>
      listChannels(id: string): Promise<readonly { channelId: string; name: string; archived: boolean; type?: 'text' | 'voice' }[]>
      createChannel(id: string, name: string, type?: 'text' | 'voice'): Promise<{ channelId: string; name: string; archived: boolean; type?: 'text' | 'voice' }>
      listMessages(id: string, channelId: string): Promise<readonly { sequence: number; content: string; deletedAt: number | null }[]>
      sendMessage(id: string, channelId: string, content: string): Promise<unknown>
      listMembers(id: string): Promise<readonly { deviceFingerprint: string }[]>
      listInvites(id: string): Promise<readonly { inviteId: string; status: string; uses: number; maxUses: number }[]>
      createInvite(id: string, maxUses: number): Promise<{ encoded: string }>
      listFriends?(): Promise<readonly Friend[]>
      addFriend?(target: string): Promise<Friend>
      listDirectMessages?(friendId: string): Promise<readonly DirectMessage[]>
      sendDirectMessage?(friendId: string, content: string): Promise<unknown>
      getDesktopSources?(options?: { types?: ('window' | 'screen')[]; thumbnailSize?: { width: number; height: number } }): Promise<readonly { id: string; name: string; thumbnail: string; appIcon?: string | null }[]>
    }
  }
}

/* --------------------------------------------------------------------------
   ÍCONES VETORIAIS SVG (Limpos e compatíveis com CSP estrita)
   -------------------------------------------------------------------------- */
function IconHash(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="4" y1="9" x2="20" y2="9" />
      <line x1="4" y1="15" x2="20" y2="15" />
      <line x1="10" y1="3" x2="8" y2="21" />
      <line x1="16" y1="3" x2="14" y2="21" />
    </svg>
  )
}

function IconPlus(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  )
}

function IconSend(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  )
}

function IconUsers(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  )
}

function IconMessage(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  )
}

function IconKey(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 2l-2 2m-1.5 1.5L14 9l-3-3 2-2 3.5 3.5M9 15l3 3-5 5H3v-4l6-6z" />
      <circle cx="7.5" cy="7.5" r="3.5" />
    </svg>
  )
}

function IconCopy(): React.JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  )
}

function IconCheck(): React.JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}

function IconClose(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  )
}

function IconMasqueradaLogo(): React.JSX.Element {
  return (
    <svg width="28" height="28" viewBox="0 0 48 48" fill="none" className="rail-mask-svg" aria-hidden="true">
      <defs>
        <linearGradient id="masqGrad" x1="4" y1="4" x2="44" y2="44" gradientUnits="userSpaceOnUse">
          <stop stopColor="#FDE68A" />
          <stop offset="0.45" stopColor="#F59E0B" />
          <stop offset="1" stopColor="#B45309" />
        </linearGradient>
        <linearGradient id="masqEye" x1="10" y1="18" x2="38" y2="30" gradientUnits="userSpaceOnUse">
          <stop stopColor="#090810" />
          <stop offset="1" stopColor="#1e1833" />
        </linearGradient>
        <filter id="masqGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="rgba(0,0,0,0.6)" />
        </filter>
      </defs>
      {/* Máscara Teatral Veneziana Principal */}
      <path
        d="M24 6C15 6 6 12 4 19C2 26 5 33 11 38C17 43 22 45 24 45C26 45 31 43 37 38C43 33 46 26 44 19C42 12 33 6 24 6Z"
        fill="url(#masqGrad)"
        filter="url(#masqGlow)"
      />
      {/* Detalhe Superior da Coroa de Carnaval */}
      <path
        d="M24 6L21 12H27L24 6ZM14 9L13 14H18L17 9H14ZM34 9L31 9L30 14H35L34 9Z"
        fill="#FEF3C7"
        opacity="0.9"
      />
      {/* Olho Esquerdo Enigmático */}
      <path
        d="M10.5 22C13.5 19.5 17.5 19.5 19.5 23.5C17.5 26.5 13.5 26.5 10.5 24.5C9.2 23.5 9.2 22.8 10.5 22Z"
        fill="url(#masqEye)"
      />
      {/* Olho Direito Enigmático */}
      <path
        d="M37.5 22C34.5 19.5 30.5 19.5 28.5 23.5C30.5 26.5 34.5 26.5 37.5 24.5C38.8 23.5 38.8 22.8 37.5 22Z"
        fill="url(#masqEye)"
      />
      {/* Ponte Nasal Veneziana */}
      <path
        d="M24 20V32M22 32H26"
        stroke="#78350F"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      {/* Arabescos e Filigranas Douradas nas Bochechas */}
      <path
        d="M8 29C10 33 14 36 18 36M40 29C38 33 34 36 30 36"
        stroke="#FEF3C7"
        strokeWidth="1.6"
        strokeLinecap="round"
        opacity="0.85"
      />
    </svg>
  )
}

function formatChannelDisplayName(name: string, type?: 'text' | 'voice'): string {
  if (type === 'voice' || name.startsWith('voz-')) {
    const clean = name.replace(/^voz-/, '').replace(/[-_]+/g, ' ')
    return clean.replace(/\b\w/g, (char) => char.toUpperCase())
  }
  return name
}

function IconSparkles(): React.JSX.Element {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3v3m0 12v3m9-9h-3M6 12H3m15.364-6.364l-2.121 2.121M7.757 16.243l-2.121 2.121m12.728 0l-2.121-2.121M7.757 7.757L5.636 5.636" />
    </svg>
  )
}

function IconChevronDown(): React.JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  )
}

function IconSettings(): React.JSX.Element {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  )
}

function IconPhone(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7 2 2 0 0 1 1.72 2z" />
    </svg>
  )
}

function IconSpeaker(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
      <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07" />
    </svg>
  )
}

function IconUserPlus(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="8.5" cy="7" r="4" />
      <line x1="20" y1="8" x2="20" y2="14" />
      <line x1="23" y1="11" x2="17" y2="11" />
    </svg>
  )
}

function IconShield(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function IconLogOut(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  )
}

function IconChevronUp(): React.JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="18 15 12 9 6 15" />
    </svg>
  )
}

function IconDiamond(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 3h12l4 6-10 12L2 9z" />
      <path d="M11 3v18" />
    </svg>
  )
}

function IconBell(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  )
}

function IconId(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="M7 15h3M7 9h4M14 9h3M14 12h3" />
    </svg>
  )
}

function IconPalette(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="13.5" cy="6.5" r=".5" fill="currentColor" />
      <circle cx="17.5" cy="10.5" r=".5" fill="currentColor" />
      <circle cx="8.5" cy="7.5" r=".5" fill="currentColor" />
      <circle cx="6.5" cy="12.5" r=".5" fill="currentColor" />
      <path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z" />
    </svg>
  )
}

function IconPencil(): React.JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" />
    </svg>
  )
}

function IconMic(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z" />
      <path d="M19 10v2a7 7 0 0 1-14 0v-2" />
      <line x1="12" y1="19" x2="12" y2="23" />
      <line x1="8" y1="23" x2="16" y2="23" />
    </svg>
  )
}

function IconHeadphones(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 18v-6a9 9 0 0 1 18 0v6" />
      <path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z" />
    </svg>
  )
}

function IconActivity(): React.JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  )
}


/* --------------------------------------------------------------------------
   COMPONENTE PRINCIPAL
   -------------------------------------------------------------------------- */
export default function App(): React.JSX.Element {
  // Navegação: 'server' (canais do servidor) | 'friends' (tela de amigos) | 'dm' (chat direto com amigo)
  const [currentView, setCurrentView] = useState<'server' | 'friends' | 'dm'>('server')
  const [server, setServer] = useState<{ localStorageId: string; displayName: string } | undefined>()
  const [servers, setServers] = useState<readonly { localStorageId: string; displayName: string }[]>([])
  const [channels, setChannels] = useState<readonly { channelId: string; name: string; archived: boolean; type?: 'text' | 'voice' }[]>([])
  const [selectedChannel, setSelectedChannel] = useState<string>()
  const [messages, setMessages] = useState<readonly { sequence: number; content: string; deletedAt: number | null }[]>([])
  const [draft, setDraft] = useState('')

  // Estado da Tela de Amigos
  const [friendsTab, setFriendsTab] = useState<'online' | 'all' | 'pending' | 'add'>('online')
  const [friends, setFriends] = useState<readonly Friend[]>([])
  const [activeDmFriendId, setActiveDmFriendId] = useState<string>()
  const [directMessages, setDirectMessages] = useState<readonly DirectMessage[]>([])
  const [friendsSearch, setFriendsSearch] = useState('')
  const [newFriendInput, setNewFriendInput] = useState('')
  const [addFriendFeedback, setAddFriendFeedback] = useState<string>()

  // Estado da Chamada de Voz P2P (Estilo Discord)
  const [callState, setCallState] = useState<CallState>('IDLE')
  const [callParticipant, setCallParticipant] = useState<CallParticipant | null>(null)
  const [isMuted, setIsMuted] = useState(false)
  const [isDeafened, setIsDeafened] = useState(false)
  const [isLocalSpeaking, setIsLocalSpeaking] = useState(false)
  const [isRemoteSpeaking, setIsRemoteSpeaking] = useState(false)
  const [isVoiceStageExpanded, setIsVoiceStageExpanded] = useState(false)
  const [voicePingMs, setVoicePingMs] = useState(14)
  const [activeVoiceChannelId, setActiveVoiceChannelId] = useState<string | null>(null)
  const outgoingCallTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Modais e formulários
  const [serverName, setServerName] = useState('Meu Servidor')
  const [channelName, setChannelName] = useState('')
  const [channelType, setChannelType] = useState<'text' | 'voice'>('text')
  const [showChannelModal, setShowChannelModal] = useState(false)
  const [showServerModal, setShowServerModal] = useState(false)
  const [showServerDropdown, setShowServerDropdown] = useState(false)
  const [showServerSettingsModal, setShowServerSettingsModal] = useState(false)
  const [showServerSecurityModal, setShowServerSecurityModal] = useState(false)
  const [copiedServerId, setCopiedServerId] = useState(false)
  const [serverNotifyMuted, setServerNotifyMuted] = useState(false)
  const [members, setMembers] = useState<readonly { deviceFingerprint: string }[]>([])
  const [invites, setInvites] = useState<readonly { inviteId: string; status: string; uses: number; maxUses: number }[]>([])
  const [inviteCode, setInviteCode] = useState('')
  const [copiedInvite, setCopiedInvite] = useState(false)
  const [copiedFingerprint, setCopiedFingerprint] = useState(false)
  const [panel, setPanel] = useState<'members' | 'invites' | null>('members')
  const [busy, setBusy] = useState(false)
  const [loadingMessages, setLoadingMessages] = useState(false)
  const [error, setError] = useState<string>()

  // Perfil do Usuário (Estilo Discord) com persistência LocalStorage
  const [userProfile, setUserProfile] = useState<UserProfile>(() => {
    if (typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem('masquerada_user_profile')
        if (saved) {
          const parsed = JSON.parse(saved) as Partial<UserProfile>
          return {
            displayName: parsed.displayName?.trim() || 'Você',
            username: parsed.username?.trim() || 'masquerada.host',
            customStatus: parsed.customStatus ?? 'Conectado à rede P2P',
            status: parsed.status || 'online',
            bio:
              parsed.bio ||
              'Operando nó de comunicação descentralizada Masquerada. Criptografia ponta a ponta ativa.',
            bannerColor: (parsed.bannerColor as ProfileBannerColor) || 'blurple',
            avatarColor: (parsed.avatarColor as ProfileAvatarColor) || 'blurple'
          }
        }
      } catch {
        /* storage indisponível */
      }
    }
    return {
      displayName: 'Você',
      username: 'masquerada.host',
      customStatus: 'Conectado à rede P2P',
      status: 'online',
      bio: 'Operando nó de comunicação descentralizada Masquerada. Criptografia ponta a ponta ativa.',
      bannerColor: 'blurple',
      avatarColor: 'blurple'
    }
  })
  const [editProfile, setEditProfile] = useState<UserProfile>(userProfile)
  const [showProfileModal, setShowProfileModal] = useState(false)
  const [profileSavedFeedback, setProfileSavedFeedback] = useState(false)
  const [userSettingsTab, setUserSettingsTab] = useState<'profile' | 'audio'>('profile')

  // Dispositivos e preferências de áudio do usuário
  const [audioInputs, setAudioInputs] = useState<MediaDeviceInfo[]>([])
  const [audioOutputs, setAudioOutputs] = useState<MediaDeviceInfo[]>([])
  const [selectedInputId, setSelectedInputId] = useState<string>(() => {
    return (typeof window !== 'undefined' && localStorage.getItem('masquerada_audio_input')) || ''
  })
  const [selectedOutputId, setSelectedOutputId] = useState<string>(() => {
    return (typeof window !== 'undefined' && localStorage.getItem('masquerada_audio_output')) || ''
  })
  const [noiseSuppressionEnabled, setNoiseSuppressionEnabled] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('masquerada_noise_suppression')
      if (saved !== null) return saved === 'true'
    }
    return true
  })
  const [noiseSuppressionLevel, setNoiseSuppressionLevel] = useState<number>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('masquerada_noise_suppression_level')
      if (saved) return Math.max(1, Math.min(100, Number(saved)))
    }
    return 50
  })
  const [inputVolume, setInputVolume] = useState<number>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('masquerada_input_volume')
      if (saved) return Number(saved)
    }
    return 100
  })
  const [outputVolume, setOutputVolume] = useState<number>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('masquerada_output_volume')
      if (saved) return Number(saved)
    }
    return 100
  })

  // Teste de microfone local ("Ouvir o Microfone")
  const [isMicTesting, setIsMicTesting] = useState(false)
  const [micTestLevel, setMicTestLevel] = useState(0)
  const [micGateOpen, setMicGateOpen] = useState(false)

  // Compartilhamento de tela P2P
  const [isScreenShareModalOpen, setIsScreenShareModalOpen] = useState(false)
  const [isScreenSharing, setIsScreenSharing] = useState(false)
  const [localScreenStream, setLocalScreenStream] = useState<MediaStream | null>(null)
  const [remoteScreenStream, setRemoteScreenStream] = useState<MediaStream | null>(null)

  const handleStartScreenShare = async (options: ScreenShareOptions): Promise<void> => {
    await voiceEngine.startScreenShare(options)
    setIsVoiceStageExpanded(true)
  }

  const handleStopScreenShare = (): void => {
    voiceEngine.stopScreenShare()
  }

  const handleToggleScreenShare = (): void => {
    if (isScreenSharing) {
      voiceEngine.stopScreenShare()
    } else {
      setIsScreenShareModalOpen(true)
    }
  }

  const api = typeof window === 'undefined' ? undefined : window.masquerada

  // Assinar eventos do motor de voz P2P
  useEffect(() => {
    voiceEngine.setListeners({
      onStateChange: (newState) => {
        setCallState(newState)
        if (newState === 'CONNECTED') {
          setIsVoiceStageExpanded(true)
        } else if (newState === 'ENDED') {
          setIsVoiceStageExpanded(false)
        }
      },
      onLocalSpeaking: setIsLocalSpeaking,
      onRemoteSpeaking: setIsRemoteSpeaking,
      onParticipantUpdate: setCallParticipant,
      onStatsUpdate: (stats) => setVoicePingMs(stats.pingMs),
      onLocalScreenShareChange: (isSharing, stream) => {
        setIsScreenSharing(isSharing)
        setLocalScreenStream(stream)
      },
      onRemoteScreenShareChange: (_isSharing, stream) => {
        setRemoteScreenStream(stream)
      }
    })
  }, [])

  // Carregar lista de servidores
  useEffect(() => {
    if (!api) return
    void api.listServers().then((items) => {
      setServers(items)
      if (!server && items[0]) setServer(items[0])
    }).catch(() => setError('Não foi possível abrir os servidores locais.'))
  }, [api, server])

  // Carregar canais, membros e convites do servidor atual
  useEffect(() => {
    if (!server || !api) return
    void api.listChannels(server.localStorageId).then((items) => {
      const typed = items.map((c) => ({
        ...c,
        type: (c.type ?? (c.name.startsWith('voz-') ? 'voice' : 'text')) as 'text' | 'voice'
      }))
      setChannels(typed)
      setSelectedChannel((prev) => {
        if (prev && typed.some((ch) => ch.channelId === prev)) return prev
        const firstText = typed.find((ch) => ch.type === 'text')
        return firstText?.channelId ?? typed[0]?.channelId
      })
    }).catch(() => setError('Não foi possível carregar os canais.'))
    void api.listMembers(server.localStorageId).then(setMembers).catch(() => setError('Não foi possível carregar os membros.'))
    void api.listInvites(server.localStorageId).then(setInvites).catch(() => setError('Não foi possível carregar os convites.'))
  }, [api, server?.localStorageId])

  // Carregar amigos
  useEffect(() => {
    if (!api?.listFriends) return
    void api.listFriends().then(setFriends).catch(() => {})
  }, [api])

  // Carregar mensagens do canal selecionado (Isolamento garantido por channelId)
  useEffect(() => {
    if (!server || !selectedChannel || !api) return
    setLoadingMessages(true)
    void api.listMessages(server.localStorageId, selectedChannel)
      .then((msgs) => {
        setMessages(msgs)
      })
      .catch(() => setError('Não foi possível carregar o histórico.'))
      .finally(() => setLoadingMessages(false))
  }, [api, selectedChannel, server])

  // Carregar mensagens da DM ativa
  useEffect(() => {
    if (!activeDmFriendId || !api?.listDirectMessages) return
    setLoadingMessages(true)
    void api.listDirectMessages(activeDmFriendId)
      .then(setDirectMessages)
      .catch(() => {})
      .finally(() => setLoadingMessages(false))
  }, [api, activeDmFriendId])

  // Iniciar chamada de voz P2P com amigo
  const handleStartCall = useCallback((targetFriend: Friend) => {
    if (outgoingCallTimerRef.current) {
      clearTimeout(outgoingCallTimerRef.current)
    }

    const callId = `call-${Date.now()}`
    setCallParticipant({
      id: targetFriend.friendId,
      displayName: targetFriend.displayName,
      deviceFingerprint: targetFriend.deviceFingerprint,
      isLocal: false,
      isMuted: false,
      isDeafened: false,
      isSpeaking: false,
      connectionType: targetFriend.connectionType,
      pingMs: 14
    })
    setIsVoiceStageExpanded(true)

    void voiceEngine.startOutgoingCall({
      callId,
      targetFriendId: targetFriend.friendId,
      targetDisplayName: targetFriend.displayName,
      targetFingerprint: targetFriend.deviceFingerprint,
      connectionType: targetFriend.connectionType
    })

    // Simulação sutil de atendimento após 2.2s em demonstrações locais
    outgoingCallTimerRef.current = setTimeout(() => {
      if (voiceEngine.getState() === 'OUTGOING') {
        voiceEngine.handleConnectionSuccess()
      }
    }, 2200)
  }, [])

  const handleAcceptCall = useCallback(() => {
    void voiceEngine.acceptIncomingCall()
    setIsVoiceStageExpanded(true)
  }, [])

  const handleRejectCall = useCallback(() => {
    if (outgoingCallTimerRef.current) {
      clearTimeout(outgoingCallTimerRef.current)
    }
    voiceEngine.rejectIncomingCall()
    setIsVoiceStageExpanded(false)
  }, [])

  const handleDisconnectCall = useCallback(() => {
    if (outgoingCallTimerRef.current) {
      clearTimeout(outgoingCallTimerRef.current)
    }
    voiceEngine.endCall()
    setIsVoiceStageExpanded(false)
    setActiveVoiceChannelId(null)
    setCallParticipant(null)
  }, [])

  const handleJoinVoiceChannel = useCallback(
    async (voiceChannel: { channelId: string; name: string }) => {
      // Se já estiver conectado a este canal de voz, abre/expande o palco
      if (activeVoiceChannelId === voiceChannel.channelId && callState === 'CONNECTED') {
        setIsVoiceStageExpanded(true)
        return
      }

      setActiveVoiceChannelId(voiceChannel.channelId)
      // Apenas o usuário local está conectado na sala inicialmente
      setCallParticipant(null)
      setIsVoiceStageExpanded(true)

      // Conectar e inicializar captura de áudio do microfone e VAD
      await voiceEngine.joinVoiceChannel(voiceChannel.channelId)
    },
    [activeVoiceChannelId, callState]
  )

  const handleToggleMute = useCallback(() => {
    const muted = voiceEngine.toggleMute()
    setIsMuted(muted)
  }, [])

  const handleToggleDeafen = useCallback(() => {
    const deafened = voiceEngine.toggleDeafen()
    setIsDeafened(deafened)
  }, [])

  async function handleCreateServer(): Promise<void> {
    if (!api || !serverName.trim()) return
    try {
      setBusy(true)
      setError(undefined)
      const created = await api.createServer(serverName.trim())
      setServers((items) => [...items, created])
      setServer(created)
      setCurrentView('server')
      setShowServerModal(false)
      setServerName('Meu Servidor')
    } catch {
      setError('Não foi possível criar o servidor.')
    } finally {
      setBusy(false)
    }
  }

  async function handleCreateChannel(forcedType?: 'text' | 'voice'): Promise<void> {
    if (!api || !server || !channelName.trim()) return
    const targetType = forcedType ?? channelType
    try {
      setBusy(true)
      setError(undefined)

      const rawSlug = channelName
        .trim()
        .toLowerCase()
        .normalize('NFC')
        .replace(/[\s_]+/g, '-')
        .replace(/[^a-z0-9-áàâãéèêíïóôõöúçñ]/gi, '')
        .replace(/^-+|-+$/g, '')

      if (!rawSlug) {
        setError('Nome do canal inválido. Digite ao menos uma letra ou número.')
        return
      }

      const formattedName =
        targetType === 'voice'
          ? (rawSlug.startsWith('voz-') ? rawSlug : `voz-${rawSlug}`)
          : rawSlug

      // Verifica duplicidade local prévia
      const exists = channels.some((c) => c.name.toLowerCase() === formattedName.toLowerCase())
      if (exists) {
        setError(`Já existe um canal de ${targetType === 'voice' ? 'voz' : 'texto'} com esse nome neste servidor.`)
        return
      }

      const channel = await api.createChannel(server.localStorageId, formattedName, targetType)
      const channelWithType = {
        ...channel,
        type: targetType
      }
      setChannels((current) => [...current.filter((c) => c.channelId !== channel.channelId), channelWithType])
      if (targetType === 'text') {
        setSelectedChannel(channel.channelId)
      } else {
        handleJoinVoiceChannel(channelWithType)
      }
      setChannelName('')
      setChannelType('text')
      setShowChannelModal(false)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg.includes('ALREADY_EXISTS')) {
        setError('Já existe um canal com esse nome neste servidor.')
      } else if (msg.includes('INVALID')) {
        setError('Nome do canal inválido.')
      } else {
        setError('Não foi possível criar o canal.')
      }
    } finally {
      setBusy(false)
    }
  }

  async function handleSendMessage(): Promise<void> {
    if (!api || !draft.trim() || busy) return

    if (currentView === 'dm' && activeDmFriendId && api.sendDirectMessage) {
      try {
        setBusy(true)
        await api.sendDirectMessage(activeDmFriendId, draft.trim())
        setDraft('')
        if (api.listDirectMessages) {
          const updated = await api.listDirectMessages(activeDmFriendId)
          setDirectMessages(updated)
        }
      } finally {
        setBusy(false)
      }
      return
    }

    if (!server || !selectedChannel) return
    try {
      setBusy(true)
      setError(undefined)
      await api.sendMessage(server.localStorageId, selectedChannel, draft.trim())
      setDraft('')
      const updatedMessages = await api.listMessages(server.localStorageId, selectedChannel)
      setMessages(updatedMessages)
    } catch {
      setError('Mensagem não enviada. Ela continua localmente disponível para nova tentativa.')
    } finally {
      setBusy(false)
    }
  }

  async function handleAddFriend(): Promise<void> {
    if (!api?.addFriend || !newFriendInput.trim()) return
    try {
      setBusy(true)
      const created = await api.addFriend(newFriendInput.trim())
      setFriends((prev) => [...prev, created])
      setNewFriendInput('')
      setAddFriendFeedback(`Conexão com "${created.displayName}" autorizada com sucesso!`)
      setTimeout(() => setAddFriendFeedback(undefined), 4000)
    } catch {
      setError('Não foi possível adicionar o contato.')
    } finally {
      setBusy(false)
    }
  }

  async function handleGenerateInvite(): Promise<void> {
    if (!api || !server) return
    try {
      const result = await api.createInvite(server.localStorageId, 1)
      setInviteCode(result.encoded)
      setCopiedInvite(false)
      const updated = await api.listInvites(server.localStorageId)
      setInvites(updated)
    } catch {
      setError('Não foi possível gerar o convite assinado.')
    }
  }

  function handleCopyInvite(): void {
    if (!inviteCode) return
    void navigator.clipboard.writeText(inviteCode)
    setCopiedInvite(true)
    setTimeout(() => setCopiedInvite(false), 2400)
  }

  function handleCopyFingerprint(): void {
    const fp = members[0]?.deviceFingerprint || 'ed25519:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f'
    void navigator.clipboard.writeText(fp)
    setCopiedFingerprint(true)
    setTimeout(() => setCopiedFingerprint(false), 2400)
  }

  const loadAudioDevices = useCallback(async () => {
    try {
      const { inputs, outputs } = await voiceEngine.getAudioDevices()
      setAudioInputs(inputs)
      setAudioOutputs(outputs)
    } catch {
      // erro silencioso
    }
  }, [])

  useEffect(() => {
    if (showProfileModal) {
      void loadAudioDevices()
    }
  }, [showProfileModal, loadAudioDevices])

  useEffect(() => {
    if (typeof navigator !== 'undefined' && navigator.mediaDevices) {
      const handleDeviceChange = (): void => {
        void loadAudioDevices()
      }
      navigator.mediaDevices.addEventListener?.('devicechange', handleDeviceChange)
      return () => {
        navigator.mediaDevices.removeEventListener?.('devicechange', handleDeviceChange)
      }
    }
    return undefined
  }, [loadAudioDevices])

  useEffect(() => {
    if (selectedInputId) {
      void voiceEngine.setInputDevice(selectedInputId)
    }
    if (selectedOutputId) {
      void voiceEngine.setOutputDevice(selectedOutputId)
    }
    voiceEngine.setNoiseSuppression(noiseSuppressionEnabled)
    voiceEngine.setNoiseSuppressionLevel(noiseSuppressionLevel)
  }, [])

  function handleOpenProfileModal(defaultTab?: 'profile' | 'audio' | React.MouseEvent): void {
    const tab: 'profile' | 'audio' = (defaultTab === 'audio' || defaultTab === 'profile') ? defaultTab : 'profile'
    setEditProfile({ ...userProfile })
    setProfileSavedFeedback(false)
    setUserSettingsTab(tab)
    setShowProfileModal(true)
    void loadAudioDevices()
  }

  function handleCloseProfileModal(): void {
    if (isMicTesting) {
      voiceEngine.stopMicTest()
      setIsMicTesting(false)
      setMicTestLevel(0)
      setMicGateOpen(false)
    }
    setShowProfileModal(false)
  }

  async function handleInputDeviceChange(deviceId: string): Promise<void> {
    setSelectedInputId(deviceId)
    if (typeof window !== 'undefined') {
      localStorage.setItem('masquerada_audio_input', deviceId)
    }
    await voiceEngine.setInputDevice(deviceId)
    if (isMicTesting) {
      try {
        await voiceEngine.startMicTest((level, gateOpen) => {
          setMicTestLevel(level)
          setMicGateOpen(gateOpen)
        })
      } catch (err) {
        console.warn('Erro ao atualizar teste de microfone com novo dispositivo:', err)
      }
    }
  }

  async function handleOutputDeviceChange(deviceId: string): Promise<void> {
    setSelectedOutputId(deviceId)
    if (typeof window !== 'undefined') {
      localStorage.setItem('masquerada_audio_output', deviceId)
    }
    await voiceEngine.setOutputDevice(deviceId)
  }

  function handleToggleNoiseSuppression(enabled: boolean): void {
    setNoiseSuppressionEnabled(enabled)
    if (typeof window !== 'undefined') {
      localStorage.setItem('masquerada_noise_suppression', String(enabled))
    }
    voiceEngine.setNoiseSuppression(enabled)
  }

  function handleNoiseSuppressionLevelChange(level: number): void {
    const clamped = Math.max(1, Math.min(100, Math.round(level)))
    setNoiseSuppressionLevel(clamped)
    if (typeof window !== 'undefined') {
      localStorage.setItem('masquerada_noise_suppression_level', String(clamped))
    }
    voiceEngine.setNoiseSuppressionLevel(clamped)
  }

  function handleInputVolumeChange(vol: number): void {
    setInputVolume(vol)
    if (typeof window !== 'undefined') {
      localStorage.setItem('masquerada_input_volume', String(vol))
    }
  }

  function handleOutputVolumeChange(vol: number): void {
    setOutputVolume(vol)
    if (typeof window !== 'undefined') {
      localStorage.setItem('masquerada_output_volume', String(vol))
    }
  }

  async function handleToggleMicTest(): Promise<void> {
    if (isMicTesting) {
      voiceEngine.stopMicTest()
      setIsMicTesting(false)
      setMicTestLevel(0)
      setMicGateOpen(false)
    } else {
      try {
        setIsMicTesting(true)
        await voiceEngine.startMicTest((level, gateOpen) => {
          setMicTestLevel(level)
          setMicGateOpen(gateOpen)
        })
      } catch {
        setIsMicTesting(false)
        setMicTestLevel(0)
        setMicGateOpen(false)
      }
    }
  }

  function handleSaveProfile(): void {
    const sanitized: UserProfile = {
      ...editProfile,
      displayName: editProfile.displayName.trim() || 'Você',
      username: editProfile.username.trim().replace(/^@+/, '') || 'masquerada.host'
    }
    setUserProfile(sanitized)
    if (typeof window !== 'undefined') {
      try {
        localStorage.setItem('masquerada_user_profile', JSON.stringify(sanitized))
      } catch {
        /* storage indisponível */
      }
    }
    setProfileSavedFeedback(true)
    setTimeout(() => {
      setProfileSavedFeedback(false)
      handleCloseProfileModal()
    }, 600)
  }

  // Atalho ESC para fechar modal de perfil
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent): void {
      if (e.key === 'Escape' && showProfileModal) {
        handleCloseProfileModal()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [showProfileModal, isMicTesting])

  function openDmWithFriend(friendId: string): void {
    setActiveDmFriendId(friendId)
    setCurrentView('dm')
  }

  const textChannels = useMemo(() => {
    return channels.filter((c) => c.type !== 'voice' && !c.name.startsWith('voz-'))
  }, [channels])

  const voiceChannels = useMemo(() => {
    return channels.filter((c) => c.type === 'voice' || c.name.startsWith('voz-') || c.channelId.includes('voice'))
  }, [channels])

  const activeChannel = channels.find((c) => c.channelId === selectedChannel)
  const activeVoiceChannel = channels.find((c) => c.channelId === activeVoiceChannelId)
  const activeFriend = friends.find((f) => f.friendId === activeDmFriendId)

  // Filtragem de amigos por pesquisa e por aba
  const filteredFriends = friends.filter((friend) => {
    const matchesSearch = friend.displayName.toLowerCase().includes(friendsSearch.toLowerCase()) ||
                          friend.deviceFingerprint.toLowerCase().includes(friendsSearch.toLowerCase())
    if (!matchesSearch) return false
    if (friendsTab === 'online') return friend.status !== 'offline'
    if (friendsTab === 'all') return true
    return true
  })

  return (
    <main className="app-shell">
      {/* Tela de Onboarding (quando não há servidor criado) */}
      {!server ? (
        <section className="onboarding-wrap">
          <div className="onboarding">
            <img src="/logo.png" alt="Masquerada Medallion" className="onboarding-logo-hero" />
            <span className="eyebrow">
              <IconSparkles /> ESPAÇO LOCAL-FIRST
            </span>
            <h1>Converse sem abrir mão do controle.</h1>
            <p className="onboarding-desc">
              Crie seu espaço comunitário privado. A identidade permanece neste dispositivo, as chaves não saem da sua máquina e a rede só começa quando você decidir.
            </p>

            <div className="onboarding-features">
              <div className="feature-pill">
                <strong>Host Autoritativo</strong>
                <span>Você governa os dados locais</span>
              </div>
              <div className="feature-pill">
                <strong>Zero Trust</strong>
                <span>Criptografia Ed25519 & AEAD</span>
              </div>
              <div className="feature-pill">
                <strong>Sem Nuvem</strong>
                <span>Operação P2P independente</span>
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="onboarding-server-name">Nome do Servidor</label>
              <input
                id="onboarding-server-name"
                className="styled-input"
                placeholder="Ex: Comunidade Secreta, Equipe Alpha..."
                value={serverName}
                onChange={(e) => setServerName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void handleCreateServer() }}
              />
            </div>

            <button
              className="btn-primary"
              disabled={busy || !serverName.trim()}
              onClick={() => void handleCreateServer()}
            >
              {busy ? <span className="loading-spinner" /> : <IconPlus />}
              <span>{busy ? 'Criando...' : 'Criar servidor'}</span>
            </button>
          </div>
        </section>
      ) : (
        /* Shell Principal (Layout Discord) */
        <section className="discord-shell">
          {/* Trilho de Servidores (Esquerda) */}
          <nav className="server-rail" aria-label="Servidores">
            {/* Botão Home / Amigos com Emblema Masquerada SVG */}
            <div className={`rail-item-wrap ${currentView === 'friends' || currentView === 'dm' ? 'active' : ''}`}>
              <span className="rail-indicator" />
              <button
                className="rail-server home"
                title="Início & Amigos"
                aria-label="Masquerada home"
                onClick={() => {
                  setCurrentView('friends')
                  setActiveDmFriendId(undefined)
                }}
              >
                <IconMasqueradaLogo />
              </button>
            </div>

            <span className="rail-divider" />

            {/* Lista de Servidores */}
            {servers.map((item) => {
              const isActive = currentView === 'server' && item.localStorageId === server.localStorageId
              return (
                <div
                  key={item.localStorageId}
                  className={`rail-item-wrap ${isActive ? 'active' : ''}`}
                >
                  <span className="rail-indicator" />
                  <button
                    className="rail-server"
                    onClick={() => {
                      setServer(item)
                      setCurrentView('server')
                    }}
                    title={item.displayName}
                    aria-label={`Servidor ${item.displayName}`}
                  >
                    {item.displayName.slice(0, 1).toUpperCase()}
                  </button>
                </div>
              )
            })}

            {/* Botão Criar Servidor */}
            <div className="rail-item-wrap">
              <button
                className="rail-server add"
                onClick={() => setShowServerModal(true)}
                aria-label="Criar servidor"
                title="Criar novo servidor"
              >
                <IconPlus />
              </button>
            </div>
          </nav>

          {/* ================================================================
              MODO INÍCIO / AMIGOS (SIDEBAR)
              ================================================================ */}
          {currentView === 'friends' || currentView === 'dm' ? (
            <aside className="server-sidebar" aria-label="Navegação de amigos">
              <div className="server-header">
                <span className="server-header-title">Conexões P2P</span>
                <span className="server-header-badge"><i /> Ativo</span>
              </div>

              <div className="channels-container">
                {/* Botão Principal: Amigos */}
                <button
                  className={`friends-nav-btn ${currentView === 'friends' ? 'selected' : ''}`}
                  onClick={() => {
                    setCurrentView('friends')
                    setActiveDmFriendId(undefined)
                  }}
                >
                  <IconUsers />
                  <span>Amigos</span>
                </button>

                {/* Seção Mensagens Diretas */}
                <div className="channel-section-header">
                  <span>MENSAGENS DIRETAS</span>
                  <button
                    className="btn-icon-xs"
                    onClick={() => {
                      setCurrentView('friends')
                      setFriendsTab('add')
                    }}
                    title="Adicionar Amigo"
                    aria-label="Adicionar Amigo"
                  >
                    <IconPlus />
                  </button>
                </div>

                <div className="dm-list">
                  {friends.length > 0 ? (
                    friends.map((friend) => {
                      const isSelected = currentView === 'dm' && activeDmFriendId === friend.friendId
                      return (
                        <button
                          key={friend.friendId}
                          className={`dm-item ${isSelected ? 'selected' : ''}`}
                          onClick={() => openDmWithFriend(friend.friendId)}
                        >
                          <div className="dm-avatar">
                            {friend.displayName.slice(0, 1)}
                            <span className={`dm-status-dot ${friend.status}`} />
                          </div>
                          <div className="dm-details">
                            <span className="dm-name">{friend.displayName}</span>
                            <span className="dm-sub">
                              {friend.connectionType === 'direct' ? 'Direto P2P' : friend.connectionType === 'relay' ? 'Via Relay' : 'Rede Local'}
                            </span>
                          </div>
                        </button>
                      )
                    })
                  ) : (
                    <p className="sidebar-empty">Nenhum amigo ainda.</p>
                  )}
                </div>
              </div>

              {/* Barra de Controle de Voz P2P (Estilo Discord) */}
              <VoiceBar
                callState={callState}
                participant={callParticipant}
                channelName={activeVoiceChannel ? formatChannelDisplayName(activeVoiceChannel.name, 'voice') : undefined}
                isMuted={isMuted}
                isDeafened={isDeafened}
                isLocalSpeaking={isLocalSpeaking}
                isScreenSharing={isScreenSharing}
                pingMs={voicePingMs}
                onToggleMute={handleToggleMute}
                onToggleDeafen={handleToggleDeafen}
                onToggleScreenShare={handleToggleScreenShare}
                onDisconnect={handleDisconnectCall}
                onOpenStage={() => setIsVoiceStageExpanded(true)}
              />

              {/* Perfil do Usuário Host */}
              <div
                className="user-footer"
                onClick={handleOpenProfileModal}
                role="button"
                tabIndex={0}
                title="Configurações de Perfil (Estilo Discord)"
              >
                <div
                  className={`user-avatar avatar-color-${userProfile.avatarColor}`}
                  title="Identidade Criptográfica Host"
                >
                  {userProfile.displayName.charAt(0).toUpperCase() || 'M'}
                  <span className={`status-dot ${userProfile.status}`} />
                </div>
                <div className="user-info">
                  <span className="user-name">{userProfile.displayName}</span>
                  <span
                    className="user-tag"
                    title={userProfile.customStatus || `@${userProfile.username}`}
                  >
                    {userProfile.customStatus ? userProfile.customStatus : `@${userProfile.username}`}
                  </span>
                </div>
                <button
                  className="btn-icon-xs"
                  onClick={(e) => {
                    e.stopPropagation()
                    handleOpenProfileModal()
                  }}
                  title="Configurar Perfil"
                  aria-label="Configurações de Perfil"
                >
                  <IconSettings />
                </button>
              </div>
            </aside>
          ) : (
            /* ================================================================
               MODO SERVIDOR (SIDEBAR DE CANAIS)
               ================================================================ */
            <aside className="server-sidebar" aria-label="Navegação do servidor">
              {/* Cabeçalho do Servidor com Dropdown */}
              <div className="server-header-wrap">
                <div
                  className={`server-header ${showServerDropdown ? 'open' : ''}`}
                  onClick={() => setShowServerDropdown((prev) => !prev)}
                  role="button"
                  tabIndex={0}
                  aria-haspopup="true"
                  aria-expanded={showServerDropdown}
                  title="Opções e configurações do servidor"
                >
                  <div className="server-header-info">
                    <span className="server-header-title">{server.displayName}</span>
                    <span className="server-header-badge">
                      <i /> Host Local
                    </span>
                  </div>
                  <span className={`server-header-chevron ${showServerDropdown ? 'open' : ''}`}>
                    {showServerDropdown ? <IconChevronUp /> : <IconChevronDown />}
                  </span>
                </div>

                {/* Menu Dropdown de Configuração do Servidor (Estilo Discord) */}
                {showServerDropdown && (
                  <>
                    <div
                      className="dropdown-backdrop"
                      onClick={() => setShowServerDropdown(false)}
                    />
                    <div className="server-dropdown-menu" role="menu">
                      <button
                        className="server-menu-item highlight-boost"
                        onClick={() => {
                          setShowServerDropdown(false)
                          setShowServerSecurityModal(true)
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconDiamond />
                        </span>
                        <span className="menu-item-text">Impulso de servidor P2P</span>
                      </button>

                      <div className="server-menu-divider" />

                      <button
                        className="server-menu-item"
                        onClick={() => {
                          setShowServerDropdown(false)
                          setPanel('invites')
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconUserPlus />
                        </span>
                        <span className="menu-item-text">Convidar para o servidor</span>
                      </button>

                      <button
                        className="server-menu-item"
                        onClick={() => {
                          setShowServerDropdown(false)
                          setShowServerSettingsModal(true)
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconSettings />
                        </span>
                        <span className="menu-item-text">Config. do servidor</span>
                      </button>

                      <button
                        className="server-menu-item"
                        onClick={() => {
                          setShowServerDropdown(false)
                          setChannelType('text')
                          setChannelName('')
                          setError(undefined)
                          setShowChannelModal(true)
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconPlus />
                        </span>
                        <span className="menu-item-text">Criar canal</span>
                      </button>

                      <button
                        className="server-menu-item"
                        onClick={() => {
                          setServerNotifyMuted((prev) => !prev)
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconBell />
                        </span>
                        <span className="menu-item-text">Config. de notificação</span>
                        {serverNotifyMuted && <span className="menu-item-check">Mudo</span>}
                      </button>

                      <button
                        className="server-menu-item"
                        onClick={() => {
                          setShowServerDropdown(false)
                          setShowServerSecurityModal(true)
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconShield />
                        </span>
                        <span className="menu-item-text">Config. de privacidade</span>
                      </button>

                      <div className="server-menu-divider" />

                      <button
                        className="server-menu-item"
                        onClick={() => {
                          void navigator.clipboard.writeText(server.localStorageId)
                          setCopiedServerId(true)
                          setTimeout(() => setCopiedServerId(false), 2200)
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconId />
                        </span>
                        <span className="menu-item-text">
                          {copiedServerId ? 'ID copiado!' : 'Copiar ID do servidor'}
                        </span>
                      </button>

                      <div className="server-menu-divider" />

                      <button
                        className="server-menu-item danger"
                        onClick={() => {
                          setShowServerDropdown(false)
                          setCurrentView('friends')
                        }}
                      >
                        <span className="menu-item-icon">
                          <IconLogOut />
                        </span>
                        <span className="menu-item-text">Sair do servidor</span>
                      </button>
                    </div>
                  </>
                )}
              </div>

              {/* Lista de Canais (Texto e Voz Separados) */}
              <div className="channels-container">
                {/* Canais de Texto */}
                <div className="channel-section-header">
                  <span>CANAIS DE TEXTO</span>
                  <button
                    className="btn-icon-xs"
                    onClick={() => {
                      setChannelType('text')
                      setChannelName('')
                      setError(undefined)
                      setShowChannelModal(true)
                    }}
                    aria-label="Criar canal de texto"
                    title="Criar canal de texto"
                  >
                    <IconPlus />
                  </button>
                </div>

                <div className="channel-list">
                  {textChannels.length > 0 ? (
                    textChannels.map((channel) => {
                      const isSelected = channel.channelId === selectedChannel
                      return (
                        <button
                          key={channel.channelId}
                          className={`channel-item ${isSelected ? 'selected' : ''}`}
                          onClick={() => setSelectedChannel(channel.channelId)}
                        >
                          <span className="channel-hash">
                            <IconHash />
                          </span>
                          <span className="channel-name">{channel.name}</span>
                        </button>
                      )
                    })
                  ) : (
                    <p className="sidebar-empty">Nenhum canal de texto.</p>
                  )}
                </div>

                {/* Canais de Voz */}
                <div className="channel-section-header voice-section">
                  <span>CANAIS DE VOZ</span>
                  <button
                    className="btn-icon-xs"
                    onClick={() => {
                      setChannelType('voice')
                      setChannelName('')
                      setError(undefined)
                      setShowChannelModal(true)
                    }}
                    aria-label="Criar canal de voz"
                    title="Criar canal de voz"
                  >
                    <IconPlus />
                  </button>
                </div>

                <div className="channel-list voice-channel-list">
                  {voiceChannels.length > 0 ? (
                    voiceChannels.map((channel) => {
                      const isVoiceConnected =
                        activeVoiceChannelId === channel.channelId && callState === 'CONNECTED'
                      return (
                        <div key={channel.channelId} className="voice-channel-group">
                          <button
                            className={`channel-item voice ${isVoiceConnected ? 'connected' : ''}`}
                            onClick={() => handleJoinVoiceChannel(channel)}
                            title="Conectar ao canal de voz"
                          >
                            <span className={`channel-voice-icon ${isVoiceConnected ? 'live' : ''}`}>
                              <IconSpeaker />
                            </span>
                            <span className="channel-name">{formatChannelDisplayName(channel.name, 'voice')}</span>
                            {isVoiceConnected && (
                              <span className="voice-status-pill">
                                <i /> RTC
                              </span>
                            )}
                          </button>

                          {/* Membros conectados no canal de voz (Estilo Discord) */}
                          {isVoiceConnected && (
                            <div className="voice-channel-members">
                              <div className={`voice-member-item ${isLocalSpeaking ? 'speaking' : ''}`}>
                                <div className={`voice-member-avatar avatar-color-${userProfile.avatarColor}`}>
                                  {userProfile.displayName.charAt(0).toUpperCase() || 'M'}
                                  {isLocalSpeaking && <span className="avatar-speaking-glow" />}
                                </div>
                                <span className="voice-member-name">{userProfile.displayName} (Você)</span>
                                <div className="voice-member-badges">
                                  {isMuted && <span className="badge-muted" title="Microfone silenciado">🔇</span>}
                                  {isDeafened && <span className="badge-deafened" title="Áudio ensurdecido">🔈</span>}
                                </div>
                              </div>

                              {/* Participante remoto na chamada */}
                              {callParticipant && (
                                <div className={`voice-member-item ${isRemoteSpeaking ? 'speaking' : ''}`}>
                                  <div className="voice-member-avatar peer">
                                    {callParticipant.displayName.slice(0, 1)}
                                    {isRemoteSpeaking && <span className="avatar-speaking-glow" />}
                                  </div>
                                  <span className="voice-member-name">{callParticipant.displayName}</span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })
                  ) : (
                    <p className="sidebar-empty">Nenhum canal de voz.</p>
                  )}
                </div>
              </div>

              {/* Barra de Controle de Voz P2P (Estilo Discord) */}
              <VoiceBar
                callState={callState}
                participant={callParticipant}
                channelName={activeVoiceChannel ? formatChannelDisplayName(activeVoiceChannel.name, 'voice') : undefined}
                isMuted={isMuted}
                isDeafened={isDeafened}
                isLocalSpeaking={isLocalSpeaking}
                isScreenSharing={isScreenSharing}
                pingMs={voicePingMs}
                onToggleMute={handleToggleMute}
                onToggleDeafen={handleToggleDeafen}
                onToggleScreenShare={handleToggleScreenShare}
                onDisconnect={handleDisconnectCall}
                onOpenStage={() => setIsVoiceStageExpanded(true)}
              />

              {/* Perfil do Usuário Host */}
              <div
                className="user-footer"
                onClick={handleOpenProfileModal}
                role="button"
                tabIndex={0}
                title="Configurações de Perfil (Estilo Discord)"
              >
                <div
                  className={`user-avatar avatar-color-${userProfile.avatarColor}`}
                  title="Identidade Criptográfica Host"
                >
                  {userProfile.displayName.charAt(0).toUpperCase() || 'M'}
                  <span className={`status-dot ${userProfile.status}`} />
                </div>
                <div className="user-info">
                  <span className="user-name">{userProfile.displayName}</span>
                  <span
                    className="user-tag"
                    title={userProfile.customStatus || `@${userProfile.username}`}
                  >
                    {userProfile.customStatus ? userProfile.customStatus : `@${userProfile.username}`}
                  </span>
                </div>
                <button
                  className="btn-icon-xs"
                  onClick={(e) => {
                    e.stopPropagation()
                    handleOpenProfileModal()
                  }}
                  title="Configurar Perfil"
                  aria-label="Configurações de Perfil"
                >
                  <IconSettings />
                </button>
              </div>
            </aside>
          )}

          {/* ================================================================
              ÁREA PRINCIPAL: PALCO DE VOZ P2P OU VIEW ATIVA
              ================================================================ */}
          {isVoiceStageExpanded && callState !== 'IDLE' ? (
            <VoiceStage
              callState={callState}
              participant={callParticipant}
              channelName={activeVoiceChannel ? formatChannelDisplayName(activeVoiceChannel.name, 'voice') : undefined}
              isMuted={isMuted}
              isDeafened={isDeafened}
              isLocalSpeaking={isLocalSpeaking}
              isRemoteSpeaking={isRemoteSpeaking}
              isScreenSharing={isScreenSharing}
              screenStream={remoteScreenStream || localScreenStream}
              localDisplayName={userProfile.displayName}
              localAvatarColor={userProfile.avatarColor}
              onToggleMute={handleToggleMute}
              onToggleDeafen={handleToggleDeafen}
              onDisconnect={handleDisconnectCall}
              onMinimize={() => setIsVoiceStageExpanded(false)}
              onStartScreenShare={() => setIsScreenShareModalOpen(true)}
              onStopScreenShare={handleStopScreenShare}
            />
          ) : currentView === 'friends' ? (
            <section className="friends-shell">
              {/* Header da Tela de Amigos com Abas */}
              <header className="friends-header">
                <div className="friends-header-title">
                  <IconUsers />
                  <span>Amigos</span>
                </div>

                <div className="friends-header-divider" />

                <div className="friends-tabs">
                  <button
                    className={`friends-tab ${friendsTab === 'online' ? 'active' : ''}`}
                    onClick={() => setFriendsTab('online')}
                  >
                    Disponíveis ({friends.filter((f) => f.status !== 'offline').length})
                  </button>

                  <button
                    className={`friends-tab ${friendsTab === 'all' ? 'active' : ''}`}
                    onClick={() => setFriendsTab('all')}
                  >
                    Todos ({friends.length})
                  </button>

                  <button
                    className={`friends-tab ${friendsTab === 'pending' ? 'active' : ''}`}
                    onClick={() => setFriendsTab('pending')}
                  >
                    Pendentes (0)
                  </button>

                  <button
                    className={`friends-tab add-tab ${friendsTab === 'add' ? 'active' : ''}`}
                    onClick={() => setFriendsTab('add')}
                  >
                    Adicionar Amigo
                  </button>
                </div>
              </header>

              {/* Corpo da Tela de Amigos */}
              <div className="friends-main">
                {friendsTab === 'add' ? (
                  <div className="add-friend-panel">
                    <h3>ADICIONAR AMIGO VIA P2P</h3>
                    <p>
                      Conecte-se diretamente a amigos colando uma <strong>Device Fingerprint Ed25519</strong> ou um <strong>Convite Assinado MQR1</strong> emitido por eles.
                    </p>

                    <div className="add-friend-form">
                      <input
                        className="styled-input"
                        placeholder="Ex: ed25519:7a8b9c... ou MQR1.ey..."
                        value={newFriendInput}
                        onChange={(e) => setNewFriendInput(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') void handleAddFriend() }}
                      />
                      <button
                        className="btn-primary btn-auto"
                        disabled={busy || !newFriendInput.trim()}
                        onClick={() => void handleAddFriend()}
                      >
                        Enviar Solicitação
                      </button>
                    </div>

                    {addFriendFeedback && (
                      <div className="privacy-pill">
                        <i />
                        <span>{addFriendFeedback}</span>
                      </div>
                    )}

                    <div className="my-identity-card">
                      <h4>SEU DEVICE FINGERPRINT (COMPARTILHE COM AMIGOS)</h4>
                      <p>Outros nós da rede Masquerada utilizam esta identidade para autenticar conexões diretas ou relays com você.</p>
                      <div className="identity-box">
                        <span>{members[0]?.deviceFingerprint ?? 'ed25519:carregando...'}</span>
                        <button className="btn-copy" onClick={handleCopyFingerprint}>
                          {copiedFingerprint ? <IconCheck /> : <IconCopy />}
                          <span>{copiedFingerprint ? 'Copiado!' : 'Copiar'}</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="friends-search-box">
                      <input
                        className="styled-input"
                        placeholder="Buscar conexões por nome ou fingerprint..."
                        value={friendsSearch}
                        onChange={(e) => setFriendsSearch(e.target.value)}
                      />
                    </div>

                    <div className="friends-section-title">
                      {friendsTab === 'online' ? 'CONEXÕES ONLINE' : 'TODAS AS CONEXÕES'} — {filteredFriends.length}
                    </div>

                    <div className="friends-list">
                      {filteredFriends.length > 0 ? (
                        filteredFriends.map((friend) => (
                          <div key={friend.friendId} className="friend-card">
                            <div className="friend-avatar-wrap">
                              {friend.displayName.slice(0, 1)}
                              <span className={`status-dot ${friend.status === 'offline' ? 'offline' : ''}`} />
                            </div>

                            <div className="friend-info">
                              <div className="friend-name-row">
                                <span className="friend-name">{friend.displayName}</span>
                                <span className={`connection-tag ${friend.connectionType}`}>
                                  {friend.connectionType === 'direct' ? '● P2P Direto' : friend.connectionType === 'relay' ? '● Via Relay' : '● LAN Local'}
                                </span>
                              </div>
                              <span className="friend-status-msg">{friend.customStatus ?? 'Conexão autorizada'}</span>
                              <span className="friend-fp">{friend.deviceFingerprint}</span>
                            </div>

                            <div className="friend-actions">
                              <button
                                className="friend-action-btn"
                                onClick={() => handleStartCall(friend)}
                                title="Iniciar chamada de voz P2P"
                                aria-label={`Ligar para ${friend.displayName}`}
                              >
                                <IconPhone />
                              </button>
                              <button
                                className="friend-action-btn"
                                onClick={() => openDmWithFriend(friend.friendId)}
                                title="Enviar mensagem direta"
                                aria-label={`Conversar com ${friend.displayName}`}
                              >
                                <IconMessage />
                              </button>
                              <button
                                className="friend-action-btn"
                                onClick={() => {
                                  void navigator.clipboard.writeText(friend.deviceFingerprint)
                                }}
                                title="Copiar Fingerprint do Amigo"
                                aria-label="Copiar chave pública"
                              >
                                <IconKey />
                              </button>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="empty-chat empty-friends">
                          <div className="empty-symbol">
                            <IconUsers />
                          </div>
                          <h3>Nenhuma conexão adicionada</h3>
                          <p>
                            Sua lista de conexões está vazia. Compartilhe seu Device Fingerprint ou
                            adicione o identificador de um amigo para iniciar uma conversa ou
                            chamada de voz privada.
                          </p>
                          <button
                            type="button"
                            className="btn-primary btn-auto"
                            onClick={() => setFriendsTab('add')}
                          >
                            <IconUserPlus />
                            <span>Adicionar Amigo</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </section>
          ) : currentView === 'dm' && activeFriend ? (
            /* ================================================================
               ÁREA PRINCIPAL: CONVERSA DIRETA COM AMIGO (DM)
               ================================================================ */
            <section className="conversation">
              <header className="conversation-header">
                <div className="channel-info">
                  <div className="dm-avatar">
                    {activeFriend.displayName.slice(0, 1)}
                    <span className={`dm-status-dot ${activeFriend.status}`} />
                  </div>
                  <div className="channel-title-group">
                    <h2>@{activeFriend.displayName}</h2>
                    <p>
                      {activeFriend.connectionType === 'direct'
                        ? '● Conexão Direta E2EE (IPv6/TCP) · Criptografia X25519 & AES-GCM'
                        : '● Circuito Relay Criptografado Ponta a Ponta'}
                    </p>
                  </div>
                </div>

                <div className="header-actions">
                  <button
                    className="btn-start-call"
                    onClick={() => handleStartCall(activeFriend)}
                    title="Iniciar Chamada de Voz P2P Direta"
                  >
                    <IconPhone />
                    <span>Ligar</span>
                  </button>
                </div>
              </header>

              <div className="conversation-main">
                <div className="timeline">
                  {directMessages.length === 0 ? (
                    <div className="empty-chat">
                      <div className="empty-symbol"><IconSparkles /></div>
                      <h3>Início de Conversa Direta</h3>
                      <p>
                        Suas mensagens com <strong>@{activeFriend.displayName}</strong> são protegidas por chaves de sessão mutuamente autenticadas.
                      </p>
                    </div>
                  ) : (
                    directMessages.map((dm) => (
                      <article key={dm.sequence} className="message">
                        <div
                          className={`message-avatar ${
                            dm.author === 'Você' ? `avatar-color-${userProfile.avatarColor}` : ''
                          }`}
                        >
                          {dm.author === 'Você'
                            ? userProfile.displayName.charAt(0).toUpperCase() || 'V'
                            : dm.author.slice(0, 1)}
                        </div>
                        <div className="message-content">
                          <div className="message-header">
                            <span className="message-author">
                              {dm.author === 'Você' ? userProfile.displayName : dm.author}
                            </span>
                            <span className="message-time">hoje às {dm.time}</span>
                            <span className="message-seq">#{dm.sequence}</span>
                          </div>
                          <p className="message-body">{dm.content}</p>
                        </div>
                      </article>
                    ))
                  )}
                </div>
              </div>

              {/* Composer da DM */}
              <div className="composer-area">
                <div className="composer-box">
                  <textarea
                    className="composer-textarea"
                    disabled={busy}
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault()
                        void handleSendMessage()
                      }
                    }}
                    placeholder={`Conversar com @${activeFriend.displayName}...`}
                    aria-label="Mensagem privada"
                  />
                  <div className="composer-actions">
                    <button
                      className="btn-send"
                      disabled={busy || !draft.trim()}
                      onClick={() => void handleSendMessage()}
                      title="Enviar mensagem (Enter)"
                      aria-label="Enviar mensagem"
                    >
                      {busy ? <span className="loading-spinner" /> : <IconSend />}
                    </button>
                  </div>
                </div>
                <span className="composer-hint">
                  Pressione <strong>Enter</strong> para enviar · <strong>Shift + Enter</strong> para quebra de linha
                </span>
              </div>
            </section>
          ) : (
            /* ================================================================
               ÁREA PRINCIPAL: CANAIS DO SERVIDOR
               ================================================================ */
            <section className="conversation">
              {/* Header da Conversa */}
              <header className="conversation-header">
                <div className="channel-info">
                  <span className="channel-hash-lg">
                    <IconHash />
                  </span>
                  <div className="channel-title-group">
                    <h2>{activeChannel?.name ?? 'Selecione um canal'}</h2>
                    <p>Conversas criptografadas, armazenadas localmente no host</p>
                  </div>
                </div>

                <div className="conversation-tools">
                  <button
                    className={`tool-btn ${panel === 'members' ? 'active' : ''}`}
                    onClick={() => setPanel(panel === 'members' ? null : 'members')}
                    aria-label="Mostrar membros"
                    title="Membros do servidor"
                  >
                    <IconUsers />
                    <span className="badge-count">{members.length}</span>
                  </button>

                  <button
                    className={`tool-btn ${panel === 'invites' ? 'active' : ''}`}
                    onClick={() => setPanel(panel === 'invites' ? null : 'invites')}
                    aria-label="Mostrar convites"
                    title="Convites MQR1"
                  >
                    <IconKey />
                  </button>
                </div>
              </header>

              {/* Mensagens e Painel Lateral */}
              <div className="conversation-main">
                <div className="timeline">
                  {loadingMessages ? (
                    <div className="loading-state" role="status">
                      <span className="loading-spinner" />
                      <span>Sincronizando histórico do banco SQLite...</span>
                    </div>
                  ) : messages.length === 0 ? (
                    <div className="empty-chat">
                      <div className="empty-symbol">
                        <IconSparkles />
                      </div>
                      <h3>O começo de uma conversa</h3>
                      <p>
                        Este é o início do canal <strong>#{activeChannel?.name ?? 'geral'}</strong>. Envie a primeira mensagem para registrar na história do servidor.
                      </p>
                    </div>
                  ) : (
                    messages.map((message) => (
                      <article
                        key={message.sequence}
                        className={`message ${message.deletedAt ? 'deleted' : ''}`}
                      >
                        <div className={`message-avatar avatar-color-${userProfile.avatarColor}`}>
                          {userProfile.displayName.charAt(0).toUpperCase() || 'M'}
                        </div>
                        <div className="message-content">
                          <div className="message-header">
                            <span className="message-author">{userProfile.displayName}</span>
                            <span className="message-time">
                              hoje às 14:{String(message.sequence).padStart(2, '0')}
                            </span>
                            <span className="message-seq">#{message.sequence}</span>
                          </div>
                          <p className="message-body">
                            {message.deletedAt ? 'Mensagem removida' : message.content}
                          </p>
                        </div>
                      </article>
                    ))
                  )}
                </div>

                {/* Painel Lateral (Membros / Convites) */}
                {panel && (
                  <aside
                    className="side-drawer"
                    aria-label={panel === 'members' ? 'Membros' : 'Convites'}
                  >
                    <div className="drawer-header">
                      <div className="drawer-tabs">
                        <button
                          className={`drawer-tab ${panel === 'members' ? 'active' : ''}`}
                          onClick={() => setPanel('members')}
                        >
                          Membros ({members.length})
                        </button>
                        <button
                          className={`drawer-tab ${panel === 'invites' ? 'active' : ''}`}
                          onClick={() => setPanel('invites')}
                        >
                          Convites
                        </button>
                      </div>
                      <button
                        className="btn-icon-xs"
                        onClick={() => setPanel(null)}
                        aria-label="Fechar painel"
                      >
                        <IconClose />
                      </button>
                    </div>

                    <div className="drawer-body">
                      {panel === 'members' ? (
                        <div className="member-list">
                          {members.length > 0 ? (
                            members.map((member, index) => (
                              <div key={member.deviceFingerprint} className="member-item">
                                <div className="member-avatar">M</div>
                                <div className="member-details">
                                  <span className="member-role">
                                    {index === 0 ? 'Proprietário (Host)' : 'Membro'}
                                  </span>
                                  <span
                                    className="member-fp"
                                    title={member.deviceFingerprint}
                                  >
                                    {member.deviceFingerprint.slice(0, 16)}...
                                  </span>
                                </div>
                              </div>
                            ))
                          ) : (
                            <p className="sidebar-empty">Nenhum membro conectado.</p>
                          )}
                        </div>
                      ) : (
                        <div className="invites-panel">
                          <div className="invite-card">
                            <p>
                              Gere um convite criptográfico <strong>MQR1</strong> assinado pela Server Identity para admitir novos membros.
                            </p>
                            <button
                              className="btn-generate-invite"
                              onClick={() => void handleGenerateInvite()}
                            >
                              <IconKey />
                              <span>Gerar convite assinado</span>
                            </button>

                            {inviteCode && (
                              <div className="invite-result">
                                <textarea
                                  className="invite-token-box"
                                  readOnly
                                  value={inviteCode}
                                  aria-label="Convite gerado"
                                />
                                <button
                                  className={`btn-copy ${copiedInvite ? 'copied' : ''}`}
                                  onClick={handleCopyInvite}
                                >
                                  {copiedInvite ? <IconCheck /> : <IconCopy />}
                                  <span>{copiedInvite ? 'Copiado!' : 'Copiar Token'}</span>
                                </button>
                              </div>
                            )}
                          </div>

                          {invites.length > 0 && (
                            <>
                              <span className="invites-history-title">HISTÓRICO DE CONVITES</span>
                              <div className="invite-badge-list">
                                {invites.map((invite) => (
                                  <div key={invite.inviteId} className="invite-badge">
                                    <span
                                      className={`status-pill ${
                                        invite.status === 'ACTIVE' ? 'active' : 'consumed'
                                      }`}
                                    >
                                      {invite.status}
                                    </span>
                                    <span>
                                      {invite.uses} / {invite.maxUses} usos
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  </aside>
                )}
              </div>

              {/* Banner de Erro */}
              {error && (
                <div className="error-banner" role="alert">
                  <span>{error}</span>
                  <button
                    className="btn-icon-xs"
                    onClick={() => setError(undefined)}
                    aria-label="Fechar aviso"
                  >
                    <IconClose />
                  </button>
                </div>
              )}

              {/* Composer de Digitação do Canal */}
              <div className="composer-area">
                <div className="composer-box">
                  <textarea
                    className="composer-textarea"
                    disabled={busy || !activeChannel}
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault()
                        void handleSendMessage()
                      }
                    }}
                    placeholder={
                      activeChannel
                        ? `Conversar em #${activeChannel.name}`
                        : 'Selecione um canal para conversar'
                    }
                    aria-label="Mensagem"
                  />
                  <div className="composer-actions">
                    <button
                      className="btn-send"
                      disabled={busy || !draft.trim() || !activeChannel}
                      onClick={() => void handleSendMessage()}
                      title="Enviar mensagem (Enter)"
                      aria-label="Enviar mensagem"
                    >
                      {busy ? <span className="loading-spinner" /> : <IconSend />}
                    </button>
                  </div>
                </div>
                <span className="composer-hint">
                  Pressione <strong>Enter</strong> para enviar · <strong>Shift + Enter</strong> para quebra de linha
                </span>
              </div>
            </section>
          )}
        </section>
      )}

      {/* Modal: Criar Canal (Estilo Discord com Texto e Voz) */}
      {showChannelModal && (
        <div className="modal-overlay" onClick={() => setShowChannelModal(false)}>
          <div className="modal-card create-channel-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">Criar canal</h3>
                <span className="modal-subtitle">
                  em {channelType === 'text' ? 'Canais de Texto' : 'Canais de Voz'}
                </span>
              </div>
              <button
                className="btn-icon-xs"
                onClick={() => setShowChannelModal(false)}
                aria-label="Fechar"
              >
                <IconClose />
              </button>
            </div>

            <div className="form-group">
              <label className="input-category-label">TIPO DE CANAL</label>
              <div className="channel-type-selector">
                <button
                  type="button"
                  className={`channel-type-card ${channelType === 'text' ? 'selected' : ''}`}
                  onClick={() => setChannelType('text')}
                >
                  <div className="channel-type-icon">
                    <IconHash />
                  </div>
                  <div className="channel-type-info">
                    <div className="channel-type-title">Texto</div>
                    <div className="channel-type-desc">
                      Envie mensagens, imagens, figurinhas e opiniões
                    </div>
                  </div>
                  <div className="channel-type-radio">
                    <span className={`radio-indicator ${channelType === 'text' ? 'checked' : ''}`} />
                  </div>
                </button>

                <button
                  type="button"
                  className={`channel-type-card ${channelType === 'voice' ? 'selected' : ''}`}
                  onClick={() => setChannelType('voice')}
                >
                  <div className="channel-type-icon">
                    <IconSpeaker />
                  </div>
                  <div className="channel-type-info">
                    <div className="channel-type-title">Voz</div>
                    <div className="channel-type-desc">
                      Converse em tempo real por chamada de áudio P2P e vídeo
                    </div>
                  </div>
                  <div className="channel-type-radio">
                    <span className={`radio-indicator ${channelType === 'voice' ? 'checked' : ''}`} />
                  </div>
                </button>
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="channel-name-input" className="input-category-label">
                NOME DO CANAL
              </label>
              <div className="input-with-prefix">
                <span className="input-prefix-icon">
                  {channelType === 'text' ? <IconHash /> : <IconSpeaker />}
                </span>
                <input
                  id="channel-name-input"
                  className="styled-input with-prefix"
                  placeholder={channelType === 'text' ? 'novo-canal' : 'Sala de Voz'}
                  value={channelName}
                  autoFocus
                  onChange={(e) => setChannelName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void handleCreateChannel()
                  }}
                />
              </div>
            </div>

            {error && (
              <div
                style={{
                  color: '#f87171',
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  marginBottom: '16px'
                }}
              >
                {error}
              </div>
            )}

            <div className="modal-actions">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setShowChannelModal(false)}
              >
                Cancelar
              </button>
              <button
                type="button"
                className="btn-primary btn-auto"
                disabled={busy || !channelName.trim()}
                onClick={() => void handleCreateChannel()}
              >
                {busy ? 'Criando...' : 'Criar canal'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Configurações do Servidor */}
      {showServerSettingsModal && server && (
        <div className="modal-overlay" onClick={() => setShowServerSettingsModal(false)}>
          <div className="modal-card server-settings-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">Configurações do Servidor</h3>
                <span className="modal-subtitle">Visão geral e governança local-first</span>
              </div>
              <button
                className="btn-icon-xs"
                onClick={() => setShowServerSettingsModal(false)}
                aria-label="Fechar"
              >
                <IconClose />
              </button>
            </div>

            <div className="settings-section-card">
              <div className="settings-row">
                <div className="settings-label-group">
                  <strong>Nome do Servidor</strong>
                  <span>Espaço de comunicação comunitária</span>
                </div>
                <input
                  className="styled-input settings-input-sm"
                  value={server.displayName}
                  readOnly
                />
              </div>

              <div className="settings-row">
                <div className="settings-label-group">
                  <strong>ID Local do Servidor</strong>
                  <span className="code-text">{server.localStorageId}</span>
                </div>
                <button
                  type="button"
                  className="btn-secondary btn-sm"
                  onClick={() => {
                    void navigator.clipboard.writeText(server.localStorageId)
                    setCopiedServerId(true)
                    setTimeout(() => setCopiedServerId(false), 2000)
                  }}
                >
                  {copiedServerId ? <IconCheck /> : <IconCopy />}
                  <span>{copiedServerId ? 'Copiado!' : 'Copiar ID'}</span>
                </button>
              </div>

              <div className="settings-row">
                <div className="settings-label-group">
                  <strong>Identidade do Host (Fingerprint)</strong>
                  <span className="code-text">
                    {members[0]?.deviceFingerprint ?? 'Host Local'}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn-secondary btn-sm"
                  onClick={handleCopyFingerprint}
                >
                  {copiedFingerprint ? <IconCheck /> : <IconCopy />}
                  <span>{copiedFingerprint ? 'Copiado!' : 'Copiar'}</span>
                </button>
              </div>

              <div className="server-stats-grid">
                <div className="stat-card">
                  <span className="stat-number">{textChannels.length}</span>
                  <span className="stat-label">Canais de Texto</span>
                </div>
                <div className="stat-card">
                  <span className="stat-number">{voiceChannels.length}</span>
                  <span className="stat-label">Canais de Voz</span>
                </div>
                <div className="stat-card">
                  <span className="stat-number">{members.length}</span>
                  <span className="stat-label">Membros Conectados</span>
                </div>
              </div>
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() => setShowServerSettingsModal(false)}
              >
                Concluir
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Privacidade & Segurança P2P */}
      {showServerSecurityModal && (
        <div className="modal-overlay" onClick={() => setShowServerSecurityModal(false)}>
          <div className="modal-card server-security-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">Segurança & Privacidade P2P</h3>
                <span className="modal-subtitle">Soberania de dados e garantias de rede</span>
              </div>
              <button
                className="btn-icon-xs"
                onClick={() => setShowServerSecurityModal(false)}
                aria-label="Fechar"
              >
                <IconClose />
              </button>
            </div>

            <div className="security-cards-list">
              <div className="security-item-card">
                <div className="security-item-badge active">ATIVO</div>
                <h4>Criptografia Ponta-a-Ponta (E2EE)</h4>
                <p>
                  Assinaturas Ed25519 e cifra autenticada ChaCha20-Poly1305 para todas as mensagens,
                  mídias e estados do servidor.
                </p>
              </div>

              <div className="security-item-card">
                <div className="security-item-badge active">DIRETO</div>
                <h4>Transmissão de Voz P2P Sem Servidor</h4>
                <p>
                  O áudio trafega de dispositivo para dispositivo através de WebRTC Datachannels e
                  STUN UDP direto, sem gravação ou intermediários em nuvem.
                </p>
              </div>

              <div className="security-item-card">
                <div className="security-item-badge active">ISOLADO</div>
                <h4>Armazenamento Local Host-Authoritative</h4>
                <p>
                  O histórico dos canais de texto e metadados é guardado em SQLite criptografado no
                  seu computador, sob seu exclusivo controle físico.
                </p>
              </div>
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() => setShowServerSecurityModal(false)}
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Criar Novo Servidor */}
      {showServerModal && (
        <div className="modal-overlay" onClick={() => setShowServerModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title">Criar Novo Espaço</h3>
              <button
                className="btn-icon-xs"
                onClick={() => setShowServerModal(false)}
                aria-label="Fechar"
              >
                <IconClose />
              </button>
            </div>
            <div className="form-group">
              <label htmlFor="server-name-input">Nome do Servidor</label>
              <input
                id="server-name-input"
                className="styled-input"
                placeholder="Ex: Masquerada VIP, Projetos..."
                value={serverName}
                autoFocus
                onChange={(e) => setServerName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void handleCreateServer()
                }}
              />
            </div>
            <div className="modal-actions">
              <button
                className="btn-secondary"
                onClick={() => setShowServerModal(false)}
              >
                Cancelar
              </button>
              <button
                className="btn-primary btn-auto"
                disabled={busy || !serverName.trim()}
                onClick={() => void handleCreateServer()}
              >
                {busy ? 'Criando...' : 'Criar servidor'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Perfil e Configurações de Usuário (Estilo Discord) */}
      {showProfileModal && (
        <div
          className="modal-overlay profile-modal-backdrop"
          onClick={handleCloseProfileModal}
        >
          <div className="user-profile-modal" onClick={(e) => e.stopPropagation()}>
            <div className="profile-modal-header">
              <div className="profile-modal-title-wrap">
                <span className="profile-modal-badge">
                  <IconSettings />
                  <span>CONFIGURAÇÕES DO USUÁRIO</span>
                </span>
                <div className="profile-modal-nav-tabs">
                  <button
                    type="button"
                    className={`profile-nav-tab ${userSettingsTab === 'profile' ? 'active' : ''}`}
                    onClick={() => setUserSettingsTab('profile')}
                  >
                    <IconPalette />
                    <span>Meu Perfil</span>
                  </button>
                  <button
                    type="button"
                    className={`profile-nav-tab ${userSettingsTab === 'audio' ? 'active' : ''}`}
                    onClick={() => setUserSettingsTab('audio')}
                  >
                    <IconMic />
                    <span>Voz & Áudio</span>
                  </button>
                </div>
              </div>
              <button
                className="btn-icon-close-esc"
                onClick={handleCloseProfileModal}
                aria-label="Fechar"
                title="Fechar (ESC)"
              >
                <IconClose />
                <span className="esc-hint">ESC</span>
              </button>
            </div>

            <div className="profile-modal-body">
              {userSettingsTab === 'profile' ? (
                <div className="profile-modal-grid">
                {/* Coluna da Esquerda: Edição de Campos */}
                <div className="profile-edit-column">
                  {/* Nome de Exibição */}
                  <div className="form-group">
                    <label htmlFor="profile-display-name">NOME DE EXIBIÇÃO</label>
                    <input
                      id="profile-display-name"
                      className="styled-input"
                      value={editProfile.displayName}
                      maxLength={32}
                      placeholder="Como você quer ser chamado"
                      onChange={(e) =>
                        setEditProfile((prev) => ({ ...prev, displayName: e.target.value }))
                      }
                    />
                    <span className="field-hint">
                      É como outros usuários verão seu perfil nas chamadas e chats.
                    </span>
                  </div>

                  {/* Nome de Usuário (@handle) */}
                  <div className="form-group">
                    <label htmlFor="profile-username">NOME DE USUÁRIO</label>
                    <div className="input-with-prefix">
                      <span className="input-prefix">@</span>
                      <input
                        id="profile-username"
                        className="styled-input prefix-padded"
                        value={editProfile.username}
                        maxLength={24}
                        placeholder="seu.usuario"
                        onChange={(e) =>
                          setEditProfile((prev) => ({
                            ...prev,
                            username: e.target.value.toLowerCase().replace(/[^a-z0-9._-]/g, '')
                          }))
                        }
                      />
                    </div>
                    <span className="field-hint">Seu identificador único na rede privada.</span>
                  </div>

                  {/* Status de Presença */}
                  <div className="form-group">
                    <label>STATUS DE PRESENÇA</label>
                    <div className="presence-status-grid">
                      <button
                        type="button"
                        className={`presence-card ${editProfile.status === 'online' ? 'selected' : ''}`}
                        onClick={() => setEditProfile((prev) => ({ ...prev, status: 'online' }))}
                      >
                        <span className="presence-dot-indicator online" />
                        <div className="presence-info">
                          <strong>Online</strong>
                          <small>Visível para todos</small>
                        </div>
                      </button>

                      <button
                        type="button"
                        className={`presence-card ${editProfile.status === 'idle' ? 'selected' : ''}`}
                        onClick={() => setEditProfile((prev) => ({ ...prev, status: 'idle' }))}
                      >
                        <span className="presence-dot-indicator idle" />
                        <div className="presence-info">
                          <strong>Ausente</strong>
                          <small>Inativo temporariamente</small>
                        </div>
                      </button>

                      <button
                        type="button"
                        className={`presence-card ${editProfile.status === 'dnd' ? 'selected' : ''}`}
                        onClick={() => setEditProfile((prev) => ({ ...prev, status: 'dnd' }))}
                      >
                        <span className="presence-dot-indicator dnd" />
                        <div className="presence-info">
                          <strong>Não Perturbe</strong>
                          <small>Silenciar notificações</small>
                        </div>
                      </button>

                      <button
                        type="button"
                        className={`presence-card ${editProfile.status === 'offline' ? 'selected' : ''}`}
                        onClick={() => setEditProfile((prev) => ({ ...prev, status: 'offline' }))}
                      >
                        <span className="presence-dot-indicator offline" />
                        <div className="presence-info">
                          <strong>Invisível</strong>
                          <small>Aparece desconectado</small>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Status Personalizado */}
                  <div className="form-group">
                    <label htmlFor="profile-custom-status">STATUS PERSONALIZADO</label>
                    <input
                      id="profile-custom-status"
                      className="styled-input"
                      value={editProfile.customStatus}
                      maxLength={64}
                      placeholder="Ex: Codando no Masquerada P2P..."
                      onChange={(e) =>
                        setEditProfile((prev) => ({ ...prev, customStatus: e.target.value }))
                      }
                    />
                  </div>

                  {/* Sobre Mim */}
                  <div className="form-group">
                    <div className="label-with-counter">
                      <label htmlFor="profile-bio" className="label-with-icon">
                        <IconPencil />
                        <span>SOBRE MIM</span>
                      </label>
                      <span className="char-counter">{editProfile.bio.length}/190</span>
                    </div>
                    <textarea
                      id="profile-bio"
                      className="styled-textarea profile-bio-textarea"
                      value={editProfile.bio}
                      maxLength={190}
                      rows={3}
                      placeholder="Conte um pouco sobre você e seu nó P2P..."
                      onChange={(e) =>
                        setEditProfile((prev) => ({ ...prev, bio: e.target.value }))
                      }
                    />
                  </div>

                  {/* Cor do Banner do Perfil */}
                  <div className="form-group">
                    <label>TEMA DO BANNER</label>
                    <div className="theme-palette-grid">
                      {(['blurple', 'gold', 'emerald', 'crimson', 'cyan', 'midnight'] as const).map(
                        (theme) => (
                          <button
                            key={theme}
                            type="button"
                            className={`theme-swatch banner-theme-${theme} ${
                              editProfile.bannerColor === theme ? 'active' : ''
                            }`}
                            onClick={() =>
                              setEditProfile((prev) => ({ ...prev, bannerColor: theme }))
                            }
                            title={`Banner ${theme}`}
                          >
                            {editProfile.bannerColor === theme && <IconCheck />}
                          </button>
                        )
                      )}
                    </div>
                  </div>

                  {/* Cor do Avatar */}
                  <div className="form-group">
                    <label>COR DO AVATAR</label>
                    <div className="avatar-palette-grid">
                      {(['blurple', 'gold', 'emerald', 'crimson', 'cyan', 'purple'] as const).map(
                        (col) => (
                          <button
                            key={col}
                            type="button"
                            className={`avatar-swatch avatar-color-${col} ${
                              editProfile.avatarColor === col ? 'active' : ''
                            }`}
                            onClick={() =>
                              setEditProfile((prev) => ({ ...prev, avatarColor: col }))
                            }
                            title={`Avatar ${col}`}
                          >
                            {editProfile.avatarColor === col && <IconCheck />}
                          </button>
                        )
                      )}
                    </div>
                  </div>

                  {/* Chave Criptográfica Host */}
                  <div className="form-group crypto-identity-box">
                    <label>CHAVE PÚBLICA CRIPTOGRÁFICA (ED25519)</label>
                    <div className="crypto-key-row">
                      <span className="crypto-key-text">
                        {members[0]?.deviceFingerprint ??
                          'ed25519:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f'}
                      </span>
                      <button
                        type="button"
                        className="btn-copy-fp"
                        onClick={handleCopyFingerprint}
                        title="Copiar chave completa"
                      >
                        {copiedFingerprint ? <IconCheck /> : <IconCopy />}
                        <span>{copiedFingerprint ? 'Copiado' : 'Copiar'}</span>
                      </button>
                    </div>
                    <span className="field-hint">
                      Esta é sua identidade imutável ponto-a-ponto, utilizada para assinatura e handshake E2EE.
                    </span>
                  </div>
                </div>

                {/* Coluna da Direita: Live Preview Discord */}
                <div className="profile-preview-column">
                  <div className="preview-sticky-wrap">
                    <span className="preview-label">PRÉ-VISUALIZAÇÃO EM TEMPO REAL</span>
                    <div className="discord-preview-card">
                      {/* Banner */}
                      <div className={`preview-banner banner-theme-${editProfile.bannerColor}`}>
                        <div className="banner-accent-overlay" />
                      </div>

                      {/* Header com Avatar sobreposto e Badges */}
                      <div className="preview-header-row">
                        <div className={`preview-avatar avatar-color-${editProfile.avatarColor}`}>
                          <span>{editProfile.displayName.charAt(0).toUpperCase() || 'V'}</span>
                          <span className={`status-dot status-dot-large ${editProfile.status}`} />
                        </div>

                        <div className="preview-badges-strip">
                          <span className="preview-badge" title="Host Soberano do Nó Masquerada">
                            🛡️
                          </span>
                          <span className="preview-badge" title="Criptografia Ponta a Ponta Ativa">
                            🔐
                          </span>
                          <span className="preview-badge" title="Membro Masquerada P2P">
                            💎
                          </span>
                        </div>
                      </div>

                      {/* Corpo do Card */}
                      <div className="preview-body">
                        <div className="preview-name-row">
                          <h3 className="preview-display-name">
                            {editProfile.displayName || 'Você'}
                          </h3>
                          <span className="preview-username">
                            @{editProfile.username || 'masquerada.host'}
                          </span>
                        </div>

                        {editProfile.customStatus && (
                          <div className="preview-custom-status">
                            <span className="status-quote-dot" />
                            <span>{editProfile.customStatus}</span>
                          </div>
                        )}

                        <div className="preview-divider" />

                        <div className="preview-section">
                          <span className="preview-section-title">SOBRE MIM</span>
                          <p className="preview-bio">
                            {editProfile.bio || 'Sem biografia informada.'}
                          </p>
                        </div>

                        <div className="preview-divider" />

                        <div className="preview-section">
                          <span className="preview-section-title">NÓ CRIPTOGRÁFICO</span>
                          <div className="preview-p2p-badge">
                            <span className="p2p-radar-dot" />
                            <span>Nó Local Autorizado (Ed25519 E2EE)</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
                <div className="audio-settings-view">
                  <div className="audio-settings-grid">
                    {/* Coluna 1: Dispositivos de Entrada e Saída */}
                    <div className="audio-col-devices">
                      {/* Card: Dispositivo de Entrada */}
                      <div className="settings-section-card audio-config-card">
                        <div className="audio-card-head">
                          <div className="audio-head-title">
                            <span className="audio-icon-wrap input-icon">
                              <IconMic />
                            </span>
                            <div>
                              <h4>DISPOSITIVO DE ENTRADA</h4>
                              <span className="audio-head-sub">Microfone para chamadas e canais de voz</span>
                            </div>
                          </div>
                          <span className="audio-badge input-badge">Entrada</span>
                        </div>

                        <div className="form-group audio-select-group">
                          <select
                            id="audio-input-device-select"
                            className="styled-select"
                            value={selectedInputId}
                            onChange={(e) => void handleInputDeviceChange(e.target.value)}
                          >
                            {audioInputs.length === 0 ? (
                              <option value="">Microfone Padrão do Sistema</option>
                            ) : (
                              audioInputs.map((d, i) => (
                                <option key={d.deviceId || i} value={d.deviceId}>
                                  {d.label || `Microfone ${i + 1}`}
                                </option>
                              ))
                            )}
                          </select>
                        </div>

                        {/* Slider de Volume de Entrada */}
                        <div className="audio-slider-wrap">
                          <div className="slider-header-row">
                            <span className="slider-title">VOLUME DE ENTRADA</span>
                            <span className="slider-val-badge">{inputVolume}%</span>
                          </div>
                          <input
                            type="range"
                            min="0"
                            max="100"
                            value={inputVolume}
                            onChange={(e) => handleInputVolumeChange(Number(e.target.value))}
                            className="styled-range"
                          />
                        </div>
                      </div>

                      {/* Card: Dispositivo de Saída */}
                      <div className="settings-section-card audio-config-card">
                        <div className="audio-card-head">
                          <div className="audio-head-title">
                            <span className="audio-icon-wrap output-icon">
                              <IconHeadphones />
                            </span>
                            <div>
                              <h4>DISPOSITIVO DE SAÍDA</h4>
                              <span className="audio-head-sub">Onde você ouvirá seus amigos e o teste de áudio</span>
                            </div>
                          </div>
                          <span className="audio-badge output-badge">Saída</span>
                        </div>

                        <div className="form-group audio-select-group">
                          <select
                            id="audio-output-device-select"
                            className="styled-select"
                            value={selectedOutputId}
                            onChange={(e) => void handleOutputDeviceChange(e.target.value)}
                          >
                            {audioOutputs.length === 0 ? (
                              <option value="">Dispositivo de Saída Padrão</option>
                            ) : (
                              audioOutputs.map((d, i) => (
                                <option key={d.deviceId || i} value={d.deviceId}>
                                  {d.label || `Alto-falante / Fone ${i + 1}`}
                                </option>
                              ))
                            )}
                          </select>
                        </div>

                        {/* Slider de Volume de Saída */}
                        <div className="audio-slider-wrap">
                          <div className="slider-header-row">
                            <span className="slider-title">VOLUME DE SAÍDA</span>
                            <span className="slider-val-badge">{outputVolume}%</span>
                          </div>
                          <input
                            type="range"
                            min="0"
                            max="100"
                            value={outputVolume}
                            onChange={(e) => handleOutputVolumeChange(Number(e.target.value))}
                            className="styled-range"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Coluna 2: Teste de Microfone & Supressão de Ruído */}
                    <div className="audio-col-test">
                      {/* Card: Testar Microfone ("Ouvir o Microfone") */}
                      <div className="settings-section-card audio-test-card">
                        <div className="test-card-head">
                          <div className="test-head-title">
                            <span className="audio-icon-wrap activity-icon">
                              <IconActivity />
                            </span>
                            <div>
                              <h4>TESTE DE MICROFONE</h4>
                              <span className="audio-head-sub">Verifique seu nível de áudio e retorno local</span>
                            </div>
                          </div>
                          <span className={`test-pulse-pill ${isMicTesting ? 'live' : 'standby'}`}>
                            {isMicTesting ? 'TESTE AO VIVO' : 'STANDBY'}
                          </span>
                        </div>

                        <p className="test-explanation">
                          Está com problemas? Clique no botão ao lado dos seletores para <strong>ouvir o microfone</strong> em tempo real através do dispositivo de saída selecionado.
                        </p>

                        <div className="mic-test-btn-row">
                          <button
                            type="button"
                            className={`btn-mic-test ${isMicTesting ? 'btn-danger' : 'btn-primary'}`}
                            onClick={() => void handleToggleMicTest()}
                          >
                            {isMicTesting ? (
                              <>
                                <span className="pulsing-red-circle" />
                                <span>Parar Teste de Microfone</span>
                              </>
                            ) : (
                              <>
                                <IconMic />
                                <span>Ouvir o Microfone</span>
                              </>
                            )}
                          </button>
                          <span className="test-headphones-tip">
                            🎧 Recomendamos o uso de fones de ouvido para evitar eco durante o teste.
                          </span>
                        </div>

                        {/* VU Meter Visualizer */}
                        <div className="vu-meter-box">
                          <div className="vu-meter-top">
                            <span className="vu-title">MEDIDOR DE ENTRADA (VU METER)</span>
                            <div className="vu-indicator-wrap">
                              {isMicTesting ? (
                                micGateOpen ? (
                                  <span className="vu-badge speaking">
                                    <span className="vu-pulse-dot" /> Som Captado
                                  </span>
                                ) : (
                                  <span className="vu-badge quiet">
                                    🔇 Silêncio / Ruído Cortado
                                  </span>
                                )
                              ) : (
                                <span className="vu-badge idle">
                                  Aguardando início do teste
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="vu-track-bar">
                            {noiseSuppressionEnabled && (
                              <div
                                className="vu-gate-mark"
                                style={{ left: `${Math.min(92, Math.max(6, Math.round(noiseSuppressionLevel * 0.9)))}%` }}
                                title={`Limiar do Noise Gate: ${noiseSuppressionLevel}%`}
                              />
                            )}
                            <div
                              className={`vu-fill-level ${micGateOpen ? 'active-voice' : ''}`}
                              style={{ width: `${isMicTesting ? micTestLevel : 0}%` }}
                            />
                          </div>
                          <div className="vu-scale-ticks">
                            <span>-60 dB</span>
                            <span>-36 dB</span>
                            <span>-18 dB</span>
                            <span>-6 dB</span>
                            <span>0 dB</span>
                          </div>
                        </div>
                      </div>

                      {/* Card: Supressão de Ruído P2P */}
                      <div className="settings-section-card audio-noise-card">
                        <div className="noise-toggle-row">
                          <div className="noise-text-block">
                            <div className="noise-title-line">
                              <span className="audio-icon-wrap shield-icon">
                                <IconShield />
                              </span>
                              <h4>SUPRESSÃO DE RUÍDO P2P</h4>
                            </div>
                            <p className="noise-desc">
                              Ativa filtros de corte de frequências parasitas (85Hz-7500Hz) e gate dinâmico RMS para eliminar chiados, respiração e ruídos de teclado.
                            </p>
                          </div>

                          <label className="switch-toggle" htmlFor="noise-suppression-checkbox">
                            <input
                              id="noise-suppression-checkbox"
                              type="checkbox"
                              checked={noiseSuppressionEnabled}
                              onChange={(e) => handleToggleNoiseSuppression(e.target.checked)}
                            />
                            <span className="slider-round" />
                          </label>
                        </div>

                        {/* Barra / Encaixe de Ajuste Fino (1% a 100%) */}
                        <div className={`noise-slider-box ${!noiseSuppressionEnabled ? 'disabled' : ''}`}>
                          <div className="slider-header-row">
                            <span className="slider-title">INTENSIDADE DO GATE / AJUSTE FINO</span>
                            <span className="slider-val-badge noise-val-badge">
                              {noiseSuppressionLevel}%
                              <span className="noise-level-label">
                                {noiseSuppressionLevel <= 25
                                  ? ' (Suave)'
                                  : noiseSuppressionLevel <= 65
                                  ? ' (Equilibrado)'
                                  : ' (Agressivo)'}
                              </span>
                            </span>
                          </div>
                          <input
                            id="noise-suppression-slider"
                            type="range"
                            min="1"
                            max="100"
                            disabled={!noiseSuppressionEnabled}
                            value={noiseSuppressionLevel}
                            onChange={(e) => handleNoiseSuppressionLevelChange(Number(e.target.value))}
                            className="styled-range noise-range"
                          />
                          <div className="range-subticks">
                            <span>1% (Sensível)</span>
                            <span>50% (Recomendado)</span>
                            <span>100% (Máximo)</span>
                          </div>
                        </div>

                        <div className="noise-pills-row">
                          <span className={`pill-feature ${noiseSuppressionEnabled ? 'enabled' : 'disabled'}`}>
                            {noiseSuppressionEnabled ? '✓ Filtros Passa-Faixa Ativos' : '✕ Filtros Desligados'}
                          </span>
                          <span className={`pill-feature ${noiseSuppressionEnabled ? 'enabled' : 'disabled'}`}>
                            {noiseSuppressionEnabled ? `✓ Gate em ${noiseSuppressionLevel}%` : '✕ Gate Desligado'}
                          </span>
                          <span className="pill-feature local-crypto">
                            🔒 Processamento 100% Local no Navegador
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Rodapé / Ações */}
            <div className="profile-modal-footer">
              <span className="footer-esc-tip">
                {userSettingsTab === 'profile'
                  ? 'Cuidado — você tem alterações não salvas caso cancele!'
                  : 'Configurações de áudio e dispositivos são aplicadas em tempo real.'}
              </span>
              <div className="profile-footer-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={handleCloseProfileModal}
                >
                  {userSettingsTab === 'profile' ? 'Cancelar' : 'Fechar'}
                </button>
                {userSettingsTab === 'profile' && (
                  <button
                    type="button"
                    className={`btn-primary ${profileSavedFeedback ? 'btn-success' : ''}`}
                    onClick={handleSaveProfile}
                  >
                    {profileSavedFeedback ? (
                      <>
                        <IconCheck />
                        <span>Salvo com sucesso!</span>
                      </>
                    ) : (
                      <span>Salvar Alterações</span>
                    )}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal / Banner de Chamada Entrante */}
      {callState === 'INCOMING' && (
        <IncomingCallModal
          participant={callParticipant}
          onAccept={handleAcceptCall}
          onReject={handleRejectCall}
        />
      )}

      {/* Modal Seletor de Compartilhamento de Tela Estilo Discord */}
      <ScreenShareModal
        isOpen={isScreenShareModalOpen}
        onClose={() => setIsScreenShareModalOpen(false)}
        onStartShare={handleStartScreenShare}
      />
    </main>
  )
}
