import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App'
import './styles.css'

export interface Friend {
  friendId: string
  displayName: string
  deviceFingerprint: string
  connectionType: 'direct' | 'relay' | 'lan'
  status: 'online' | 'idle' | 'offline'
  customStatus?: string
}

// Mock para navegação em navegador web comum (fora do Electron)
if (typeof window !== 'undefined' && !window.masquerada) {
  const mockServers: { localStorageId: string; serverId: string; displayName: string }[] = [
    { localStorageId: 'srv-masquerada', serverId: 'server-id-local-01', displayName: 'Masquerada Core' }
  ]
  const mockChannels: { channelId: string; name: string; archived: boolean; type?: 'text' | 'voice' }[] = [
    { channelId: 'chan-geral', name: 'geral', archived: false, type: 'text' },
    { channelId: 'chan-dev', name: 'desenvolvimento', archived: false, type: 'text' },
    { channelId: 'chan-p2p', name: 'rede-p2p', archived: false, type: 'text' },
    { channelId: 'chan-voice-geral', name: 'voz-geral', archived: false, type: 'voice' },
    { channelId: 'chan-voice-reuniao', name: 'voz-reuniao', archived: false, type: 'voice' }
  ]

  // Histórico de mensagens isolado estritamente por canal
  const mockMessagesByChannel: Record<string, { sequence: number; content: string; deletedAt: number | null }[]> = {
    'chan-geral': [
      { sequence: 1, content: 'Boas-vindas ao canal #geral do Masquerada!', deletedAt: null },
      { sequence: 2, content: 'Este canal é aberto para todos os membros do servidor.', deletedAt: null }
    ],
    'chan-dev': [
      { sequence: 1, content: 'Canal #desenvolvimento ativo.', deletedAt: null },
      { sequence: 2, content: 'Discussões de código, criptografia Ed25519 e protocolos P2P.', deletedAt: null }
    ],
    'chan-p2p': [
      { sequence: 1, content: 'Canal #rede-p2p: monitoramento de topologia e STUN.', deletedAt: null },
      { sequence: 2, content: 'Rendezvous WAN e relays operando com zero-trust.', deletedAt: null }
    ]
  }

  const mockMembers: { deviceFingerprint: string }[] = [
    { deviceFingerprint: 'ed25519:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f' }
  ]
  const mockInvites: { inviteId: string; status: string; uses: number; maxUses: number }[] = [
    { inviteId: 'inv-8910', status: 'ACTIVE', uses: 0, maxUses: 5 }
  ]

  // Lista de Amigos / Conexões P2P vazia para o usuário adicionar seus próprios amigos reais
  const mockFriends: Friend[] = []

  // Mensagens diretas (DMs) isoladas por amigo (inicia vazio)
  const mockDirectMessages: Record<string, { sequence: number; author: string; content: string; time: string }[]> = {}

  window.masquerada = {
    listServers: async () => [...mockServers],
    createServer: async (name: string) => {
      const created = { localStorageId: `srv-${Date.now()}`, serverId: `server-${Date.now()}`, displayName: name }
      mockServers.push(created)
      return created
    },
    listChannels: async () => [...mockChannels],
    createChannel: async (_id: string, name: string, type: 'text' | 'voice' = 'text') => {
      const finalName = type === 'voice' && !name.startsWith('voz-') ? `voz-${name}` : name
      const created = { channelId: `chan-${Date.now()}`, name: finalName, archived: false, type }
      mockChannels.push(created)
      if (type === 'text') {
        mockMessagesByChannel[created.channelId] = []
      }
      return created
    },
    // Isolamento estrito por canal: retorna exclusivamente as mensagens do canal solicitado
    listMessages: async (_storageId: string, channelId: string) => {
      return [...(mockMessagesByChannel[channelId] ?? [])]
    },
    // Envia mensagem armazenando na lista do canal correspondente
    sendMessage: async (_storageId: string, channelId: string, content: string) => {
      if (!mockMessagesByChannel[channelId]) {
        mockMessagesByChannel[channelId] = []
      }
      const list = mockMessagesByChannel[channelId]
      list.push({ sequence: list.length + 1, content, deletedAt: null })
      return {}
    },
    listMembers: async () => [...mockMembers],
    listInvites: async () => [...mockInvites],
    createInvite: async () => {
      const token = 'MQR1.eyJzZXJ2ZXIiOiJNYXNxdWVyYWRhIENvcmUiLCJleHAiOjE3NzQ5MjAwMDB9.dHJ1c3RlZF9lZDI1NTE5X3NpZ25hdHVyZV9leGFtcGxl'
      mockInvites.push({ inviteId: `inv-${Date.now()}`, status: 'ACTIVE', uses: 0, maxUses: 1 })
      return { encoded: token }
    },
    // Métodos para tela de Amigos e Conexões Diretas
    listFriends: async () => [...mockFriends],
    addFriend: async (target: string) => {
      const isFp = target.startsWith('ed25519:')
      const created: Friend = {
        friendId: `friend-${Date.now()}`,
        displayName: isFp ? `Peer ${target.slice(8, 14)}` : target.trim(),
        deviceFingerprint: isFp ? target : `ed25519:${Math.random().toString(16).slice(2, 18)}`,
        connectionType: 'direct',
        status: 'online',
        customStatus: 'Conexão P2P autorizada'
      }
      mockFriends.push(created)
      return created
    },
    listDirectMessages: async (friendId: string) => {
      return [...(mockDirectMessages[friendId] ?? [])]
    },
    sendDirectMessage: async (friendId: string, content: string) => {
      if (!mockDirectMessages[friendId]) {
        mockDirectMessages[friendId] = []
      }
      const now = new Date()
      const time = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`
      mockDirectMessages[friendId].push({
        sequence: mockDirectMessages[friendId].length + 1,
        author: 'Você',
        content,
        time
      })
      return {}
    }
  }
}

const root = document.getElementById('root')

if (!root) {
  throw new Error('Elemento raiz da aplicação não encontrado.')
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>
)
