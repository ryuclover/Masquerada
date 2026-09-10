import { useEffect, useState } from 'react'

declare global {
    interface Window {
    masquerada?: {
      createServer(name: string): Promise<{ localStorageId: string; serverId: string; displayName: string }>
      listServers(): Promise<readonly { localStorageId: string; serverId: string; displayName: string }[]>
      listChannels(id: string): Promise<readonly { channelId: string; name: string; archived: boolean }[]>
      createChannel(id: string, name: string): Promise<{ channelId: string; name: string; archived: boolean }>
      listMessages(id: string, channelId: string): Promise<readonly { sequence: number; content: string; deletedAt: number | null }[]>
      sendMessage(id: string, channelId: string, content: string): Promise<unknown>
      listMembers(id: string): Promise<readonly { deviceFingerprint: string }[]>
      listInvites(id: string): Promise<readonly { inviteId: string; status: string; uses: number; maxUses: number }[]>
      createInvite(id: string, maxUses: number): Promise<{ encoded: string }>
    }
  }
}

export default function App(): React.JSX.Element {
  const [server, setServer] = useState<{ localStorageId: string; displayName: string } | undefined>()
  const [servers, setServers] = useState<readonly { localStorageId: string; displayName: string }[]>([])
  const [channels, setChannels] = useState<readonly { channelId: string; name: string; archived: boolean }[]>([])
  const [selectedChannel, setSelectedChannel] = useState<string>()
  const [messages, setMessages] = useState<readonly { sequence: number; content: string; deletedAt: number | null }[]>([])
  const [draft, setDraft] = useState('')
  const [serverName, setServerName] = useState('Meu servidor')
  const [channelName, setChannelName] = useState('Geral')
  const [members, setMembers] = useState<readonly { deviceFingerprint: string }[]>([])
  const [invites, setInvites] = useState<readonly { inviteId: string; status: string; uses: number; maxUses: number }[]>([])
  const [inviteCode, setInviteCode] = useState('')
  const [panel, setPanel] = useState<'members' | 'invites'>('members')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const api = typeof window === 'undefined' ? undefined : window.masquerada

  useEffect(() => {
    if (!api) return
    void api.listServers().then((items) => {
      setServers(items)
      if (!server && items[0]) setServer(items[0])
    }).catch(() => setError('Não foi possível abrir os servidores locais.'))
  }, [api, server])

  useEffect(() => {
    if (!server || !api) return
    void api.listChannels(server.localStorageId).then((items) => {
      setChannels(items)
      if (!selectedChannel && items[0]) setSelectedChannel(items[0].channelId)
    }).catch(() => setError('Não foi possível carregar os canais.'))
    void api.listMembers(server.localStorageId).then(setMembers).catch(() => setError('Não foi possível carregar os membros.'))
    void api.listInvites(server.localStorageId).then(setInvites).catch(() => setError('Não foi possível carregar os convites.'))
  }, [api, server, selectedChannel])

  useEffect(() => {
    if (!server || !selectedChannel || !api) return
    void api.listMessages(server.localStorageId, selectedChannel).then(setMessages).catch(() => setError('Não foi possível carregar o histórico.'))
  }, [api, selectedChannel, server])

  async function createServer(): Promise<void> {
    if (!api) return
    try {
      setBusy(true); setError(undefined)
      const created = await api.createServer(serverName)
      setServers((items) => [...items, created])
      setServer(created)
    } catch { setError('Não foi possível criar o servidor.') } finally { setBusy(false) }
  }

  async function createChannel(): Promise<void> {
    if (!api || !server) return
    try { setBusy(true); const channel = await api.createChannel(server.localStorageId, channelName); setChannels((current) => [...current, channel]); setSelectedChannel(channel.channelId); setChannelName('') } catch { setError('Não foi possível criar o canal.') } finally { setBusy(false) }
  }

  async function sendMessage(): Promise<void> {
    if (!api || !server || !selectedChannel || !draft.trim()) return
    try { setBusy(true); setError(undefined); await api.sendMessage(server.localStorageId, selectedChannel, draft.trim()); setDraft(''); setMessages(await api.listMessages(server.localStorageId, selectedChannel)) } catch { setError('Mensagem não enviada. Ela continua localmente disponível para nova tentativa.') } finally { setBusy(false) }
  }

  async function generateInvite(): Promise<void> {
    if (!api || !server) return
    try { const result = await api.createInvite(server.localStorageId, 1); setInviteCode(result.encoded); setInvites(await api.listInvites(server.localStorageId)) } catch { setError('Não foi possível gerar o convite.') }
  }

  return (
    <main className="app-shell">
      <header className="topbar"><strong>MASQUERADA</strong><span>{server ? server.displayName : 'Offline local'}</span></header>
      {!server ? (
        <section className="onboarding panel">
          <p className="eyebrow">PRIVATE / LOCAL-FIRST</p>
          <h1>Converse sem abrir mão do controle.</h1>
          <p>Crie seu primeiro espaço local. A identidade fica neste dispositivo e a rede só começa quando você decidir.</p>
          <label>Nome do servidor<input value={serverName} onChange={(event) => setServerName(event.target.value)} /></label>
          <button disabled={busy || !serverName.trim()} onClick={() => void createServer()}>{busy ? 'Criando...' : 'Criar servidor'}</button>
        </section>
      ) : (
        <section className="workspace">
          <aside className="sidebar panel" aria-label="Navegação do servidor">
            <div className="server-switcher">{servers.map((item) => <button key={item.localStorageId} className={item.localStorageId === server.localStorageId ? 'server-chip active' : 'server-chip'} onClick={() => setServer(item)} title={item.displayName}>{item.displayName.slice(0, 1).toUpperCase()}</button>)}<button className="server-chip add" onClick={() => setServer(undefined)} aria-label="Criar outro servidor">+</button></div>
            <div className="section-heading"><span>Canais</span><button className="icon-button" onClick={() => void createChannel()}>+</button></div>
            {channels.map((channel) => <button className={channel.channelId === selectedChannel ? 'channel selected' : 'channel'} key={channel.channelId} onClick={() => setSelectedChannel(channel.channelId)}># {channel.name}</button>)}
            <input className="compact-input" value={channelName} onChange={(event) => setChannelName(event.target.value)} placeholder="novo canal" aria-label="Nome do novo canal" />
            <div className="sidebar-tools"><button className={panel === 'members' ? 'tool active' : 'tool'} onClick={() => setPanel('members')}>Membros <span>{members.length}</span></button><button className={panel === 'invites' ? 'tool active' : 'tool'} onClick={() => setPanel('invites')}>Convites <span>{invites.length}</span></button></div>
            {panel === 'members' ? <div className="people-list">{members.map((member) => <div className="person" key={member.deviceFingerprint}><span className="avatar small">M</span><span title={member.deviceFingerprint}>membro<br /><small>{member.deviceFingerprint.slice(0, 18)}...</small></span></div>)}</div> : <div className="invite-panel"><button onClick={() => void generateInvite()}>Gerar convite</button>{inviteCode && <textarea readOnly value={inviteCode} aria-label="Convite gerado" />}{invites.map((invite) => <small key={invite.inviteId}>{invite.status} · {invite.uses}/{invite.maxUses}</small>)}</div>}
          </aside>
          <section className="conversation panel">
            <div className="conversation-header"><div><p className="eyebrow">CHANNEL</p><h2>{channels.find((channel) => channel.channelId === selectedChannel)?.name ?? 'Selecione um canal'}</h2></div><span className="connection-dot">● conectado</span></div>
            <div className="timeline">{messages.map((message) => <article className={message.deletedAt ? 'message deleted' : 'message'} key={message.sequence}><span className="avatar">M</span><div><div className="message-meta">membro <small>#{message.sequence}</small></div><p>{message.deletedAt ? 'Mensagem removida' : message.content}</p></div></article>)}</div>
            {error && <div className="error-banner" role="alert">{error}<button onClick={() => setError(undefined)} aria-label="Fechar aviso">×</button></div>}
            <div className="composer"><textarea disabled={busy} value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void sendMessage() } }} placeholder="Escreva uma mensagem..." aria-label="Mensagem" /><button disabled={busy || !draft.trim()} onClick={() => void sendMessage()}>{busy ? '...' : 'Enviar'}</button></div>
          </section>
        </section>
      )}
    </main>
  )
}

