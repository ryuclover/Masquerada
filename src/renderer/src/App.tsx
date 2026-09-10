import { useEffect, useState } from 'react'

declare global {
  interface Window {
    masquerada?: {
      createServer(name: string): Promise<{ localStorageId: string; serverId: string; displayName: string }>
      listChannels(id: string): Promise<readonly { channelId: string; name: string; archived: boolean }[]>
      createChannel(id: string, name: string): Promise<{ channelId: string; name: string; archived: boolean }>
      listMessages(id: string, channelId: string): Promise<readonly { sequence: number; content: string; deletedAt: number | null }[]>
      sendMessage(id: string, channelId: string, content: string): Promise<unknown>
    }
  }
}

export default function App(): React.JSX.Element {
  const [server, setServer] = useState<{ localStorageId: string; displayName: string } | undefined>()
  const [channels, setChannels] = useState<readonly { channelId: string; name: string; archived: boolean }[]>([])
  const [selectedChannel, setSelectedChannel] = useState<string>()
  const [messages, setMessages] = useState<readonly { sequence: number; content: string; deletedAt: number | null }[]>([])
  const [draft, setDraft] = useState('')
  const [serverName, setServerName] = useState('Meu servidor')
  const [channelName, setChannelName] = useState('Geral')
  const api = typeof window === 'undefined' ? undefined : window.masquerada

  useEffect(() => {
    if (!server || !api) return
    void api.listChannels(server.localStorageId).then((items) => {
      setChannels(items)
      if (!selectedChannel && items[0]) setSelectedChannel(items[0].channelId)
    })
  }, [api, server, selectedChannel])

  useEffect(() => {
    if (!server || !selectedChannel || !api) return
    void api.listMessages(server.localStorageId, selectedChannel).then(setMessages)
  }, [api, selectedChannel, server])

  async function createServer(): Promise<void> {
    if (!api) return
    setServer(await api.createServer(serverName))
  }

  async function createChannel(): Promise<void> {
    if (!api || !server) return
    const channel = await api.createChannel(server.localStorageId, channelName)
    setChannels((current) => [...current, channel])
    setSelectedChannel(channel.channelId)
  }

  async function sendMessage(): Promise<void> {
    if (!api || !server || !selectedChannel || !draft.trim()) return
    await api.sendMessage(server.localStorageId, selectedChannel, draft.trim())
    setDraft('')
    setMessages(await api.listMessages(server.localStorageId, selectedChannel))
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
          <button onClick={() => void createServer()}>Criar servidor</button>
        </section>
      ) : (
        <section className="workspace">
          <aside className="sidebar panel">
            <div className="section-heading"><span>Canais</span><button className="icon-button" onClick={() => void createChannel()}>+</button></div>
            {channels.map((channel) => <button className={channel.channelId === selectedChannel ? 'channel selected' : 'channel'} key={channel.channelId} onClick={() => setSelectedChannel(channel.channelId)}># {channel.name}</button>)}
            <input className="compact-input" value={channelName} onChange={(event) => setChannelName(event.target.value)} aria-label="Nome do novo canal" />
          </aside>
          <section className="conversation panel">
            <div className="conversation-header"><div><p className="eyebrow">CHANNEL</p><h2>{channels.find((channel) => channel.channelId === selectedChannel)?.name ?? 'Selecione um canal'}</h2></div><span className="connection-dot">● conectado</span></div>
            <div className="timeline">{messages.map((message) => <article className={message.deletedAt ? 'message deleted' : 'message'} key={message.sequence}><span className="avatar">M</span><div><div className="message-meta">membro <small>#{message.sequence}</small></div><p>{message.deletedAt ? 'Mensagem removida' : message.content}</p></div></article>)}</div>
            <div className="composer"><textarea value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void sendMessage() } }} placeholder="Escreva uma mensagem..." /><button onClick={() => void sendMessage()}>Enviar</button></div>
          </section>
        </section>
      )}
    </main>
  )
}

