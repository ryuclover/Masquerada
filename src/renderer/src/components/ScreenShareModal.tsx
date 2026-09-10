import React, { useEffect, useState } from 'react'
import type { DesktopSource } from '../../../preload/index'
import type {
  ScreenShareFps,
  ScreenShareOptimization,
  ScreenShareOptions,
  ScreenShareResolution
} from '../voice/voice-types'

interface ScreenShareModalProps {
  isOpen: boolean
  onClose: () => void
  onStartShare: (options: ScreenShareOptions) => Promise<void>
}

export function ScreenShareModal({
  isOpen,
  onClose,
  onStartShare
}: ScreenShareModalProps): React.JSX.Element | null {
  const [sources, setSources] = useState<readonly DesktopSource[]>([])
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'screens' | 'windows'>('screens')
  const [isLoadingSources, setIsLoadingSources] = useState(false)

  // Opções de Qualidade e Desempenho
  const [resolution, setResolution] = useState<ScreenShareResolution>('1080p')
  const [frameRate, setFrameRate] = useState<ScreenShareFps>(30)
  const [optimization, setOptimization] = useState<ScreenShareOptimization>('detail')
  const [withAudio, setWithAudio] = useState(false)
  const [isStarting, setIsStarting] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const masqueradaApi = typeof window !== 'undefined'
    ? (window.masquerada as (typeof window.masquerada & {
        getDesktopSources?: (options: { types: string[]; thumbnailSize?: { width: number; height: number } }) => Promise<readonly DesktopSource[]>
      }) | undefined)
    : undefined
  const hasElectronApi = Boolean(masqueradaApi?.getDesktopSources)

  useEffect(() => {
    if (!isOpen) {
      setSelectedSourceId(null)
      setErrorMsg(null)
      setIsStarting(false)
      return
    }

    if (hasElectronApi && masqueradaApi?.getDesktopSources) {
      setIsLoadingSources(true)
      masqueradaApi
        .getDesktopSources({ types: ['screen', 'window'], thumbnailSize: { width: 360, height: 200 } })
        .then((fetched: readonly DesktopSource[]) => {
          setSources(fetched)
          const firstScreen = fetched.find((s: DesktopSource) => s.id.startsWith('screen:'))
          if (firstScreen) {
            setSelectedSourceId(firstScreen.id)
            setActiveTab('screens')
          } else if (fetched.length > 0 && fetched[0]) {
            setSelectedSourceId(fetched[0].id)
            setActiveTab('windows')
          }
        })
        .catch((err: unknown) => {
          console.warn('Erro ao carregar fontes de tela do Electron:', err)
        })
        .finally(() => {
          setIsLoadingSources(false)
        })
    }
  }, [isOpen, hasElectronApi, masqueradaApi])

  if (!isOpen) return null

  const screens = sources.filter((s) => s.id.startsWith('screen:'))
  const windows = sources.filter((s) => s.id.startsWith('window:'))
  const currentList = activeTab === 'screens' ? screens : windows

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()
    setIsStarting(true)
    setErrorMsg(null)

    try {
      await onStartShare({
        resolution,
        frameRate,
        optimization,
        sourceId: selectedSourceId ?? undefined,
        withAudio
      })
      onClose()
    } catch (err: unknown) {
      console.warn('Falha ao iniciar compartilhamento de tela:', err)
      const errorText =
        err instanceof Error
          ? err.message === 'Permission denied' || err.name === 'NotAllowedError'
            ? 'Compartilhamento cancelado pelo usuário.'
            : err.message
          : 'Não foi possível capturar a tela.'
      setErrorMsg(errorText)
    } finally {
      setIsStarting(false)
    }
  }

  return (
    <div className="screen-share-modal-backdrop" onClick={onClose}>
      <div
        className="modal-content screen-share-modal-container"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="screen-share-title-group">
            <span className="screen-share-icon-title">🖥️</span>
            <div>
              <h3>Compartilhar sua Tela</h3>
              <p className="screen-share-sub">Transmissão P2P com nitidez cristalina e baixa latência</p>
            </div>
          </div>
          <button className="modal-close" onClick={onClose} aria-label="Fechar" title="Fechar">
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="screen-share-body">
          {errorMsg && <div className="screen-share-error-banner">⚠️ {errorMsg}</div>}

          {/* Seleção de Fonte (quando no Electron) */}
          {hasElectronApi && (
            <div className="screen-share-source-picker">
              <div className="screen-share-tabs">
                <button
                  type="button"
                  className={`screen-share-tab ${activeTab === 'screens' ? 'active' : ''}`}
                  onClick={() => {
                    setActiveTab('screens')
                    if (screens.length > 0 && screens[0] && (!selectedSourceId || !selectedSourceId.startsWith('screen:'))) {
                      setSelectedSourceId(screens[0].id)
                    }
                  }}
                >
                  🖥️ Telas ({screens.length})
                </button>
                <button
                  type="button"
                  className={`screen-share-tab ${activeTab === 'windows' ? 'active' : ''}`}
                  onClick={() => {
                    setActiveTab('windows')
                    if (windows.length > 0 && windows[0] && (!selectedSourceId || !selectedSourceId.startsWith('window:'))) {
                      setSelectedSourceId(windows[0].id)
                    }
                  }}
                >
                  🪟 Janelas de Aplicativos ({windows.length})
                </button>
              </div>

              {isLoadingSources ? (
                <div className="screen-share-loading">
                  <div className="spinner" />
                  <span>Localizando telas e janelas disponíveis...</span>
                </div>
              ) : currentList.length === 0 ? (
                <div className="screen-share-empty">
                  <span>Nenhuma {activeTab === 'screens' ? 'tela' : 'janela'} encontrada.</span>
                </div>
              ) : (
                <div className="screen-share-source-grid">
                  {currentList.map((source) => {
                    const isSelected = selectedSourceId === source.id
                    return (
                      <div
                        key={source.id}
                        className={`screen-source-card ${isSelected ? 'selected' : ''}`}
                        onClick={() => setSelectedSourceId(source.id)}
                      >
                        <div className="screen-source-thumb-wrapper">
                          <img
                            src={source.thumbnail}
                            alt={source.name}
                            className="screen-source-thumb"
                          />
                          {source.appIcon && (
                            <img src={source.appIcon} alt="App" className="screen-source-app-icon" />
                          )}
                          {isSelected && <span className="screen-source-checkmark">✓</span>}
                        </div>
                        <span className="screen-source-name" title={source.name}>
                          {source.name}
                        </span>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* Banner explicativo quando no Navegador Web */}
          {!hasElectronApi && (
            <div className="screen-share-browser-notice">
              <div className="browser-notice-icon">🌐</div>
              <div className="browser-notice-text">
                <strong>Captura via Navegador / Sistema</strong>
                <p>
                  Ao clicar em <em>Iniciar Compartilhamento</em>, o diálogo nativo do sistema
                  permitirá escolher entre tela cheia, janela ou aba do navegador.
                </p>
              </div>
            </div>
          )}

          {/* Painel de Qualidade e Presets Otimizados */}
          <div className="screen-share-presets-section">
            <h4 className="presets-title">⚙️ Presets de Qualidade & Otimização de Imagem</h4>

            <div className="presets-grid">
              {/* Resolução */}
              <div className="preset-control-group">
                <label>Resolução</label>
                <div className="preset-pill-group">
                  <button
                    type="button"
                    className={`preset-pill ${resolution === '720p' ? 'active' : ''}`}
                    onClick={() => setResolution('720p')}
                  >
                    720p
                    <small>Econômico</small>
                  </button>
                  <button
                    type="button"
                    className={`preset-pill ${resolution === '1080p' ? 'active' : ''}`}
                    onClick={() => setResolution('1080p')}
                  >
                    1080p
                    <small>FHD Recomendado</small>
                  </button>
                  <button
                    type="button"
                    className={`preset-pill ${resolution === 'source' ? 'active' : ''}`}
                    onClick={() => setResolution('source')}
                  >
                    Fonte
                    <small>4K / Nativo</small>
                  </button>
                </div>
              </div>

              {/* Taxa de Quadros (FPS) */}
              <div className="preset-control-group">
                <label>Taxa de Quadros</label>
                <div className="preset-pill-group">
                  <button
                    type="button"
                    className={`preset-pill ${frameRate === 15 ? 'active' : ''}`}
                    onClick={() => setFrameRate(15)}
                  >
                    15 FPS
                    <small>Texto / Docs</small>
                  </button>
                  <button
                    type="button"
                    className={`preset-pill ${frameRate === 30 ? 'active' : ''}`}
                    onClick={() => setFrameRate(30)}
                  >
                    30 FPS
                    <small>Balanceado</small>
                  </button>
                  <button
                    type="button"
                    className={`preset-pill ${frameRate === 60 ? 'active' : ''}`}
                    onClick={() => setFrameRate(60)}
                  >
                    60 FPS
                    <small>Ultra Fluido</small>
                  </button>
                </div>
              </div>
            </div>

            {/* Otimização de Conteúdo (Texto vs Vídeo) */}
            <div className="preset-optimization-box">
              <label className="opt-label">Modo de Otimização do Codec</label>
              <div className="opt-toggle-cards">
                <div
                  className={`opt-card ${optimization === 'detail' ? 'selected' : ''}`}
                  onClick={() => setOptimization('detail')}
                >
                  <div className="opt-card-header">
                    <span className="opt-card-icon">📝</span>
                    <strong>Texto & Código (Nitidez Prioritária)</strong>
                  </div>
                  <p>
                    Preserva nitidez em terminais, IDEs e documentos sem pixelização, reduzindo framerate
                    se a rede oscilar.
                  </p>
                </div>

                <div
                  className={`opt-card ${optimization === 'motion' ? 'selected' : ''}`}
                  onClick={() => setOptimization('motion')}
                >
                  <div className="opt-card-header">
                    <span className="opt-card-icon">🎮</span>
                    <strong>Vídeos & Jogos (Movimento Fluido)</strong>
                  </div>
                  <p>
                    Mantém alta taxa de quadros e baixa latência de resposta, ideal para animações e reprodução de vídeos.
                  </p>
                </div>
              </div>
            </div>

            {/* Áudio do Sistema */}
            <div className="screen-share-audio-toggle">
              <label className="audio-toggle-label">
                <input
                  type="checkbox"
                  checked={withAudio}
                  onChange={(e) => setWithAudio(e.target.checked)}
                />
                <span className="audio-toggle-custom" />
                <div className="audio-toggle-text">
                  <strong>Transmitir áudio do computador</strong>
                  <small>Compartilha som do sistema ou aplicativo selecionado</small>
                </div>
              </label>
            </div>
          </div>

          <div className="modal-actions screen-share-actions">
            <button type="button" className="btn-secondary" onClick={onClose} disabled={isStarting}>
              Cancelar
            </button>
            <button
              type="submit"
              className="btn-primary screen-share-submit-btn"
              disabled={isStarting || (hasElectronApi && !selectedSourceId)}
            >
              {isStarting ? (
                <>
                  <span className="btn-spinner" />
                  <span>Iniciando transmissão...</span>
                </>
              ) : (
                <>
                  <span>Transmitir ao Vivo</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
