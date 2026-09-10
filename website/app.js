/**
 * website/app.js
 * Gerenciamento dinâmico de versão e download do Masquerada
 */

document.addEventListener('DOMContentLoaded', () => {
  const navVersionBadge = document.getElementById('navVersionBadge')
  const downloadSubtitle = document.getElementById('downloadSubtitle')
  const fileSizeDisplay = document.getElementById('fileSizeDisplay')
  const sha256Display = document.getElementById('sha256Display')
  const footerVersion = document.getElementById('footerVersion')
  const previewVersionText = document.querySelector('.preview-version-text')
  const primaryDownloadBtn = document.getElementById('primaryDownloadBtn')
  const downloadFeedbackBanner = document.getElementById('downloadFeedbackBanner')
  const btnCopyHash = document.getElementById('btnCopyHash')
  const copyFeedback = document.getElementById('copyFeedback')

  let currentSha256 = ''

  // 1. Carregar manifesto dinâmico version.json
  async function loadVersionManifest() {
    try {
      const response = await fetch('version.json?t=' + Date.now())
      if (!response.ok) throw new Error('Não foi possível carregar version.json')

      const data = await response.json()
      applyVersionData(data)
    } catch (err) {
      console.warn('Aviso ao carregar version.json dinâmico, aplicando fallback local:', err)
      applyVersionData({
        version: '0.1.0',
        fileName: 'Masquerada-Windows-x64.zip',
        fileSizeFormatted: '153 MB',
        sha256: '421e966b94ca53c830d6bbd1f1acc42c890b5140d089d649941e37d8fe548a37',
        downloadUrl: 'https://github.com/ryuclover/Masquerada/releases/download/v0.1.0/Masquerada-Windows-x64.zip'
      })
    }
  }

  function applyVersionData(data) {
    const versionStr = `v${data.version || '0.1.0'}`
    const sizeStr = data.fileSizeFormatted || '153 MB'

    if (navVersionBadge) navVersionBadge.textContent = versionStr
    if (footerVersion) footerVersion.textContent = versionStr
    if (previewVersionText) previewVersionText.textContent = data.version || '0.1.0'
    if (fileSizeDisplay) fileSizeDisplay.textContent = sizeStr

    if (downloadSubtitle) {
      downloadSubtitle.textContent = `${versionStr} • 64-bit • ${sizeStr} • Pacote .ZIP (Pronto para Uso)`
    }

    if (primaryDownloadBtn) {
      const targetUrl = data.downloadUrl || 'downloads/Masquerada-Portable.exe'
      primaryDownloadBtn.setAttribute('href', targetUrl)
      if (data.fileName) {
        primaryDownloadBtn.setAttribute('download', data.fileName)
      }
    }

    if (sha256Display && data.sha256) {
      currentSha256 = data.sha256
      sha256Display.textContent = data.sha256
    }
  }

  // 2. Feedback ao clicar em download
  if (primaryDownloadBtn) {
    primaryDownloadBtn.addEventListener('click', () => {
      setTimeout(() => {
        if (downloadFeedbackBanner) {
          downloadFeedbackBanner.classList.add('visible')
        }
      }, 300)
    })
  }

  // 3. Copiar SHA-256 para a área de transferência
  if (btnCopyHash) {
    btnCopyHash.addEventListener('click', async () => {
      if (!currentSha256) return
      try {
        await navigator.clipboard.writeText(currentSha256)
        if (copyFeedback) copyFeedback.textContent = 'Copiado!'
        setTimeout(() => {
          if (copyFeedback) copyFeedback.textContent = 'Copiar'
        }, 2000)
      } catch {
        // Fallback
      }
    })
  }

  // Inicializar
  loadVersionManifest()
})
