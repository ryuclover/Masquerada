/**
 * scripts/sync-website-release.js
 * Sincroniza a versão do package.json e o executável recém-compilado de dist/
 * para as pastas website/downloads/ e website/public/downloads/,
 * atualizando o manifesto version.json e assets do site.
 */

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const rootDir = path.resolve(__dirname, '..')
const packageJsonPath = path.join(rootDir, 'package.json')
const distExePath = path.join(rootDir, 'dist', 'Masquerada-Portable.exe')
const websiteDir = path.join(rootDir, 'website')
const websiteDownloadsDir = path.join(websiteDir, 'downloads')
const contentLogoPath = path.join(rootDir, 'content.png')

// 1. Carregar versão do package.json
if (!fs.existsSync(packageJsonPath)) {
  console.error('[ERRO] package.json não encontrado.')
  process.exit(1)
}

const packageData = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'))
const version = packageData.version || '0.1.0'

// 2. Garantir diretórios
const dirsToCreate = [websiteDir, websiteDownloadsDir]
for (const dir of dirsToCreate) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
}

// 3. Copiar logo
if (fs.existsSync(contentLogoPath)) {
  fs.copyFileSync(contentLogoPath, path.join(websiteDir, 'logo.png'))
}

// 4. Copiar e inspecionar executável
let fileSizeBytes = 0
let fileSizeFormatted = '~97 MB'
let sha256 = ''
const fileName = 'Masquerada-Portable.exe'

if (fs.existsSync(distExePath)) {
  console.log(`[1/3] Copiando executável de dist/ para website/downloads/...`)
  const target1 = path.join(websiteDownloadsDir, fileName)
  
  fs.copyFileSync(distExePath, target1)

  const stats = fs.statSync(target1)
  fileSizeBytes = stats.size
  fileSizeFormatted = `${(fileSizeBytes / (1024 * 1024)).toFixed(1)} MB`

  console.log(`[2/3] Calculando checksum SHA-256...`)
  const fileBuffer = fs.readFileSync(target1)
  sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex')
} else {
  console.warn(`[AVISO] dist/${fileName} não encontrado. Execute 'npm run dist:portable' antes para gerar o binário real.`)
}

// 5. Atualizar version.json
const now = new Date().toISOString().split('T')[0]
const versionPayload = {
  version,
  productName: 'Masquerada',
  releaseDate: now,
  fileName,
  fileSizeBytes,
  fileSizeFormatted,
  sha256,
  downloadUrl: `downloads/${fileName}`,
  mirrorUrl: '',
  systemRequirements: {
    os: 'Windows 10 / 11 (64-bit)',
    architecture: 'x64',
    ram: '512 MB livre',
    disk: '200 MB livre'
  },
  highlights: [
    'Comunicação P2P direta sem servidores intermediários',
    'Canais de voz com supressão de ruído calibrável de 1% a 100%',
    'Compartilhamento de tela em 1080p e 60 FPS com foco em nitidez de código',
    'Executável portátil sem necessidade de instalação'
  ]
}

const payloadStr = JSON.stringify(versionPayload, null, 2)
fs.writeFileSync(path.join(websiteDir, 'version.json'), payloadStr, 'utf-8')

console.log(`[3/3] Manifesto version.json atualizado com sucesso! (Versão: v${version}, Tamanho: ${fileSizeFormatted})`)
console.log(`Pronto para deploy na Vercel com 'npx vercel --prod website'.`)
