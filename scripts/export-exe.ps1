# Script PowerShell para exportação do executável Masquerada
param(
    [ValidateSet("portable", "installer", "both")]
    [string]$Target = "portable"
)

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "             MASQUERADA - EXPORTADOR DE EXECUTÁVEL (.EXE)" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command "node" -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js não encontrado. Instale o Node.js em https://nodejs.org antes de continuar."
    exit 1
}

Write-Host "[1/2] Compilando e otimizando código fonte..." -ForegroundColor Yellow
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Falha na compilação do projeto."
    exit $LASTEXITCODE
}

Write-Host "[2/2] Empacotando executável para Windows (Modo: $Target)..." -ForegroundColor Yellow
switch ($Target) {
    "portable" {
        npx electron-builder --win portable
    }
    "installer" {
        npx electron-builder --win nsis
    }
    "both" {
        npx electron-builder --win
    }
}

if ($LASTEXITCODE -ne 0) {
    Write-Error "Falha durante o empacotamento com electron-builder."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host " SUCESSO! Executável gerado na pasta 'dist'." -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""

Start-Process explorer.exe -ArgumentList "dist"
