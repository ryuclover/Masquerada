@echo off
setlocal enabledelayedexpansion
chcp 65001 > nul
cls

echo =====================================================================
echo                 MASQUERADA - EXPORTADOR DE EXECUTAVEL (.EXE)
echo =====================================================================
echo.
echo Este utilitário cria um arquivo .exe pronto para você enviar a amigos
echo ou utilizar em qualquer computador Windows de forma simples e direta.
echo.

where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERRO] O Node.js não foi encontrado no seu sistema.
    echo Por favor, instale o Node.js em: https://nodejs.org
    echo e tente novamente.
    echo.
    pause
    exit /b 1
)

echo Escolha o tipo de operação desejada:
echo.
echo   [1] Portátil (.exe único, abre direto sem instalar - RECOMENDADO)
echo   [2] Instalador (.exe com atalho na Área de Trabalho e Menu Iniciar)
echo   [3] Gerar Ambos (Portátil + Instalador)
echo   [4] Exportar EXE + Atualizar Site de Download e Publicar na Vercel
echo.
set /p TIPO="Digite sua opção (1, 2, 3 ou 4) [Padrão: 1]: "

if "%TIPO%"=="" set TIPO=1
if "%TIPO%"=="1" goto BUILD_PORTABLE
if "%TIPO%"=="2" goto BUILD_INSTALLER
if "%TIPO%"=="3" goto BUILD_BOTH
if "%TIPO%"=="4" goto BUILD_AND_WEBSITE

echo Opção inválida, utilizando a opção 1 (Portátil)...
set TIPO=1
goto BUILD_PORTABLE

:BUILD_PORTABLE
echo.
echo ---------------------------------------------------------------------
echo  [Etapa 1/2] Compilando e otimizando o aplicativo Masquerada...
echo ---------------------------------------------------------------------
call npm run build
if %errorlevel% neq 0 goto ERROR

echo.
echo ---------------------------------------------------------------------
echo  [Etapa 2/2] Gerando executável portátil (Masquerada-Portable.exe)...
echo ---------------------------------------------------------------------
call npx electron-builder --win portable
if %errorlevel% neq 0 goto ERROR
goto FINISH

:BUILD_INSTALLER
echo.
echo ---------------------------------------------------------------------
echo  [Etapa 1/2] Compilando e otimizando o aplicativo Masquerada...
echo ---------------------------------------------------------------------
call npm run build
if %errorlevel% neq 0 goto ERROR

echo.
echo ---------------------------------------------------------------------
echo  [Etapa 2/2] Gerando instalador do Windows (Masquerada-Instalador.exe)...
echo ---------------------------------------------------------------------
call npx electron-builder --win nsis
if %errorlevel% neq 0 goto ERROR
goto FINISH

:BUILD_BOTH
echo.
echo ---------------------------------------------------------------------
echo  [Etapa 1/2] Compilando e otimizando o aplicativo Masquerada...
echo ---------------------------------------------------------------------
call npm run build
if %errorlevel% neq 0 goto ERROR

echo.
echo ---------------------------------------------------------------------
echo  [Etapa 2/2] Gerando executáveis (Portátil e Instalador)...
echo ---------------------------------------------------------------------
call npx electron-builder --win
if %errorlevel% neq 0 goto ERROR
goto FINISH

:BUILD_AND_WEBSITE
echo.
echo ---------------------------------------------------------------------
echo  [Etapa 1/3] Compilando e gerando o executável portátil...
echo ---------------------------------------------------------------------
call npm run build
if %errorlevel% neq 0 goto ERROR
call npx electron-builder --win portable
if %errorlevel% neq 0 goto ERROR

echo.
echo ---------------------------------------------------------------------
echo  [Etapa 2/3] Sincronizando executável e versão com o site...
echo ---------------------------------------------------------------------
call npm run site:sync

echo.
echo ---------------------------------------------------------------------
echo  [Etapa 3/3] Publicação na Vercel
echo ---------------------------------------------------------------------
set /p DEPLOY="Deseja publicar o site na Vercel agora? (S/N) [Padrão: S]: "
if "%DEPLOY%"=="" set DEPLOY=S
if /i "%DEPLOY%"=="S" (
    call npx vercel --prod website
)
goto FINISH

:FINISH
echo.
echo Sincronizando cópia do executável com a pasta de download do site...
call npm run site:sync >nul 2>nul

echo.
echo =====================================================================
echo  SUCESSO! O executável foi gerado com sucesso na pasta "dist".
echo.
echo  Arquivo(s) pronto(s) para download e compartilhamento!
echo  O site oficial em "website/" também foi atualizado.
echo  Abrindo a pasta para você...
echo =====================================================================
explorer.exe dist
echo.
pause
exit /b 0

:ERROR
echo.
echo =====================================================================
echo  [ERRO] Ocorreu uma falha durante o processo.
echo  Verifique as mensagens acima para detalhes.
echo =====================================================================
echo.
pause
exit /b 1
