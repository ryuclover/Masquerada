# Como Gerar e Usar o Executável (.EXE) do Masquerada

Este guia explica como gerar um arquivo executável (.exe) de fácil compartilhamento para pessoas leigas, amigos e usuários comuns.

---

## 🚀 Método 1: Dois Cliques (O Mais Fácil para Usuários Comuns)

Na pasta raiz do projeto, você encontrará o arquivo:
👉 **`exportar-exe.bat`**

1. Dê um **duplo clique** em `exportar-exe.bat`.
2. Uma janela se abrirá com opções simples:
   - **Opção 1 (Padrão/Recomendado):** Gera o `Masquerada-Portable.exe`.
   - **Opção 2:** Gera o instalador tradicional `Masquerada-Instalador.exe`.
   - **Opção 3:** Gera ambos.
3. Pressione **Enter** (ou digite `1` e pressione Enter).
4. O script fará a compilação e o empacotamento automaticamente.
5. Ao concluir, a pasta **`dist`** se abrirá automaticamente com o executável pronto!

---

## 📦 Qual Executável Enviar para Usuários Comuns?

### 🌟 Recomendado: `Masquerada-Portable.exe`
- **Por que é o melhor para usuários comuns?**
  - Não requer permissão de administrador.
  - Não passa por assistentes de instalação ("Avançar > Avançar > Concluir").
  - A pessoa apenas baixa, dá dois cliques e o programa abre na hora.
  - Perfeito para disponibilizar no Google Drive, Mega, MediaFire, Discord ou pen drive.

### 💼 Alternativa: `Masquerada-Instalador.exe`
- Cria atalho oficial na Área de Trabalho e no Menu Iniciar.
- Ideal para quem prefere ter o aplicativo formalmente instalado no sistema com opção de desinstalação no Painel de Controle.

---

## 💻 Método 2: Via Linha de Comando / Terminal (Para Desenvolvedores)

Se preferir rodar diretamente no terminal do projeto:

```bash
# Gerar apenas o executável portátil (.exe direto):
npm run dist:portable

# Gerar apenas o instalador tradicional:
npm run dist:installer

# Gerar ambos:
npm run dist
```

Ou usando o script PowerShell:
```powershell
.\scripts\export-exe.ps1 -Target portable
```

---

## 📁 Onde os Arquivos Ficam Salvos?

Todos os arquivos compilados ficam salvos na pasta:
```
Masquerada/dist/
├── Masquerada-Portable.exe   <-- Arquivo para enviar
└── Masquerada-Instalador.exe <-- Instalador com atalhos
```

Basta pegar o arquivo `Masquerada-Portable.exe` e disponibilizá-lo para download!
