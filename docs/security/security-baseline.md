# Security baseline

Regras obrigatórias para mudanças futuras:

- Manter TypeScript em modo `strict` e lint/testes sem erros.
- Manter o renderer com `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` e `webSecurity: true`.
- Não expor Node.js, Electron, filesystem, processos ou secrets diretamente ao renderer.
- Manter CSP restritiva; não liberar `unsafe-eval` ou `unsafe-inline` sem revisão documentada.
- Preload e IPC futuros devem expor operações específicas por allowlist, nunca primitivas genéricas.
- Validar schema, versão, tamanho e estado em toda trust boundary antes de efeitos colaterais.
- Aplicar autenticação e autorização na camada que controla o recurso, com deny-by-default.
- Nunca confiar em paths externos; canonicalizar e comprovar containment antes do filesystem.
- Definir limites de payload, filas, concorrência, tempo e armazenamento antes de aceitar entrada remota.
- Não manter secrets no código, renderer, mensagens de erro, logs ou telemetria.
- Usar bibliotecas criptográficas consolidadas e protocolos revisados; não criar criptografia própria.
- Aplicar domain separation e APIs semanticamente restritas a toda operação de assinatura.
- Manter dependências mínimas, lockfile versionado e revisão explícita para novos pacotes.
- Atualizar threat model, invariantes e testes quando uma nova fronteira ou capacidade privilegiada for introduzida.
- Port mapping deve permanecer PCP-first. NAT-PMP só pode ser usado após incompatibilidade de versão estritamente correlacionada ou por chamada low-level explícita; timeout e erros semânticos PCP nunca autorizam downgrade.
- Capabilities `PORT_MAPPED_TCP` devem ser runtime-only, vinculadas a listener/lease e protocol-agnostic no wire. Nenhum gateway, epoch ou protocolo de roteador pode ser tratado como identidade ou autoridade.
- Conectividade permanece metadata de routing não confiável até a autenticação criptográfica da expected Server Identity. LAN, mappings, Direct IPv6, STUN, rendezvous e relay nunca concedem identity, membership ou authorization; todos convergem em SecureSession confirmada e uma única decisão do target.
- Toda operation de conectividade deve respeitar failure classification semântica fail-closed, governor global, deadline monotônico hierárquico, network generation e shutdown bounded. Erro desconhecido, resource exhaustion, abort, shutdown ou autorização já iniciada nunca autorizam fallback adicional.
