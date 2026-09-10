# Threat model

## Escopo e premissas

Este modelo cobre o cliente desktop e a arquitetura local-first/P2P, incluindo a subsystem final de conectividade da Fase 7: TCP/LAN, discovery direcionada, PCP, NAT-PMP, UPnP IGD v1, Direct Global IPv6, STUN opt-in, descriptors/candidate racing, rendezvous, Peer Relay, lifecycle renovável, governor global, network generations e shutdown bounded. Todos os paths preservam Server Identity, SecureSession e autorização única. SQLite permanece no schema v4; IPC de negócio e infraestrutura central obrigatória não existem.

O host é a autoridade do servidor hospedado em sua pasta local. Isso não torna o host, seus arquivos, peers ou infraestrutura de rendezvous confiáveis para o cliente. Um sistema operacional totalmente comprometido está fora do limite de proteção do aplicativo.

## Assets

- Chaves privadas e identidades de usuários e servidores.
- Memberships, permissões e convites.
- Mensagens, arquivos, configurações e demais dados do servidor.
- Streams de voz, vídeo e compartilhamento de tela.
- Metadados de conexão, endereços de rede e topologia P2P.
- Disponibilidade e integridade dos recursos locais do dispositivo.

## Trust boundaries

| Fronteira | Entrada não confiável | Regra de segurança |
| --- | --- | --- |
| Renderer → main process | Toda solicitação originada na UI | O renderer não recebe Node.js nem acesso direto a filesystem, processos ou secrets. IPC futuro deve ser allowlisted, validado e autorizado no main/domínio. |
| Peer remoto → aplicação local | Mensagens, comandos, arquivos, identidade declarada, mídia, telemetria e metadados | Validar schema, versão, tamanho, autenticidade, autorização e replay antes de qualquer efeito ou entrada no domínio. |
| Signaling/rendezvous → cliente | Peers anunciados, candidatos e dados de descoberta | Tratar o serviço como comprometível. Ele auxilia descoberta, mas nunca decide identidade, membership ou permissão. |
| Filesystem → aplicação | Pastas, arquivos, nomes, symlinks e bancos locais | Derivar caminhos somente da raiz controlada e de IDs internos estritos; confirmar containment e estrutura física; rejeitar traversal, links indevidos, corrupção e formatos inválidos antes de reconhecer o conteúdo. |
| Persistência → domínio | Registros de SQLite e configurações | Dados persistidos só viram objetos de domínio após validação e migração explícitas. Falhas fecham a operação. |
| Usuário local/UI → operação privilegiada | Intenção e parâmetros fornecidos pela interface | A camada que controla o recurso valida e autoriza a operação; intenção da UI não equivale a permissão. |
| Default gateway → port mapping client | Respostas PCP/NAT-PMP, external address, port, lifetime e epoch | O gateway é input não confiável. Origem, porta, formato, opcode, correlação, address scope, lease e epoch são validados antes de produzir uma capability runtime. Port mapping não prova identidade, autenticação ou autorização. |
| Gateway UPnP → SSDP/HTTP/XML/SOAP client | Datagrams SSDP, LOCATION, device description, URLBase, controlURL, SOAP responses e leases | Provenance do gateway não implica confiança. Source e formato são bounded; URLs passam por policy SSRF sem DNS/cross-host/redirect; XML proíbe DTD/entidades/XInclude e tem limites estruturais; apenas quatro actions conhecidas podem produzir uma mapping verificada. |
| Backends de mapping → Port Mapping Strategy | Success capabilities, timeouts, incompatibilidade, denials, topology e failures locais | Fallback é uma decisão central, sequencial e allowlisted por tipos/códigos. Unknown errors, denials e topology inválida param fail-closed; fallback nunca equivale a autorização para contornar policy do gateway. |
| Authorized peer channels → Peer Relay | Registration proofs, exact target lookups, circuit control e byte streams opacos | Somente capabilities pós-`MEMBER_CONNECTED` participam. Target prova ao vivo a Server Identity; circuitos são channel-bound e bounded; o relay não resolve destinos, autentica o target, concede membership nem termina a SecureSession interna. |

## Adversaries

1. Peer remoto malicioso.
2. Membro legítimo que abusa das próprias credenciais.
3. Cliente Masquerada modificado.
4. Serviço de signaling/rendezvous comprometido.
5. Atacante de rede capaz de observar, bloquear, repetir ou alterar tráfego.
6. Malware ou processo local com acesso limitado ao usuário/filesystem.
7. Usuário que altera manualmente arquivos, configurações ou banco.
8. Atacante que busca indisponibilidade ou exaustão de recursos.

## Principais ameaças e respostas exigidas

| Ameaça | Exemplos | Resposta arquitetural |
| --- | --- | --- |
| Spoofing | Peer, usuário ou servidor falso | Identidades criptográficas locais já são independentes; autenticação e prova de posse futuras devem permanecer independentes do transporte/signaling. |
| Tampering | Mensagem, permissão, banco ou arquivo alterado | Verificação de integridade/autenticidade e validação antes do domínio. |
| Information disclosure | Vazamento de chaves, mensagens, streams ou IPs | Privilégio mínimo, proteção de secrets, canais autenticados e logs sem dados sensíveis. |
| Privilege escalation | UI ou cliente declara permissões maiores | Autorização deny-by-default na autoridade do recurso, nunca no renderer ou em claims do cliente. |
| Replay | Reenvio de convite ou comando válido | Nonces/identificadores, validade temporal quando aplicável e registro de operações consumidas. |
| Path traversal | `..`, caminho absoluto ou symlink escapa da pasta | Resolução canônica, containment na raiz autorizada e política explícita de links. |
| Malicious files | Conteúdo ativo, nome enganoso ou parser hostil | Tratar arquivo como dado, limitar tamanho/tipo e nunca executar ou abrir implicitamente. |
| IPC abuse | Canal arbitrário, payload forjado ou chamada excessiva | Preload mínimo futuro, allowlist por operação, schemas, autorização e limites. |
| Protocol abuse | Tipo desconhecido, estado inválido ou downgrade | Protocolo versionado, máquina de estados estrita e rejeição de mensagens desconhecidas. |
| Resource exhaustion | Payloads, peers, streams ou filas ilimitadas | Limites de tamanho/quantidade, timeouts, backpressure e cancelamento. |
| Supply-chain compromise | Pacote ou build adulterado | Dependências mínimas, lockfile, auditoria de atualizações e builds reproduzíveis quando viável. |

## Invariantes

- **SEC-001:** o renderer nunca acessa diretamente Node.js, filesystem, processos ou secrets.
- **SEC-002:** conexão estabelecida não autentica um peer; identidade deve ser verificada separadamente.
- **SEC-003:** permissões nunca são aceitas com base em declaração do próprio cliente, renderer ou signaling.
- **SEC-004:** chaves privadas não saem do dispositivo, exceto por uma operação futura de migração explicitamente autorizada e protegida.
- **SEC-005:** nenhum path externo é passado diretamente a APIs de filesystem; o destino deve permanecer na raiz autorizada.
- **SEC-006:** signaling/rendezvous nunca é autoridade de identidade, membership ou permissão.
- **SEC-007:** tipos e versões de mensagem desconhecidos são rejeitados.
- **SEC-008:** falha de validação ou autorização resulta em rejeição, sem fallback permissivo.
- **SEC-009:** dados externos ou persistidos só entram no domínio após validação de schema e invariantes.
- **SEC-010:** entradas, filas e operações custosas possuem limites e cancelamento; nenhuma entrada remota controla recursos sem limite.
- **SEC-011:** conteúdo recebido é tratado como dado e nunca executado ou aberto implicitamente.
- **SEC-012:** operações reutilizáveis sensíveis a replay exigem unicidade/frescor e rejeitam duplicatas.
- **SEC-013:** criptografia utiliza primitivas e protocolos consolidados; o projeto não cria criptografia própria.
- **SEC-014:** assinaturas criptográficas usam domain separation e APIs semanticamente restritas à operação autorizada.
- **SEC-015:** cada servidor possui identidade criptográfica própria, independente da identidade do dispositivo e de seu identificador local de storage.
- **SEC-016:** identidade criptográfica de servidor ausente, perdida ou corrompida nunca é regenerada silenciosamente; a operação falha fechada.
- **SEC-017:** a autoridade inicial de um servidor só é válida quando declarada e assinada pela própria Server Identity sob domain separation específica.
- **SEC-018:** ausência ou corrupção do vínculo de autoridade nunca elege automaticamente outro owner nem produz uma nova declaração.
- **SEC-019:** dados locais de autoridade permanecem não confiáveis até a validação estrutural e criptográfica completa da declaração, das identidades e da assinatura.
- **SEC-020:** banco SQLite carregado do filesystem é considerado não confiável até validação estrutural, de versão e schema.
- **SEC-021:** nenhum consumidor externo recebe capability para executar SQL arbitrário; o acesso a dados é estritamente mediado por operações parametrizadas e semanticamente tipadas.
- **SEC-022:** corrupção ou ausência inesperada do banco de dados do servidor nunca resulta em recriação automática silenciosa; a operação falha fechada.
- **SEC-023:** membership é identificado exclusivamente por Device Identity criptograficamente validada, nunca por nickname, IP ou identificador declarado pelo cliente.
- **SEC-024:** a presença de um membro no SQLite nunca concede autoridade de owner; ownership continua derivado exclusivamente do Initial Owner Binding assinado.
- **SEC-025:** o Initial Owner criptograficamente válido deve existir como membro e corresponder exatamente à mesma Device Identity; inconsistência falha fechada e nunca é reparada automaticamente.
- **SEC-026:** convites são artefatos criptográficos autossuficientes assinados pela Server Identity sob domain separation específica (`Masquerada/server-invite/v1`); sua validade independe de serviços centrais.
- **SEC-027:** a posse de um convite válido concede exclusivamente a capability de solicitar admissão ao servidor sob as condições assinadas; ela não confere status imediato de membro nem altera a autoridade de owner.
- **SEC-028:** a emissão de convites exige autorização comprovada da autoridade do servidor (nesta etapa, o Initial Owner); membros comuns sem autoridade explícita não podem emitir convites válidos.
- **SEC-029:** o bearer secret de um convite não é persistido em plaintext pelo host; apenas material derivado (hash SHA-256) suficiente para validação em tempo constante é armazenado.
- **SEC-030:** uso e revogação de convites são controlados exclusivamente pelo estado local do servidor e nunca por infraestrutura central.
- **SEC-031:** convites single-use/limited-use são consumidos atomicamente; replay após esgotamento ou revogação é rejeitado com fail-closed.
- **SEC-032:** ausência ou corrupção do estado persistido de um convite nunca é reconstruída automaticamente a partir do bearer token.
- **SEC-033:** a admissão de membro exige simultaneamente convite válido e uma Device Identity criptograficamente válida/autenticada; possuir apenas um dos dois não concede membership.
- **SEC-034:** consumo do convite e persistência do novo member são executados em uma única transação atômica; falha em qualquer etapa reverte todas as mudanças.
- **SEC-035:** uma Device Identity já reconhecida como member nunca consome usos adicionais de convite ao tentar nova admissão.
- **SEC-036:** convites jamais concedem ownership, roles ou permissões implícitas; admissão cria exclusivamente membership básica.
- **SEC-037:** todo tráfego P2P futuro é considerado hostil até passar por framing estrutural estrito e pelas validações criptográficas das camadas superiores.
- **SEC-038:** frames com versão, tipo, flags, tamanho ou estrutura desconhecidos são rejeitados fail-closed; o protocolo nunca tenta downgrade ou interpretação permissiva.
- **SEC-039:** o comprimento declarado por um peer nunca controla alocação de memória antes de ser comparado com limites locais explícitos.
- **SEC-040:** após erro estrutural que comprometa a sincronização do stream, o decoder não tenta ressincronização silenciosa.
- **SEC-041:** uma Device Identity remota somente é considerada autenticada após prova Ed25519 válida vinculada a nonces frescos e ao transcript específico do handshake.
- **SEC-042:** uma Server Identity somente é considerada autenticada quando sua chave Ed25519 corresponde ao serverId esperado e produz prova válida vinculada ao handshake atual.
- **SEC-043:** AuthenticatedCandidateDevice é uma capability runtime produzida exclusivamente pelo caminho de autenticação bem-sucedido; objetos crus ou casts TypeScript não concedem essa propriedade.
- **SEC-044:** mensagens, provas ou transcripts de handshakes anteriores não são reutilizáveis em novas negociações devido a nonces CSPRNG, transcript binding e state machines single-use.
- **SEC-045:** bearer secrets de convite nunca são transmitidos antes do estabelecimento de um canal confidencial autenticado.
- **SEC-046:** chaves de sessão são derivadas exclusivamente de X25519 efêmero autenticado e vinculadas ao transcriptHash do handshake mutuamente autenticado.
- **SEC-047:** cada direção de uma SecureSession utiliza key e nonce space criptograficamente distintos; nonce AEAD nunca é reutilizado sob a mesma key.
- **SEC-048:** todo SESSION payload é autenticado e cifrado por AEAD antes de ser tratado como plaintext de aplicação.
- **SEC-049:** sequence numbers são monotônicos e estritos; replay, duplicate, gap ou reorder invalidam a sessão atual.
- **SEC-050:** shared secrets, ephemeral private keys e session keys nunca são persistidos e não são expostos a consumidores da sessão.
- **SEC-051:** bearer secrets de convite permanecem proibidos até a SecureSession concluir autenticação, key agreement e key confirmation.
- **SEC-052:** bearer invites só podem ser apresentados ao host dentro de uma SecureSession completamente estabelecida e protegida por AEAD.
- **SEC-053:** a identidade admitida nunca é declarada pelo ADMISSION_REQUEST; ela é exclusivamente a AuthenticatedCandidateDevice vinculada criptograficamente à SecureSession atual.
- **SEC-054:** SecureSession, authenticated candidate e LocalServer devem pertencer ao mesmo contexto criptográfico/serverId antes que qualquer invite seja consumido.
- **SEC-055:** uma resposta de admissão SUCCESS só pode ser produzida após commit atômico do consumo do convite e persistência do membro.
- **SEC-056:** plaintext autenticado por AEAD continua sendo tratado como input hostil até validação estrutural e semântica da camada de aplicação.
- **SEC-057:** falha ou perda da resposta após commit nunca causa rollback inseguro da membership; retries do mesmo Device não consomem usos adicionais.
- **SEC-058:** uma conexão TCP nunca é tratada como autenticada por endereço, porta ou existência do socket; identidade continua sendo exclusivamente criptográfica.
- **SEC-059:** cada conexão possui decoder, state machines, timers e SecureSession isolados; estado de peers distintos nunca é compartilhado.
- **SEC-060:** peers que excedem limites, violam framing/protocolo ou excedem deadlines de handshake/session/admission são encerrados fail-closed com cleanup completo.
- **SEC-061:** backpressure de socket nunca pode produzir fila de escrita sem limite.
- **SEC-062:** o listener não é iniciado implicitamente no startup normal do aplicativo nesta etapa e usa loopback como bind seguro padrão.
- **SEC-063:** nenhum byte de aplicação recebido por TCP alcança lógica de domínio antes de framing, autenticação, SecureSession e validação da camada correspondente.
- **SEC-110:** NAT-PMP somente opera sobre um `LanTcpServerHandle` IPv4 RFC1918 legítimo e ativo e usa o endereço source e a porta interna reais do listener; o caller não escolhe arbitrariamente o target interno.
- **SEC-111:** PCP permanece preferencial; fallback NAT-PMP somente ocorre após a resposta curta `Version=0, OP=0, Result=1, Epoch`, com exatamente 8 bytes, proveniente do gateway e da porta esperados durante a transaction PCP.
- **SEC-112:** responses NAT-PMP são correlacionadas por gateway/porta source, opcode, internal port e estado serializado; IP do gateway é provenance de roteamento, nunca identidade.
- **SEC-113:** uma mapping NAT-PMP só é advertisable depois de OP0 retornar IPv4 global roteável e OP2 retornar porta TCP e lifetime não zero; RFC1918, CGNAT e special-purpose falham fechados.
- **SEC-114:** `Seconds Since Start of Epoch` NAT-PMP usa a regra própria do RFC 6886 (`previous + floor(7 × elapsed / 8)`, tolerância de 2 segundos) e não reutiliza a fórmula PCP.
- **SEC-115:** mapping NAT-PMP é efêmera, registrada como capability runtime, vinculada ao listener e à lease monotônica e deixa de ser advertisable em expiry, close do listener ou suspeita de state loss.
- **SEC-116:** PCP e NAT-PMP produzem a mesma semântica `PORT_MAPPED_TCP`; protocolo do roteador, gateway, epoch, porta interna e lifetime raw nunca entram no candidate wire nem conferem authority.
- **SEC-117:** estado NAT-PMP não é persistido nem iniciado automaticamente; cada restart exige nova negociação PCP-first.
- **SEC-118:** UPnP IGD somente opera sobre `LanTcpServerHandle` IPv4 RFC1918 legítimo, explicitamente ativo e vinculado à interface; `InternalClient` e `InternalPort` derivam exclusivamente desse listener.
- **SEC-119:** uma resposta SSDP somente origina discovery state após validação bounded do formato, source IP/port do gateway esperado, `ST` exato e `LOCATION` submetido à policy SSRF fail-closed.
- **SEC-120:** `LOCATION`, `URLBase` e `controlURL` nunca provocam DNS resolution, navegação cross-host, redirects, credentials, fragments ou acesso a scheme diferente de HTTP no IPv4 literal do gateway validado.
- **SEC-121:** todo XML UPnP é input não confiável, UTF-8 bounded e processado sem DTD, declarations de entidades, external entities ou XInclude, com limites explícitos de bytes, profundidade, elementos, atributos e texto.
- **SEC-122:** apenas `WANIPConnection:1` ou `WANPPPConnection:1` na cadeia IGD v1 esperada podem fornecer control operations; SCPD/eventing e actions ou `SOAPAction` arbitrárias são proibidos.
- **SEC-123:** sucesso isolado de `AddPortMapping` não cria authority de routing; a mapping só é advertisable após `GetSpecificPortMappingEntry` comprovar client, port, enabled e lease finita aceitável.
- **SEC-124:** mappings UPnP permanentes não são criadas nem aceitas automaticamente; lease finita, deadline monotônica, expiry e lifecycle do listener limitam a validade da capability.
- **SEC-125:** `UpnpActivePortMapping` é capability runtime efêmera e não forjável por literal/cast ou constructor sem token; `LOCATION`, `controlURL`, gateway, service metadata e estado SOAP nunca são persistidos.
- **SEC-126:** PCP, NAT-PMP e UPnP produzem a mesma semântica `PORT_MAPPED_TCP`; protocolo do roteador e metadata de controle nunca integram o signed wire candidate.
- **SEC-127:** toda conexão alcançada por uma mapping UPnP continua exigindo Server Identity authentication, autorização e `SecureSession` completas; UPnP não concede identidade nem authority.
- **SEC-128:** port mapping production é negociado por uma única strategy PCP-first; PCP, NAT-PMP e UPnP nunca são executados paralelamente para o mesmo listener.
- **SEC-129:** fallback somente ocorre para classes de falha explicitamente allowlisted; erros desconhecidos, denial explícito, resource denial e topology inválida falham fechados.
- **SEC-130:** PCP permanece preferencial e NAT-PMP somente é usado após incompatibilidade PCP válida; timeout PCP pode seguir diretamente para UPnP, mas nunca para NAT-PMP.
- **SEC-131:** um `LanTcpServerHandle` possui no máximo uma `ManagedPortMapping` advertisable por strategy, inclusive durante overlap temporário de migration no gateway.
- **SEC-132:** mappings fallback reavaliam PCP apenas no renewal point bounded para permitir protocol upgrade sem polling e sem preferência histórica persistida.
- **SEC-133:** migration somente troca a mapping advertisable depois que a nova runtime capability está completamente criada e validada; a mapping antiga é encerrada best-effort após o switch.
- **SEC-134:** authorization/resource denial ou topology inválida de um protocolo preferencial não são contornados renovando uma mapping fallback já existente.
- **SEC-135:** renewal scheduling possui uma única authority no modo gerenciado; os timers internos de PCP, NAT-PMP e UPnP ficam desabilitados enquanto `ManagedPortMapping` controla o lifecycle.
- **SEC-136:** `ManagedPortMapping` é capability runtime efêmera e não forjável por literal/cast ou constructor sem token; backend preference, attempts, gateway, lease e endpoint não são persistidos.
- **SEC-137:** PCP, NAT-PMP e UPnP permanecem mecanismos exclusivos de reachability; `PORT_MAPPED_TCP` selecionado não recebe authority criptográfica nem metadata do protocolo de origem.
- **SEC-138:** `DIRECT_GLOBAL_TCP` somente pode ser produzido por listener TCP IPv6 global-unicast explicitamente selecionado, atualmente atribuído ao host e bound ao endereço exato com exposição IPv6-only.
- **SEC-139:** wildcards, IPv4, IPv4-mapped IPv6, ULA, link-local, loopback, multicast, documentation e demais endereços não elegíveis nunca originam `ActiveDirectGlobalListener`.
- **SEC-140:** um snapshot de interface/endereço não constitui capability; o endereço é revalidado contra o SO antes e depois do bind e novamente antes de cada novo descriptor.
- **SEC-141:** `ActiveDirectGlobalListener` é capability runtime efêmera e não forjável, vinculada ao listener TCP real e à permanência do endereço global selecionado no host.
- **SEC-142:** remoção ou mudança do endereço selecionado invalida terminalmente a capacidade de anunciar `DIRECT_GLOBAL_TCP` e nunca causa migração silenciosa para outro IPv6 ou interface.
- **SEC-143:** `DIRECT_GLOBAL_TCP` contém exclusivamente endpoint de routing; interface name, scope ID, mecanismo de autoconfiguração e metadata de privacy nunca integram o wire candidate.
- **SEC-144:** um listener Direct Global preserva integralmente limites, framing, handshake, `SecureSession` e authorization da pipeline TCP existente; exposição direta à Internet nunca cria trust shortcut.
- **SEC-145:** `ActiveDirectGlobalListener` prova somente que o host possuía um listener local em IPv6 global validado; não prova reachability externa, rota bidirecional ou ausência de firewall.
- **SEC-146:** Direct Global IPv6 é explicitamente opt-in, efêmero, não persistido e nunca iniciado automaticamente no startup.
- **SEC-147:** STUN é uma primitive opcional de observação de topologia; sua ausência nunca impede o funcionamento básico do Masquerada nem introduz infraestrutura central obrigatória.
- **SEC-148:** toda STUN transaction utiliza target explicitamente fornecido como IP literal, local bind explícito, transaction ID CSPRNG de 96 bits e validação do source endpoint antes de aceitar response.
- **SEC-149:** `ValidatedStunObservation` representa apenas o que o endpoint STUN esperado respondeu em uma transaction correlacionada; ela não autentica o servidor STUN nem garante veracidade ou reachability futura.
- **SEC-150:** `XOR-MAPPED-ADDRESS` observado por STUN UDP jamais é convertido em `PORT_MAPPED_TCP` ou `DIRECT_GLOBAL_TCP`, e sua porta UDP nunca é tratada como external TCP port.
- **SEC-151:** STUN observation nunca integra Server Identity, membership ou authorization e não é aceita pelo signer de `SignedConnectivityDescriptor`.
- **SEC-152:** comparações STUN com `PORT_MAPPED_TCP`/`DIRECT_GLOBAL_TCP` usam somente endereço como topology signal; mismatch não causa authority change, delete ou auto-migration nesta etapa.
- **SEC-153:** nenhum STUN server é hardcoded, descoberto por DNS ou consultado automaticamente no startup; observations são explícitas, efêmeras e não persistidas.
- **SEC-154:** o parser STUN possui limites estritos de datagram, attributes, TLV bounds, transaction correlation e validação de `FINGERPRINT` quando presente; malformed e unknown-required falham fechados.
- **SEC-155:** candidate racing somente opera sobre fontes criptograficamente vinculadas à mesma Server Identity esperada; candidates de identidades distintas nunca são agregados.
- **SEC-156:** `LAN_TCP` somente é dialable com provenance runtime da targeted authenticated LAN discovery e source address coerente; um generic signed descriptor jamais autoriza conexões arbitrárias a private, link-local ou loopback endpoints.
- **SEC-157:** WAN candidates continuam sujeitos a validação type-specific mesmo após assinatura; descriptor signature autentica a declaração, não transforma endpoint proibido em válido.
- **SEC-158:** candidate race utiliza attempts bounded e escalonados; TCP connect isolado nunca constitui sucesso e somente autenticação da Server Identity esperada mais SecureSession confirmada pode selecionar winner.
- **SEC-159:** após existir winner criptográfico, todos os demais attempts são cancelados e qualquer late success é destruído sem authorization.
- **SEC-160:** Admission ou Reconnect ocorre exatamente uma vez e exclusivamente sobre o secure winner; invites e authorization requests nunca são enviados aos loser candidates.
- **SEC-161:** dial ordering, STUN hints e recent-success state são exclusivamente heurísticas locais efêmeras e nunca alteram candidate eligibility, Server Identity, membership ou authorization.
- **SEC-162:** STUN observation do cliente nunca é confundida com endereço do servidor remoto e não cria, remove ou autentica dial targets.
- **SEC-163:** endpoint success history somente é registrado após authenticated SecureSession para a Server Identity correta, possui lifetime e bounds limitados e nunca persiste.
- **SEC-164:** connectivity racing é explicitamente opt-in, não inicia no startup e não modifica ConnectivityDescriptor v1, PortMappingStrategy ou candidate wire semantics.
- **SEC-165:** peer-provided rendezvous somente opera sobre conexão Masquerada já plenamente autorizada; SecureSessions pré-auth nunca podem consultar descriptors.
- **SEC-166:** rendezvous permite exclusivamente lookup exato pelo `serverId` canônico e nunca oferece listagem, wildcard, busca parcial ou enumeração de servers conhecidos.
- **SEC-167:** o peer intermediário somente encaminha bytes do `SignedConnectivityDescriptor` e nunca assina, modifica, renova ou concede autoridade em nome do target Server.
- **SEC-168:** somente descriptors frescos, criptograficamente válidos e compostos exclusivamente por WAN candidates podem ser compartilhados via rendezvous; `LAN_TCP` nunca é propagado por esse mecanismo.
- **SEC-169:** toda response rendezvous é correlacionada à request atual por nonce CSPRNG e `serverId` exato, e o descriptor retornado é integralmente revalidado pelo requester.
- **SEC-170:** caches de rendezvous são efêmeros, bounded, não persistidos e jamais estendem o `expiresAt` assinado pelo Server.
- **SEC-171:** rendezvous peers não recebem inviteSecret, MQR1, Member Certificate ou authorization request do target server; Admission/Reconnect ocorre somente após conexão direta e autenticação do target Server.
- **SEC-172:** rendezvous possui rate limits por conexão e globais, outstanding-request limit, timeout e response-size bounds contra enumeração e amplificação não controladas mesmo por peers autorizados.
- **SEC-173:** descriptor recebido via rendezvous é somente uma nova source para Candidate Aggregation e continua sujeito a WAN validation e cryptographic racing; rendezvous não cria novo candidate type.
- **SEC-174:** peer-provided rendezvous nunca encaminha application payload ou SecureSession bytes para o target Server e, portanto, não constitui relay.
- **SEC-175:** Peer Relay somente conecta duas `AuthorizedPeerChannel` já estabelecidas com o mesmo relay process; o relay nunca recebe nem utiliza IP, hostname ou porta arbitrária como destination.
- **SEC-176:** um target somente se torna relayable após live Ed25519 proof of possession da própria Server Identity, sob `Masquerada/peer-relay-target-registration/v1` e vinculada ao Relay Server, ao authorized channel atual e ao fingerprint autenticado do outer Device.
- **SEC-177:** target registrations são explícitas, efêmeras, bounded, não persistidas e imediatamente invalidadas quando o authorized target channel fecha ou a registration expira.
- **SEC-178:** relay circuits usam circuit IDs CSPRNG imprevisíveis e são vinculados simultaneamente aos requester/target channels; conhecer um circuitId isolado nunca permite takeover.
- **SEC-179:** `RELAY_DATA` é tratado pelo relay exclusivamente como byte stream opaco e bounded; o relay não parseia MQRD interno, não termina a target SecureSession e não obtém application plaintext.
- **SEC-180:** toda conexão através de relay executa integralmente Server Identity authentication, X25519, SecureSession e key confirmation do target; outer relay authorization jamais substitui target authentication.
- **SEC-181:** Admission e Reconnect ocorrem exclusivamente dentro da inner SecureSession requester↔target; MQR1, inviteSecret e target membership data nunca são enviados em plaintext ao relay.
- **SEC-182:** relay possui hard bounds para circuit count, payload size, buffered bytes, byte budget, lifetime, idle timeout, requests pendentes e rates de open/registration/data; resource exhaustion fecha somente circuits afetados de forma bounded.
- **SEC-183:** relay target selection é exact-serverId only e não oferece enumeração, arbitrary destination forwarding, outbound socket creation, DNS, multi-hop ou routing table.
- **SEC-184:** Peer Relay é opt-in, efêmero, não persistido, não iniciado automaticamente e não altera ConnectivityDescriptor v1 nem ConnectivityCandidateType.
- **SEC-185:** a orquestração de conectividade high-level é estritamente direct-first; relay somente é considerado depois de direct candidate reachability falhar ou quando nenhum direct target elegível existe.
- **SEC-186:** uma target Server Identity criptograficamente autenticada que rejeita Admission/Reconnect encerra a connection operation; authorization failure nunca provoca tentativa por outro network path.
- **SEC-187:** rendezvous enrichment é exact-serverId, bounded e sequencial e somente fornece novos signed WAN descriptors para uma tentativa direct adicional; nunca abre relay implicitamente.
- **SEC-188:** relay selection opera exclusivamente sobre AuthorizedPeerChannels explicitamente fornecidos, com número de peers e attempts bounded; relay peers nunca são enumerados ou descobertos por directory.
- **SEC-189:** relay attempts são sequenciais e um path só vence após autenticar a mesma expected Server Identity e estabelecer a inner SecureSession; NOT_AVAILABLE, timeout e wrong-target podem permitir o próximo relay, mas target authorization failure não.
- **SEC-190:** direct, rendezvous e relay phases nunca executam authorization paralelamente e uma connection operation entrega no máximo uma target-authorized connection.
- **SEC-191:** relay success history e rendezvous hints são efêmeros, target-bound e usados somente para ordering; jamais pulam direct-first, target authentication ou current peer eligibility.
- **SEC-192:** relay target registration refresh exige fresh one-shot Server Identity PoP vinculada ao mesmo AuthorizedPeerChannel e só estende disponibilidade após nova prova válida.
- **SEC-193:** relay circuits utilizam renewable bounded leases; cada extensão exige request correlacionada e target registration ainda válida e nunca transforma um circuito em recurso sem prazo ou sem quotas.
- **SEC-194:** relay circuit failure encerra a inner byte stream; recuperação ocorre por nova connection operation e novo handshake/SecureSession, nunca por transplantar uma sessão criptográfica viva para outro transport.
- **SEC-195:** uma conexão relay ativa não provoca probes direct em background nem migração silenciosa quando conectividade direta reaparece; a próxima conexão volta à policy direct-first.
- **SEC-196:** toda orchestration, relay preference, registration manager state e circuit lease state é efêmera, não persistida e nunca iniciada automaticamente no startup.
- **SEC-197:** toda falha de conectividade é classificada por códigos e tipos semânticos; erros desconhecidos nunca são considerados seguros para fallback automático.
- **SEC-198:** uma vez iniciada autorização contra a Server Identity esperada, nenhuma falha de transporte subsequente provoca nova tentativa automática por outro path na mesma operation.
- **SEC-199:** a subsystem mantém hard global resource bounds além dos limites locais de cada protocolo, incluindo connection operations e secure connection attempts, e toda reserva é liberada exatamente uma vez.
- **SEC-200:** mudanças relevantes na configuração local de rede invalidam somente observations e provenances dependentes daquele ambiente; nunca alteram Server Identity, membership ou a validade criptográfica de descriptors assinados ainda frescos.
- **SEC-201:** STUN observations e LAN discovery provenance pertencentes a uma network generation anterior não influenciam novas decisões de routing.
- **SEC-202:** deadlines de connectivity são monotônicos e hierárquicos; operações filhas nunca podem estender o deadline global da connection operation.
- **SEC-203:** shutdown da subsystem bloqueia novas operações, cancela trabalho em voo e encerra recursos de rede de forma bounded e idempotente antes que dependências persistentes necessárias sejam removidas.
- **SEC-204:** nenhum estado de topologia, routing, relay, session, mapping, discovery, observation ou success hint é restaurado após restart; somente security state explicitamente persistente permanece.
- **SEC-205:** para qualquer connection operation, authorization pode ocorrer no máximo uma vez e somente depois de autenticação criptográfica da expected Server Identity e estabelecimento confirmado da SecureSession.
- **SEC-206:** para qualquer connection operation, uma conexão final pode ser entregue no máximo uma vez; late completions de fases anteriores são destruídas e não alteram estado terminal.
- **SEC-207:** resource exhaustion, shutdown, abort e internal invariant failures nunca iniciam fallback adicional como forma de contornar limites locais.
- **SEC-208:** LAN, gateway mappings, Direct Global, STUN, rendezvous e relay continuam separados de authority; todos os network paths convergem obrigatoriamente na mesma Server Identity authentication e target authorization.

## NAT-PMP e fallback PCP-first

O fluxo privilegiado é: listener LAN ativo → default gateway validado → PCP MAP → somente em `Unsupported Version` legado estrito, NAT-PMP OP0 + OP2 → capability runtime → `PORT_MAPPED_TCP` → descriptor assinado → TCP WAN → autenticação completa da Server Identity → SecureSession. NAT-PMP não equivale a identidade, autenticação ou autorização.

Requests NAT-PMP usam UDP source efêmera vinculada exatamente ao IPv4 do listener e são serializadas por gateway. Não existe bind wildcard nem listener de announcements em `224.0.0.1:5350`. A retransmission mantém doubling de 250, 500, 1000 e 2000 ms, mas limita a quatro attempts. Esse é um desvio consciente dos nove attempts e espera final de 64 segundos descritos no RFC 6886: o caminho production normalmente já observou uma resposta explícita de incompatibilidade PCP, e o limite evita retenção prolongada de recursos e UX.

Uma assinatura de `Masquerada/device-auth/v1` prova somente a posse da private key para aquele challenge. Ela não garante freshness sozinha; o autenticador futuro deverá emitir challenges únicos e rejeitar reutilização no contexto da sessão.

## UPnP IGD v1 explícito e restrito

O fluxo privilegiado é: listener LAN ativo → default gateway validado → M-SEARCH SSDP transitório → resposta SSDP não confiável → source/header/`ST` estritos → policy SSRF de `LOCATION` → GET HTTP bounded → XML não confiável sem DTD/entidades/XInclude → hierarquia IGD v1 validada → policy SSRF de `URLBase` e `controlURL` → `GetExternalIPAddress` global → `AddPortMapping` TCP com lease finita → `GetSpecificPortMappingEntry` → capability runtime → `PORT_MAPPED_TCP` → descriptor assinado → TCP WAN → autenticação completa da Server Identity → `SecureSession`. Gateway UPnP não equivale a identidade, autenticação ou autorização.

SSDP usa `239.255.255.250:1900`, TTL 2, bind e multicast interface no IPv4 do listener e janela de 1500 ms; não há daemon, `NOTIFY` ou listener de announcements. HTTP usa `node:http` direto com `localAddress`, timeout de 3000 ms, `Accept-Encoding: identity`, limites separados de 128 KiB para description e 64 KiB para SOAP, sem proxy e sem redirects. HTTP 500 só avança como SOAP Fault bounded.

O parser XML `fast-xml-parser` 5.11.1 está fixado no lockfile e configurado com `processEntities: false`, boolean attributes desabilitados e namespace prefix removido apenas após a validação. Uma barreira anterior rejeita DTD/`DOCTYPE`, declarations de entidades e XInclude; uma passada posterior limita profundidade a 32, elementos a 512, atributos por elemento a 16 e texto total a 64 KiB. Não há entity resolver, I/O de arquivo/rede, SCPD crawling, GENA, SUBSCRIBE ou eventing.

A seleção usa exatamente um `WANIPConnection:1` quando disponível; sem WANIP, usa exatamente um `WANPPPConnection:1`; multiplicidade não resolvida falha fechada. Redirects 3xx, inclusive no mesmo gateway, são deliberadamente proibidos porque alteram provenance e ampliam a superfície de SSRF, embora a arquitetura UPnP permita 307 em cenários de interoperabilidade.

## Port Mapping Strategy e lifecycle unificado

O fluxo production é: `LanTcpServerHandle` explicitamente ativo → gateway resolvido uma vez → PCP preferred → matriz de fallback central → NAT-PMP somente após `PCP_UNSUPPORTED_VERSION`, ou UPnP diretamente após timeout PCP → exatamente uma capability selecionada → `ManagedPortMapping` → `PORT_MAPPED_TCP` → descriptor assinado → WAN não confiável → Server Identity handshake → `SecureSession` → Admission/Reconnect. Fallback não equivale a authorization bypass.

A matriz de creation permite exclusivamente PCP Unsupported → NAT-PMP, PCP timeout → UPnP e NAT-PMP timeout → UPnP. Success para imediatamente. Denial semântico, resource failure, topology inválida, configuração local inválida, abort e erro desconhecido param fail-closed. Um `WeakMap` pelo runtime listener rejeita creation concorrente e uma única operação sequencial pode criar mappings; IP/porta não são usados como chave de authority.

No modo gerenciado, backends são criados com `autoRenew: false`. A `ManagedPortMapping` agenda um único timer aproximadamente na meia-vida, delega expiry à lease atual e reproba PCP no renewal point de NAT-PMP/UPnP. PCP success cria e valida a mapping nova antes do switch atômico; PCP Unsupported permite NAT-PMP quando o current é UPnP; timeouts renovam o backend fallback atual. Denial/resource/topology durante upgrade invalidam a advertisability e fecham o fallback antigo, evitando bypass de policy.

Migration conserva a mapping antiga como única `current` enquanto a nova é criada. Após validação, uma troca síncrona publica apenas a nova e o cleanup antigo ocorre best-effort. Descriptor emitido antes da troca continua sendo snapshot da mapping antiga e limitado pela lease antiga; novos descriptors consultam o endpoint/lease atuais. Close ou listener close abortam a operação em voo, aguardam seu cleanup bounded e fecham current/new mappings de forma idempotente.

## Direct Global IPv6 explícito

O fluxo production é: seleção explícita de um IPv6 → classificação global fail-closed e validação no snapshot atual do SO → bind TCP no endereço canônico exato com `ipv6Only: true` → nova validação pós-bind → capability runtime `ActiveDirectGlobalListener` → revalidação imediata pelo signer → `DIRECT_GLOBAL_TCP` v1 → descriptor assinado → WAN não confiável → autenticação completa da Server Identity → `SecureSession` → Admission/Reconnect. Endereço local global não equivale a reachability proof, identidade ou autorização.

Wildcards, IPv4, IPv4-mapped IPv6, zone identifiers, scopes especiais e atribuições em interface interna são proibidos. Duplicatas na mesma interface são deduplicadas; o mesmo endereço em interfaces distintas é ambíguo e falha fechado. A API nunca auto-seleciona, autoenumera para advertisement, migra entre interfaces ou persiste a escolha. Temporary/privacy status não é inferido heuristicamente: o caller seleciona um endereço atualmente atribuído e novas assinaturas dependem de nova validação.

O listener Direct Global usa `ServerTcpPeerConnection` e conserva os mesmos limites globais/per-source, timeouts, framing, backpressure, handshake, session setup e authorization do transporte existente. Source IPv6 é canonicalizado para resource accounting, IPv4-mapped inbound é rejeitado e nenhuma origem IP concede trust. Não há firewall manipulation, router I/O, STUN, probe externo, self-connect WAN ou integração com `PortMappingStrategy`.

`DIRECT_GLOBAL_TCP` carrega somente `candidateType=0x03`, `family=6`, endereço IPv6 canônico, porta real do socket e scope byte zero. Interface, MAC, prefix, scope ID e metadata de privacy/autoconfiguração não entram no wire. Um descriptor já assinado é snapshot não revogável; remoção posterior do endereço invalida terminalmente a capability e bloqueia novas emissões, enquanto lifetime curto e a autenticação completa limitam o risco do snapshot anterior.

## Observação STUN RFC 8489 opt-in

O fluxo é: target STUN IP literal fornecido explicitamente + endereço local atualmente atribuído → bind UDP exato em porta efêmera → Binding Request RFC 8489 com cookie `0x2112a442`, transaction ID CSPRNG de 96 bits e `FINGERPRINT` → Internet não confiável → validação antecipada do source IP/port → validação bounded de header, cookie, transaction e TLVs → exatamente um `XOR-MAPPED-ADDRESS` → `ValidatedStunObservation` efêmera → comparação topológica opcional. STUN observation não equivale a reachability proof, candidate, identidade, autenticação ou autorização.

Não há hostname, DNS/SRV discovery, redirect por `ALTERNATE-SERVER`, credential challenge, `USERNAME`, `MESSAGE-INTEGRITY`, `SOFTWARE`, TURN, ICE ou STUN por TCP/TLS. O request não carrega serverId, Device Identity, invite, display name ou membership. O `FINGERPRINT` é apenas CRC-32 para discriminação/corrupção, não autenticação contra atacante ativo; mesmo uma response estruturalmente válida do endpoint esperado pode mentir sobre o endereço observado.

Cada call cria uma única transaction e reutiliza transaction ID e bytes idênticos nas retransmissões. A policy envia no máximo quatro vezes aproximadamente em 0, 500, 1500 e 3500 ms e encerra até 7500 ms. Isso reduz deliberadamente o default RFC 8489 de `Rc=7`/`Rm=16` como controle de recursos e latência; não há jitter, busy-loop, aggregation ou refresh periódico nesta etapa.

O parser limita datagram a 2048 bytes e no máximo 32 attributes, exige message length exato e múltiplo de quatro, valida padding/bounds, rejeita comprehension-required desconhecido, XOR/FINGERPRINT duplicado, family/port inválidos e `FINGERPRINT` fora da última posição. Error responses são reduzidas a código bounded; 401/438 não iniciam credentials e 300/`ALTERNATE-SERVER` nunca muda o único target explícito.

Uma observation dura no máximo 30 segundos por relógio monotônico, é runtime-branded, imutável e não persistida. Comparações com port mappings ou Direct Global retornam apenas match/mismatch/incomparable/stale por endereço canônico. A porta observada pertence ao socket UDP STUN e nunca é comparada com a porta TCP de PCP, NAT-PMP, UPnP ou listener global. Mismatch pode indicar double NAT, multihoming, policy routing, egress diferente, estado stale ou servidor STUN mentindo; não altera mapping/listener.

## Candidate aggregation e racing criptográfico

O fluxo é: verified candidate sources → consistência de `serverId` e chave pública esperados → provenance LAN/WAN → eligibility type-specific → canonicalização e dedup por socket endpoint → ordering local determinístico → attempts TCP escalonados e bounded → MQRD → Server Identity esperada → X25519/SecureSession com key confirmation → winner único → cancelamento de losers → uma única Admission ou Reconnect. Um signed candidate é uma declaração autenticada de routing, não permissão para acessar serviços LAN arbitrários; TCP connect também não equivale a candidate success.

`LAN_TCP` genérico em `VerifiedConnectivityDescriptor` permanece metadata e nunca abre socket. A capability de dial LAN somente nasce de targeted authenticated LAN discovery quando nonce, assinaturas, Server Identity, interface local e source UDP correspondem; o candidate anunciado deve usar o mesmo endereço source. Link-local IPv6 adicionalmente exige `scopeId` local daquela interface, e loopback remoto é proibido em production. `PORT_MAPPED_TCP` exige endereço WAN strict-global; `DIRECT_GLOBAL_TCP` exige IPv6 global-unicast canônico sem zone ID. Assinatura válida não pula essa validação semântica.

O primeiro attempt inicia imediatamente, o segundo somente após 250 ms se necessário, fast failure respeita gap mínimo de 100 ms, no máximo dois handshakes coexistem e o deadline global default é 12 segundos. Descriptor expirado não inicia attempt novo; um attempt que iniciou fresh pode terminar depois do expiry porque a autenticação ativa substitui o snapshot de routing. Success exige Server Identity e public key esperadas, transcript válido, SecureSession real e key confirmation; socket TCP, Server Proof isolado ou key exchange incompleto não vencem.

O winner permanece em `SECURE_UNAUTHORIZED` até o race cancelar losers. Só então a capability vencedora recebe o invite ou produz `MEMBER_RECONNECT_REQUEST`. Falha de authorization não tenta outro path, porque a identidade do servidor já foi autenticada. Abort destrói o winner ainda não entregue, attempts e sessions pendentes; all-failed expõe somente erro semântico bounded, sem lista de endereços, interfaces ou descriptors.

Ordering local prefere LAN proven, recent cryptographic success ainda presente, Direct Global e Port Mapped, com interleaving determinístico entre famílias. Success hints usam LRU em memória de 64 entradas e TTL de 10 minutos, keyed por Server Identity e endpoint; nunca criam candidate nem persistem failure. STUN fresh pode apenas escolher a família inicial em empate: o endereço observado do cliente nunca é comparado ao candidate de servidor remoto, e observation ausente, stale ou mentirosa não filtra endpoint.

## Peer-provided rendezvous pós-auth

O fluxo é: peer já autorizado como membro → `AuthorizedPeerChannel` sobre a `SecureSession` existente → request pelo `serverId` canônico exato → resposta `FOUND` ou `NOT_AVAILABLE` → verificação local completa do `SignedConnectivityDescriptor` do servidor target → candidate aggregation como fonte WAN não confiável → racing criptográfico → autenticação da Server Identity esperada → autorização direta no servidor target. O peer rendezvous, o servidor target e a autoridade de identidade são papéis distintos; o peer rendezvous não se torna target, autoridade ou relay.

O protocolo somente existe após `MEMBER_CONNECTED`. Cada frame `SESSION` é decifrado exatamente uma vez antes do dispatch e cifrado exatamente uma vez no envio. Requests e responses usam tipos fixos `0x20`/`0x21`, nonce CSPRNG de 32 bytes, comprimentos estritos e correlação por nonce mais `serverId`. Não existem wildcard, listagem, busca aproximada, enumeração, push, gossip ou reason string em `NOT_AVAILABLE`. A AEAD do canal autentica o peer que respondeu; ela não substitui a assinatura Ed25519 do servidor target contida no descriptor.

Somente descriptors verificados, frescos e exclusivamente WAN (`PORT_MAPPED_TCP` ou `DIRECT_GLOBAL_TCP`) podem ser marcados como shareable. O store mantém os bytes assinados originais sem reserialização, uma entrada por `serverId`, até 64 entradas e 512 KiB, com substituição determinística e sem rollback para descriptor mais antigo. Expiração assinada é revalidada no acesso e na resposta; não é estendida. O store é volátil, começa vazio após restart, recebe entradas apenas por inserção explícita e nunca inicia descoberta de rede.

O endpoint limita requests a 10 por conexão e 100 globais por janela de 10 segundos, permite no máximo duas requests pendentes por requester, usa timeout padrão de 3 segundos e limita responses a 8300 bytes. Duplicatas, malformed frames, overflow, abort e channel close têm cleanup bounded; responses atrasadas ou com nonce desconhecido são ignoradas. Um peer pode observar interesse e timing, omitir, atrasar ou repetir metadata ainda fresca para causar indisponibilidade, mas não pode forjar a assinatura do target, autorizar membership, receber o invite ou encaminhar bytes de aplicação.

Após a obtenção do descriptor, toda conexão ocorre diretamente entre requester e target. O invite somente é entregue ao único winner criptograficamente autenticado pelo pipeline existente de candidate racing; nenhum invite, payload de aplicação, handshake do target ou byte de `SecureSession` atravessa o peer rendezvous.

## Peer Relay pós-auth

O target X se conecta e se autoriza normalmente com Relay R e, por chamada explícita, solicita uma registration. R emite challenge CSPRNG de 32 bytes, one-shot e válido por até 10 segundos. X assina um transcript determinístico com domínio exclusivo, versão, Server Identity do relay, Server Identity e chave pública canônica do target, challenge, binding aleatório do channel e fingerprint do outer Device já autenticado. R valida estrutura e binding antes da verificação Ed25519 e mantém uma única registration efêmera por target por no máximo 300 segundos. Channel close, expiry ou unregister removem o binding e encerram seus circuits; nada é persistido ou renovado automaticamente.

Um requester já autorizado escolhe explicitamente um único R e solicita o `targetServerId` canônico exato com nonce CSPRNG de 32 bytes. R consulta apenas registrations locais ativas, gera circuitId CSPRNG de 16 bytes, oferece o circuito ao channel já conectado de X e só responde `READY` depois do accept. `NOT_AVAILABLE` colapsa ausência, expiry e quotas. O wire não possui host, IP, porta, URL, wildcard, listagem ou rota; R não executa DNS, socket outbound, discovery, rendezvous, multi-hop ou direct→relay fallback.

Cada lado recebe um `RelayTransportStream` runtime-branded que implementa somente byte-stream bounded sobre mensagens `RELAY_DATA`. Chunks de até 16 KiB não correspondem a frames internos e podem fragmentá-los ou coalescê-los. O relay copia e encaminha bytes sem chamar decoder MQRD ou `SecureSession.decrypt` internos. A mesma pipeline cliente/servidor usada pelo TCP roda sobre o stream: MQRD framing, expected Server Identity, mutual Ed25519 handshake, X25519, key confirmation, inner SecureSession e uma única Admission/Reconnect. Assim, outer membership com R e registration de X nunca concedem membership no target.

Circuitos são stateful (`OPENING` → `ACTIVE` → `CLOSING` → `CLOSED`) e pertencem simultaneamente aos dois channels; circuitId conhecido por terceiro não autoriza DATA ou CLOSE. A primitive limita duas opens pendentes e dois circuits por channel, 32 circuits globais, 16 KiB por DATA, 64 KiB queued por direção, 1 MiB queued global, 32 MiB por circuito, lifetime de 300 segundos, idle de 60 segundos e rates bounded de registration/open/data. Overflow, protocol violation, channel close, expiry e timers propagam close genérico e liberam buffers, listeners e pending state.

R observa targetServerId, presença opt-in da registration, timing, tamanhos, duração e material público do handshake interno. R pode apagar, atrasar, reordenar, duplicar, injetar ou modificar bytes, causando DoS, falha de assinatura/transcript/key confirmation ou falha AEAD/sequence. Depois da inner SecureSession, invite e application plaintext permanecem cifrados ponta a ponta entre requester e X; R não possui suas chaves e não participa semanticamente da autorização.

## Orquestração direct-first e lifecycle relay renovável

O fluxo único é: expected target Server Identity → fontes direct locais frescas → candidate race DIRECT → se reachability falhar, até três consultas rendezvous exatas, sequenciais e bounded → no máximo um descriptor WAN novo e uma segunda race DIRECT → se ainda inalcançável, seleção de até três relay peers autorizados fornecidos explicitamente → circuit exact-target → autenticação da mesma inner Server Identity → inner SecureSession → uma única Admission/Reconnect. Relay fallback é resposta a falha de reachability, nunca fallback de autorização.

As fases compartilham deadline global de no máximo 45 segundos. Direct mantém budget de até 15 segundos, rendezvous até 5 segundos e relays usam somente o restante. Success hints de rendezvous/relay duram até dez minutos, têm no máximo 64 entradas, são vinculados ao target e apenas reordenam peers atualmente elegíveis; direct-first não é alterado. Abort cancela a operação inteira, e completions tardias não podem produzir segunda autorização ou conexão.

No lado disponível, cada target registra-se explicitamente e prova novamente sua Server Identity com challenge one-shot fresco no refresh gerenciado de meia-vida. A troca só ocorre após a nova prova válida; falha mantém a expiração antiga, retries são bounded e channel/manager close impede ressurreição. Há no máximo três registrations gerenciadas por target e nenhum peer é descoberto automaticamente.

Cada circuito ACTIVE continua finito em cada instante, mas o requester high-level solicita renew na meia-vida usando nonce CSPRNG correlacionado. O relay só estende a lease se o requester ainda possuir o circuito, ele estiver ativo e a target registration continuar válida. Idle, filas, rates, contagem de circuitos e byte budget hard de 256 MiB continuam ativos. Perda do circuito encerra o stream interno: recuperação requer nova operação direct-first e novo handshake, não live SecureSession migration. Uma sessão relay ativa não dispara direct probes nem migração em background.

## Consolidação final da Fase 7

Todas as fontes e paths de conectividade convergem na mesma fronteira criptográfica:

```text
Local sources                         Remote metadata
├─ LAN Discovery                     └─ Peer Rendezvous
├─ PCP / NAT-PMP / UPnP
├─ Direct Global IPv6                Connection paths
└─ STUN observation                  ├─ Direct Candidate Race
                                      └─ Peer Relay
                                                ↓
                                  expected Server Identity
                                                ↓
                                      confirmed SecureSession
                                                ↓
                                      single Authorization
```

Network interface data é observação local do sistema operacional, não identidade. Gateway é ator de routing não confiável. STUN server é observador não confiável. Rendezvous peer transporta metadata não confiável. Relay peer transporta bytes opacos não confiáveis. Um `SignedConnectivityDescriptor` é uma declaração de routing autenticada, não autorização. Server Identity é a identidade criptográfica do target; membership permanece decisão exclusiva desse target.

### Failure matrix global

| Evento semântico | Classe | Decisão permitida antes de authorization |
| --- | --- | --- |
| Direct refused, timeout ou nenhum candidate alcançável | `TRANSIENT_REACHABILITY` | concluir a fase direct e avançar pela policy bounded |
| Endpoint errado ou target identity mismatch pré-auth | `TARGET_IDENTITY_MISMATCH` | próximo source/path elegível |
| Descriptor expirado antes do attempt | `STALE_ROUTING_STATE` | skip local do target |
| Network generation mudou | `LOCAL_NETWORK_CHANGED` | descartar provenance local dependente |
| Rendezvous/relay `NOT_AVAILABLE` | `TRANSIENT_REACHABILITY` | próximo peer bounded da fase |
| Malformed vindo de endpoint não confiável | `PROTOCOL_INVALID` | falha daquele peer/path; nunca cria authority |
| Resource cap local/global | `RESOURCE_LIMIT` | terminal para a operation; sem fallback storm |
| Abort | `ABORTED` | terminal |
| Shutdown | `SHUTTING_DOWN` | terminal e novo trabalho bloqueado |
| Invariante local inválida ou erro desconhecido | `SECURITY_INVARIANT_FAILURE` / `INTERNAL_FAILURE` | terminal fail-closed |
| Target esperado autenticado rejeita Admission/Reconnect | `TARGET_AUTHORIZATION_FAILURE` | terminal; invite/reconnect não é repetido |

A decisão é baseada exclusivamente em classes e códigos estáveis, nunca em texto de `message`, `name` frouxo ou regex. Depois que `authorizationStarted` se torna verdadeiro, nenhuma classe permite outro path.

O adaptador direct valida a identidade local antes de abrir transporte e so converte erros remotos/reachability explicitamente conhecidos em tentativa recuperavel. Falhas locais, de recursos e desconhecidas permanecem terminais, inclusive quando concorrem com abort.

### Resource, generation, deadline e shutdown

O `ConnectivityResourceGovernor` limita oito connection operations globais, uma por Server Identity target, dezesseis secure attempts, oito operações UDP, 32 relay circuits, 1 MiB de relay bytes enfileirados e 32 rendezvous requests. Reservas runtime-branded usam release idempotente em `finally`; resource exhaustion não tenta protocolo alternativo.

Cada conexao TCP limita a entrada pendente a 256 frames e 1 MiB, incluindo cabecalhos e o frame em processamento. Excesso encerra a conexao; dados parciais, replay e mensagens rejeitadas nao renovam o idle timeout. Atividade autorizada concluida renova idle sem alterar deadlines pre-auth. Cleanup zera os buffers de chaves derivados controlados pelo codigo e libera referencias de setup; nao garante zeroizacao das copias internas do runtime/OpenSSL.

Requests HTTP UPnP possuem deadline absoluto, independente da chegada de bytes. Sucesso, rejeicao, aborto remoto e timeout cancelam o timer e encerram request/response, sem drenar indefinidamente corpos rejeitados.

O banco de autoridade mantem quota de 1 MiB com `max_page_count` calculado pelo tamanho de pagina em cada abertura. Escritas sem capacidade falham sem impedir o carregamento do estado anterior; admissao reverte consumo, membro e certificado juntos. Migracao v3 para v4 somente confirma apos validacao completa. A allowlist de schema exclui apenas o prefixo literal `sqlite_`, rejeitando triggers e demais objetos inesperados.

`NetworkEnvironmentTracker` produz snapshot canônico, deduplicado e order-independent de interfaces/endereços somente quando chamado explicitamente. STUN e LAN provenance carregam sua generation e deixam de influenciar aggregation depois de mudança; descriptors WAN assinados e ainda frescos não são invalidados pela mudança local. Não existe watcher nem recovery loop automático.

Connection operations usam deadline monotônico absoluto. Child direct races, rendezvous queries e relay opens recebem `min(configuração, remainingOverallTime)`; remaining zero não inicia I/O. Signed timestamps continuam usando wall clock onde o protocolo exige. Relay registration/circuit durations e managed refresh usam relógio monotônico em produção.

O deadline e revalidado ao iniciar cada tentativa, aceitar um vencedor e antes/depois da autorizacao, sem depender apenas da execucao do callback do timer. Handshakes internos via relay tambem reservam `SECURE_CONNECTION_ATTEMPT` no governor da subsystem e liberam a reserva em toda saida terminal.

`ConnectivitySubsystem.shutdown()` muda primeiro para `SHUTTING_DOWN`, bloqueia novas operações, aborta scopes em voo e encerra resources registrados. O deadline máximo é cinco segundos; depois dele `forceClose` é best effort. Chamadas repetidas retornam a mesma promise, timers de renew/refresh são cancelados e nenhum estado pode reativar após `SHUT_DOWN`. A ordem de shutdown da aplicação deve ser rede primeiro e storage/identidades depois.

Restart cria governors, generations, caches, observations, mappings, listeners, relay registrations/circuits e sessions vazios. Nenhum handle de topologia ou sessão é persistido ou restaurado; somente identidade, bindings, memberships, certificados e invite state intencionalmente persistentes no schema v4 sobrevivem.

## Riscos residuais conhecidos

- O Application Protocol v1 (ETAPA 8.1) usa o namespace 0x70 sobre o AuthorizedPeerChannel: envelope com IDs hex de 128 bits, JSON canônico, schemas fechados, limites de corpo 40 KiB/payload 32 KiB, profundidade 8 e 2048 nós. Decode exige recodificação canônica byte a byte; duplicata de ID, replay, sequence fora de ordem e frames acima do rate limit falham fechadas. A autorização de leitura de estado é revalidada no ponto de uso; nenhuma mensagem concede authority.
- As etapas 8.2–8.5 adicionam canais owner-only no schema v5, mensagens no schema v6, sequences atribuídas pelo host, dedup por `clientMessageId`, histórico por cursor, tombstones, retention bounded, recovery por transações SQLite e outbox local FIFO. A quota de disco de 1 MiB limita a capacidade prática; o limite de 2000 mensagens por canal é deliberadamente inferior ao teto teórico para acomodar índices e journaling.
- A boundary desktop M3 usa preload/contextBridge allowlisted e valida novamente argumentos no processo main. Renderer não recebe chaves, signers, contextos autenticados, caminhos ou objetos SQLite; networking P2P continua opt-in e não é iniciado pelo startup.
- O shell desktop restaura servidores locais válidos após reinício, ignora entradas corrompidas na listagem sem recriar identidades, e oferece somente DTOs de servidor, canal, mensagem, membro e convite via IPC. Convites são gerados apenas no main com owner authorization e o renderer recebe o texto codificado, nunca a chave usada para assiná-lo.

- Um host offline torna seu servidor indisponível; a arquitetura não promete disponibilidade central.
- P2P e signaling podem revelar metadados de rede mesmo quando o conteúdo estiver protegido.
- Um host malicioso controla o estado que hospeda; o protocolo futuro precisará distinguir autoridade do servidor de confiança pessoal.
- Malware com controle equivalente ao usuário ou comprometimento total do sistema operacional pode ler memória, arquivos e entradas; hardening do aplicativo reduz, mas não elimina esse risco.
- No Windows, `safeStorage`/DPAPI não protege a chave de outro processo executando como o mesmo usuário. No JavaScript, a cópia textual exigida pela API e o material mantido por `KeyObject` dependem do garbage collector; zeroization completa não pode ser garantida.
- A private key do servidor é protegida pelo `safeStorage` do sistema/usuário atual. Copiar a pasta bruta para outra máquina ou perfil não garante descriptografia e não constitui migração segura; exportação e migração exigirão um protocolo específico futuro, sem fallback em plaintext.
- Nesta etapa o owner representa uma Device Identity, não uma pessoa ou conta. Perda do dispositivo poderá exigir recuperação, transferência, múltiplos dispositivos ou identidade humana em protocolos futuros; nenhuma dessas alternativas é inferida ou executada automaticamente agora.
- O banco `server.db` persiste o estado de domínio do servidor, mas não é raiz de confiança para identidade ou ownership criptográfico. Processos locais concorrentes executando no mesmo perfil de usuário poderiam teoricamente modificar o arquivo no disco entre verificações (TOCTOU local); mitigado no aplicativo pelo lock de instância única e validação no carregamento.
- Convites funcionam como bearer capabilities: quem tiver posse do token assinado pode tentar admissão. A expiração depende do relógio local (sem autoridade central de tempo). A operação atômica de admissão garante que consumo do convite e inserção do novo membro ocorram indivisivelmente.
- O transporte TCP oferece caminhos LAN/WAN e relay com ativacao explicita; o startup atual nao inicia listeners P2P. Reachability depende da interface, do firewall, do roteador e dos peers disponiveis, sem garantia de descoberta publica universal.
- A validação de symlinks reduz escritas fora do diretório, mas não elimina ataques locais de troca entre verificação e uso por um processo concorrente com acesso ao mesmo perfil.
- Uma interrupção abrupta durante a criação de servidor pode deixar diretórios temporários ou finais incompletos. Eles não são reconhecidos como servidores válidos sem um `server.json` completo e validado; limpeza de resíduos após crash fica para uma etapa futura.
- Relays P2P ampliam riscos de privacidade, abuso e exaustão; os limites globais e locais, o payload interno opaco e a ausência de destinos arbitrários reduzem esses riscos, mas não ocultam do relay metadados de circuito, volume e timing.
- Announcements NAT-PMP multicast em `224.0.0.1:5350` permanecem fora do escopo. State loss é detectado nos epochs de responses de create/renew e recovery reexecuta OP0 + OP2 antes de readvertising.
- Compatibilidade UPnP fica intencionalmente restrita a IGD v1, HTTP sem redirect/compressão, IPv4 RFC1918 e `WANIPConnection:1`/`WANPPPConnection:1`. IGD v2, routers que exigem lease permanente, descriptions via hostname/HTTPS e topologias multi-WAN ambíguas falham fechadas.
- Delete UPnP é advisory: timeout ou gateway offline não reativa a capability local, mas uma entrada pode permanecer no roteador até a lease finita expirar. Crash abrupto também depende dessa expiração; mappings permanentes são proibidas para limitar essa exposição residual.
- Durante migration pode haver overlap temporário de duas entradas no gateway, mas somente uma é `current`/advertisable. Se o delete antigo falhar, sua exposição residual termina pela lease finita; a mapping nova permanece válida.
- Os backends atuais não possuem cancelamento nativo de cada socket/request. Abort da strategy impede fallback e aguarda a tentativa bounded terminar para fechar qualquer mapping criada tardiamente; portanto a latência de cancelamento pode alcançar o timeout configurado, sem operação ilimitada.
- Um IPv6 global local e um bind bem-sucedido não comprovam reachability externa: host firewall, firewall de rede, filtros do ISP e ausência de rota bidirecional podem tornar o candidate inalcançável. Esta etapa deliberadamente não modifica firewall nem executa probe externo.
- IPv6 temporary/privacy pode mudar ou expor um identificador correlacionável ao destinatário do descriptor. O runtime Node não fornece classificação portátil confiável dessa propriedade; por isso não há inferência, auto-seleção ou persistência, e somente o endereço explicitamente escolhido é emitido por lifetime curto.
- Cada consulta STUN revela ao target o source IP, a porta UDP efêmera e timing. Como o target não é autenticado e a response não usa `MESSAGE-INTEGRITY`, ela pode ser falsa mesmo após source/transaction/FINGERPRINT válidos; por isso a consulta é opt-in, sem provider hardcoded, background ou promoção automática para candidate.
- UDP STUN observa somente o address/port daquela transaction UDP. NAT pode aplicar mappings ou filtros diferentes para TCP, destinos distintos ou instantes posteriores; concordância de endereço é apenas corroboration, nunca prova de inbound TCP.
- Racing pode revelar ao servidor e a observadores de rede que vários endpoints foram tentados em curta sequência. Stagger e limite de concorrência reduzem, mas não eliminam, esse metadata leakage.
- Um endpoint pode cair depois de vencer o handshake ou durante authorization; nesta etapa a operação falha e o caller pode iniciar nova race, sem manter secure winners em standby.
- Success hints podem ficar obsoletos por até dez minutos e mudar apenas a ordem dos attempts. Eles não suprimem candidates e desaparecem no restart.
- O peer rendezvous aprende qual `serverId` foi solicitado e o timing da consulta. Padding, private information retrieval e ocultação desse grafo social permanecem fora do escopo.
- Um peer rendezvous autorizado pode suprimir, atrasar ou repetir um descriptor ainda fresco, causando indisponibilidade ou attempts em endpoints obsoletos; assinatura, freshness e autenticação ativa do target impedem que isso se torne falsificação de identidade ou autorização.
- A disponibilidade do rendezvous depende de já existir um peer autorizado que possua explicitamente um descriptor WAN fresco do target. Não há busca por peers, gossip, diretório central ou garantia de descoberta; rendezvous não seleciona nem abre relay automaticamente.
- O relay conhece o targetServerId solicitado, qual outer peer registrou essa Server Identity, timing, tamanhos e duração do circuito, além do material público do handshake interno. Criptografia E2E não elimina análise de tráfego nem essa exposição de topologia.
- Um relay autorizado pode recusar, atrasar, descartar, reordenar, duplicar ou corromper bytes. As provas e a inner SecureSession convertem isso em indisponibilidade detectável, mas não garantem disponibilidade contra o próprio relay.
- Registrations e leases de circuito podem ser renovadas enquanto os outer channels e provas continuam válidos, mas cada renovação ainda depende do relay e pode ser suprimida para causar indisponibilidade. O hard byte budget de 256 MiB exige uma nova conexão após esgotamento.
- Um circuito depende simultaneamente dos dois outer authorized channels e do processo R. Queda de qualquer um encerra o stream; failover exige nova conexão e novo handshake, sem retomada, multi-hop ou migração de sessão viva.
