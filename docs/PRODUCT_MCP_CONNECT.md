# Conectar o ORDAX ao ChatGPT

## Arquitetura

O ORDAX Runtime mantém o computador conectado ao Control Plane. O ChatGPT não acessa `localhost` e não precisa manter um terminal aberto.

```text
ChatGPT normal
   |
   | ORDAX Studio (conector ChatGPT)
   v
MCP remoto do Control Plane (definido pelo manifest publicado)
   |
   v
ORDAX Runtime no Windows
   |
   +-- projetos
   +-- arquivos / Git
   +-- preview / processos
   +-- Computer Control
   +-- Blender / Unity
```

## Conector

A fonte do conector do ChatGPT fica em `plugins/ordax-chatgpt/`. O pacote contém somente os manifests/configuração e assets necessários para apontar o ChatGPT ao MCP remoto. O runtime real continua no dispositivo.

O nome visível do conector é **ORDAX Studio**, governado pelo mesmo manifest
`plugins/ordax-chatgpt/plugin.json` usado no pacote. O ID estável `ordax-chatgpt`
continua identificando o conector ChatGPT, com versão independente do app. O
nome compartilhado não altera ownership nem embute Studio/Runtime no plugin.
[IA do OS, contratos necessários e limites atuais](ORDAX_PROVIDER_CONNECTORS.md#relationship-to-ordax-os).

Outros providers devem seguir o mesmo padrão com conectores independentes, por exemplo `ORDAX for Grok`, reutilizando o mesmo protocolo, Control Plane, grants e handlers tipados.

## Autenticação OAuth e cutover do Supabase

O **SSOT de identidade** para a próxima versão do OrdaX Platform é o projeto Supabase
`jhfphsjptrpmtnzkpwud` (`ordax-platform`, São Paulo). A página
`/oauth/consent` deriva a origem desse projeto exclusivamente da variável
`PRODUCT_AUTH_ISSUER`; a chave `SUPABASE_PUBLISHABLE_KEY` é pública e
pertence ao mesmo projeto. Sem configuração válida, a rota retorna **503**
(fail-closed), sem fallback ao projeto antigo.

A tela não cria contas no fluxo de link mágico
(`shouldCreateUser: false`). A aprovação de um OAuth client só é habilitada
após validar os detalhes do `authorization_id` junto ao Supabase.

**Migração ainda pendente:** o manifest do conector distribuído
(`plugins/ordax-chatgpt/mcp.json`) aponta para o Worker publicado na conta
Cloudflare antiga. Essa URL é operacionalmente legada e **não valida** o
projeto Supabase canônico. Não redirecionar o manifest nem desligar o serviço
antigo antes do cutover coordenado, preservando conexões existentes.

Antes de anunciar o OAuth em produção no ambiente canônico:

1. Habilitar o **OAuth 2.1 Server** no projeto Supabase correto, configurar
   **Authentication → URL Configuration** (Site URL/redirects) e o caminho
   `/oauth/consent` em **Authentication → OAuth Server**.
2. Configurar o modo de clientes OAuth: **registro dinâmico (DCR)** para
   provedores MCP compatíveis, com consentimento por usuário e monitoramento,
   **ou** pré-cadastrar cada cliente com URI de redirecionamento exata.
   **Zero clientes pré-cadastrados não é falha por si só se o DCR estiver
   habilitado.** Configurar também envio de e-mails e a política de
   cadastro/recuperação.
3. Concluir o cutover seguro Worker/D1 → PostgreSQL, secrets, grants e
   vinculação do dispositivo na conta Cloudflare exclusiva do ORDAX.
4. Publicar o Worker canônico **somente após** o gate de readiness e
   testar PKCE, consentimento, revogação, isolamento por `client_id`,
   ausência de grants, fluxo de e-mail, cadastro desabilitado e E2E no Runtime.
5. Atualizar manifests e URL pública apenas depois de demonstrar E2E
   no ambiente novo, preservando rollback e auditabilidade.

### Verificação não destrutiva do OAuth canônico

Executar na raiz do repositório:

```bash
python scripts/cloudflare/verify_product_oauth_server.py https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1
```

O verificador aceita **somente** o emissor do projeto Supabase, valida a
descoberta OAuth (issuer, endpoints na mesma origem, PKCE S256, cliente público
`none` e anúncio do registro dinâmico) e não aceita redirecionamentos de
HTTP nem respostas JSON excessivas. Não usa token administrativo.

**Limitação deliberada:** o endpoint de registro pode ser **anunciado** sem
que o cadastro de um cliente tenha sido testado. Esse diagnóstico apenas lê
metadados; não cria cliente, sessão nem grant e não substitui E2E de registro,
aprovação, troca de código, renovação, revogação e acesso autorizado no Runtime.

O uso local do Studio não depende da ativação do serviço OAuth remoto.

## Descoberta dos dispositivos da conta

Entrar na Conta ORDAX e conectar um dispositivo não concede acesso automático
ao cliente de IA. O catálogo canônico consulta dispositivos ativos com grants
ativos e não expirados para o usuário e o **cliente OAuth exato**. Esses filtros
pertencem a `ordax_list_product_targets_v1`, não à UI, ao conector ou a um scan
de computadores. Os claims assinados `sub` e `client_id` identificam o usuário
e o cliente; campos enviados em headers, argumentos ou metadata do usuário
não escolhem essa autoridade. A distinção entre identidade OAuth e acesso aos
dados segue o [contrato OAuth do Supabase](https://supabase.com/docs/guides/auth/oauth-server/token-security).

Um catálogo vazio pode significar ausência de grants para esse cliente. Já
falha de autenticação, conta inelegível, banco indisponível ou resposta inválida
precisam aparecer como erro, sem fingir que o catálogo disponível está vazio.
`online` é a presença informada pela plataforma; `last_seen_at` é a última
atividade informada. Nenhum deles concede execução. Um dispositivo offline
pode continuar listado, mas operações locais dependem do Runtime conectado.

**Estado comprovado no source em 2026-10-09:**

- A projeção MCP preserva nome, presença e descrições dos grants canônicos,
  excluindo campos privados e identificadores internos de grupos.
- `product_mcp_reads.ts` prepara handlers de leitura que verificam OAuth
  com o boundary existente e chamam o adapter PostgreSQL existente. Catálogos
  são relidos por requisição e recebem `Cache-Control: no-store`; erros não
  expõem SQL, credenciais nem detalhes internos.
- O teste `product_mcp_discovery.test.mts` percorre requisição MCP → verificação
  de token assinado → reader RPC controlado → projeção pública. Também testa
  negação antes do reader, catálogo alterado/vazio, conta inelegível, UUIDs
  inválidos/duplicados e ausência da configuração PostgreSQL. Não é E2E real.
- **As rotas em `index.ts` ainda usam D1.** Os novos handlers não estão
  ativados. A migração coordenada de descoberta, grants, ações e status está
  pendente no item #42 e no `d1-cutover-authority-map.json`.
- A publicação permanece bloqueada por `production-foundation.json`.
  CI verde ou esses testes de source não removem o gate de produção.

Para aceitar a funcionalidade em produção, demonstrar OAuth/consentimento no
emissor canônico, isolamento entre duas contas e dois clientes OAuth, ausência
e revogação de grants, presença online/offline e uma ação autorizada pelo
Runtime. A conta autenticada precisa ser elegível no momento da consulta.
Não redirecionar apenas a descoberta ao PostgreSQL mantendo execução em D1.

## Acompanhamento canônico de tarefas — source preparado

O mesmo factory `createCanonicalProductMcpReadHandlers` prepara a leitura de
`ordax_get_product_action_v1`. A identidade é verificada em cada requisição;
o RPC existente verifica elegibilidade da conta e seleciona somente o request
do usuário e do cliente OAuth exato. Um resultado ausente retorna 404, uma
conta inelegível retorna 403 e falhas de configuração/transporte retornam 503.
Registros malformados, IDs divergentes e estados desconhecidos retornam 502,
sem simular conclusão ou publicar SQL/credenciais.

Os estados publicados são `queued`, `leased`, `running`, `succeeded`, `failed`
e `cancelled`. A projeção MCP mantém o request de continuação e distingue
pendência de estado terminal. O `project_id` canônico é preservado; `project`
fica nulo porque não existe conversão oficial para o slug legado nesse RPC.
O resultado pertence ao contrato Product do Runtime; campos extras de banco,
payload de entrada e identidades internas não são incluídos na resposta HTTP.
Timestamps válidos são normalizados e as respostas recebem `no-store`, também
na saída JSON MCP. A consulta não concede execução nem cria audit/queue
paralelos; usa somente o adapter de leitura existente.

O histórico de uma ação aceita é consultado diretamente por sua identidade,
sem pedir catálogo de dispositivos ou disparar outra ação. Desktop offline
ou catálogo indisponível não apagam essa identidade. Isso não equivale a
executar novas operações offline. A autoridade do RPC determina o acesso
ao histórico; o handler não adiciona grants nem amplia seu escopo.

`product_mcp_action_status.test.mts` exercita token assinado → handler/MCP →
reader controlado → resultado público, incluindo todas as transições,
negações, identidade enviada pelo caller ignorada, ausência de replay,
preservação do UUID de projeto e ausência de configuração PostgreSQL.
Esses testes não comprovam execução, filtragem ou revogação em banco real.

### Dependências para ativar as rotas juntas

O Runtime remoto foi conferido no commit `113c49e72eb6f12ed12ca4597478765102c18ac7`.
O [consumidor Product auditado](https://github.com/ordaxsystems/ordax-runtime/blob/113c49e72eb6f12ed12ca4597478765102c18ac7/ordax_dev_agent/product_remote.py)
ainda exige o envelope legado `action`, `arguments`, `context`, `grant` e
reconhece `ordax.product.invoke`/`ordax.product.read.invoke`.
O [transporte auditado](https://github.com/ordaxsystems/ordax-runtime/blob/113c49e72eb6f12ed12ca4597478765102c18ac7/ordax_dev_agent/cloudflare_control_plane.py)
usa o WebSocket `/v3/device/ws` e o audit `/v3/product/audit` existentes.
Isso não demonstra consumo da fila Product privada PostgreSQL.

Antes do cutover, Platform e Runtime precisam provar o contrato de enqueue →
claim/lease → execução com política local → report/audit → status. Também
precisam publicar o vínculo entre UUID do projeto canônico e projeto local,
preservar requests já aceitos, prevenir execução duplicada e validar
revogação/reconexão. Usar slugs arbitrários como UUIDs, fabricar grants ou
enviar jobs para o consumidor legado sem esse contrato não resolve a migração.
Os handlers preparados não estão conectados às rotas de `index.ts`.

### Recuperação do consumidor Runtime atual

[Runtime PR 65](https://github.com/ordaxsystems/ordax-runtime/pull/65), source
`fd72a79`, corrige o único cliente HTTP/MCP Python existente: ID/estado da tarefa
validados, ID aceito preservado em erro/timeout, `product_action_status` como GET
autenticado e ACK perdido/malformado tratado como aceitação incerta. Um teste das
ferramentas registradas prova POST → falha GET → recuperação GET, com um único
POST. Não cria grant, fila, pairing ou executor e não adapta o envelope legado
para fingir compatibilidade PostgreSQL. Runtime candidato 0.4.5 deriva sua versão
de metadados próprios, separado do Studio/Blender/Device Agent, e requer o SDK
MCP 1.30.0 verificado, sem correções privadas no SDK.

O [contrato de recuperação](https://github.com/ordaxsystems/ordax-runtime/blob/codex/product-action-response-integrity/docs/PRODUCT-ACTION-RECOVERY.md)
descreve limites, riscos, testes e source versus instalação. A enumeração de
dependências de cutover acima permanece válida; esta correção não habilita rotas
canônicas, não altera readiness/authority map nem comprova conta/dispositivo real.

### Correção do facade MCP atual

O facade compartilhado também valida o conteúdo das respostas dos handlers
atuais: HTTP 200 sozinho não autentica a sessão, não comprova catálogo, ACK
de ação nem status. Catálogo malformado recebe erro; somente `ok:true` com
array de targets pode representar lista vazia. Estados desconhecidos, action
ausente e IDs divergentes não mantêm uma tarefa como se estivesse trabalhando
nem anunciam conclusão. `isError` reflete essas falhas na saída MCP.

Consulta inválida/falha depois do ACK preserva o request aceito para recuperação
por `ordax_action_status`. Nenhuma falha repete o dispatch; ausência de ACK
válido é estado incerto, não prova de que a ação nunca foi aceita. Exceções e
campos arbitrários do backend não aparecem como detalhes ao provider. A
negação de grant conserva o código público e o direcionamento para o perfil
de autorização do owner, sem criar ou ampliar permissões.

A leitura de JSON reutiliza `readBoundedJsonObject` com limite de 2 MiB e UTF-8
válido; resposta excessiva ou inválida é rejeitada e o reader é liberado.
`product_mcp_failure_responses.test.mts` testa o facade efetivo, incluindo
sessão inválida, catálogo vazio legítimo, erro HTTP, exceção, estado desconhecido,
request diferente, ACK malformado e ausência de segundo dispatch. A mesma
função de validação dos seis estados serve ao handler canônico e à projeção.
Essas correções de source não removem o gate de publicação.

## Configuração no Windows

### Presença canônica do dispositivo — source, ainda sem ativação

O cadastro canônico em PostgreSQL agora possui um contrato HTTP de presença:
`POST /v3/product/device/presence`, autenticado pela credencial do dispositivo
e delegado aos RPCs existentes. Conta/OAuth no navegador não substitui essa
credencial nem autoriza um heartbeat. Nome, presença observada e grants são
informações distintas. `changed:false` significa coalescência da autoridade;
não é falha e não informa que o timestamp mudou naquela chamada.

O Runtime atual ainda usa `/v3/device/ws` legado e **não envia** para essa nova
rota. Portanto, este incremento não comprova que um dispositivo real cadastrado
apareça online no plugin nem que receba tarefas. Canal, grants, bindings e
consumidor precisam migrar juntos, sem heartbeat ou persistência paralelos.
O Worker permanece sujeito ao gate de produção. [Contrato, limites e provas](PRODUCT_DEVICE_PRESENCE.md).

A instalação/conexão deve deixar claro que existem duas decisões diferentes:

1. **Vincular o dispositivo à Conta ORDAX / conector remoto.** Isso determina quem pode alcançar o Runtime remotamente e quais ações/grants remotos são válidos.
2. **Escolher localmente o modo de Computer Control.** Essa escolha pertence ao dono do computador e nunca ao cliente de IA.

No ORDAX Studio, em **Acesso ao computador**, o dono escolhe:

### Bounded

Mantém controles de menor privilégio:

- filesystem limitado às pastas autorizadas, salvo quando `full_filesystem` for habilitado separadamente;
- aplicativos limitados à allowlist local;
- adequado para máquinas em que o usuário quer restringir a superfície acessível pelo conector.

### Full Access

Depois de uma confirmação local explícita, remove as allowlists ORDAX de pastas e aplicativos para todas as capabilities Computer Control suportadas.

O aviso deve explicar de forma clara que um cliente ORDAX remoto **já autorizado** poderá, conforme as capabilities disponíveis:

- ler, criar, alterar, mover e remover arquivos;
- inspecionar e controlar janelas;
- usar mouse, teclado e clipboard;
- inspecionar processos;
- capturar a tela/janela ativa;
- iniciar aplicativos suportados;
- usar outras capabilities Computer Control publicadas pelo Runtime.

Full Access não remove autenticação, grants, validação tipada, receipts/auditoria nem as permissões reais do Windows. UAC, recursos protegidos, outro usuário/sessão e operações que exigem elevação continuam sujeitos às regras do Windows.

**O ChatGPT, o conector ou qualquer outro cliente remoto não pode habilitar, ampliar ou persistir Full Access.** A alteração precisa acontecer na superfície local do ORDAX Studio ou por uma política administrada no próprio dispositivo.

O dono pode revogar Full Access a qualquer momento e voltar para Bounded; a mudança deve ter efeito imediato nas próximas ações.

## Fluxo recomendado de onboarding

```text
1. Instalar ORDAX Studio / ORDAX Runtime no Windows
2. Abrir ORDAX Studio localmente
3. Opcionalmente entrar na Conta ORDAX
4. Vincular o dispositivo ao conector ORDAX Studio
5. Escolher localmente:
      - Bounded
      - Full Access
6. Se Full Access:
      mostrar aviso de controle amplo do computador
      exigir confirmação local do dono
7. Usar o conector ORDAX Studio no cliente externo
```

A Conta ORDAX continua opcional para uso local do Studio. Ela passa a ser necessária quando o usuário quer as capacidades remotas/account-scoped correspondentes, como vínculo de dispositivo, grants remotos e acesso pelo conector.

## Produto atual

Nesta etapa não há licença nem assinatura. Conta ORDAX, quando usada, serve para autenticar/vincular o dispositivo e seus grants; ela não conecta automaticamente um provider de IA.

A UI Windows é o ORDAX Studio. A conversa acontece no cliente externo, por exemplo o ChatGPT normal, e o conector apenas disponibiliza as capabilities ORDAX autorizadas.
