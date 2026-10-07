# OrdaX Control Plane — Cloudflare

Este diretório contém a camada Cloudflare do Control Plane remoto do OrdaX.

A autoridade arquitetural de produção está em `production-foundation.json`. Este README explica o contrato; quando houver divergência, o arquivo de foundation e os testes associados prevalecem.

## Arquitetura canônica de produção

- **Cloudflare Worker**: edge/API boundary, autenticação de requests, gateway HTTP, WebSocket handoff e integração com os serviços do Control Plane.
- **PostgreSQL / Supabase**: SSOT persistente. O projeto canônico é `ordax-platform-prod` / `jhfphsjptrpmtnzkpwud` em `sa-east-1`.
- **Hyperdrive**: transporte canônico do Worker para PostgreSQL, com binding futuro `POSTGRES`.
- **R2**: bytes de artifacts/binários. R2 não é SSOT de metadata.
- **Durable Objects**: coordenação realtime/sessão. DO storage não substitui persistência de negócio.
- **D1**: legado temporário do Worker atual, proibido na arquitetura de destino.

Não existe dual-write permitido entre D1 e PostgreSQL.

## Estado da transição

A fundação de produção está deliberadamente **fail-closed**. `deployment_ready=false` permanece enquanto houver blockers em `production-foundation.json`.

O D1 atual está congelado:

- nenhuma tabela D1 nova;
- nenhuma migration D1 nova;
- nenhum novo módulo pode introduzir D1;
- remoções são permitidas e esperadas;
- o binding D1 só pode desaparecer depois que todos os call-sites tiverem authority PostgreSQL canônica.

O guard dessa regra roda em `tests/test_cloudflare_account_resolution.py`.

O mapa canônico da remoção está em `d1-cutover-authority-map.json`. Ele agrupa o legado por domínio de authority, não por cópia de schema, e fixa o baseline atual de 75 call-sites `env.DB`. A CI permite apenas redução desse número e exige que toda tabela D1 referenciada esteja classificada exatamente uma vez.

A auditoria de cutover encontrou 10 tabelas D1 legadas. Product grants/action queue/audit já possuem authorities PostgreSQL canônicas. Product pairing/link exige redesenho sobre identity/bindings canônicos; o registry de device é parcialmente coberto e ainda precisa separar Product de engineering/runtime. Artifact metadata/multipart e a queue genérica de engenharia continuam dependentes do contrato acompanhado em **#42**. Não criar tabelas PostgreSQL apenas para reproduzir o schema D1 1:1.

## Product PostgreSQL

O destino correto é:

`Worker -> Hyperdrive -> PostgreSQL`

O runtime PostgreSQL usa a credencial LOGIN dedicada `ordax_edge_runtime`, que herda somente o boundary NOLOGIN `ordax_edge_executor`. O Hyperdrive canônico está provisionado com cache desabilitado, TLS `require` e limite de 10 conexões de origem.

O arquivo `src/product_postgres_store.ts` ainda representa o adaptador REST legado com backend secret. Ele **não é o destino de produção** e o foundation mantém `worker_hyperdrive_adapter_not_implemented` como blocker enquanto esse código existir.

São proibidos no runtime Worker de produção:

- `SUPABASE_SERVER_KEY`;
- `SUPABASE_SERVICE_ROLE_KEY`;
- `service_role` genérico como application authority.

O cache do Hyperdrive permanece desabilitado para authority paths como autenticação, grants, jobs e operações com read-after-write.

## Product Auth

A verificação de JWT usa metadata pública do projeto Supabase Brasil:

- issuer: `https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1`;
- audience: `authenticated`;
- JWKS: `https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json`.

Esses valores são metadata pública, não secrets. Os testes derivam issuer e JWKS do `postgres.project_ref` do foundation para evitar drift entre Cloudflare e o projeto PostgreSQL canônico.

## workers.dev

O subdomínio account-level canônico foi inicializado como:

`ordaxsystems.workers.dev`

Nenhum Worker foi criado como efeito desse bootstrap. O Worker de produção, quando autorizado pelo gate, ficará no hostname derivado de `worker_name` + esse subdomínio.

O deploy rotineiro resolve o subdomínio ao vivo; não existe fallback para hostname/account legado.

## R2 e artifacts

O bucket canônico é definido pelo foundation como `ordax-device-artifacts`.

Estado atual da conta dedicada: R2 está habilitado e o único bucket canônico `ordax-device-artifacts` foi provisionado em classe Standard, jurisdição default. A API confirmou o bucket ao vivo após a criação.

Regras permanentes:

1. manter bytes no R2;
2. manter metadata persistente no PostgreSQL;
3. não criar segundo bucket como authority paralela;
4. não usar D1 ou Durable Objects como novo SSOT de artifacts.

O fluxo legado de metadata/multipart ainda depende de D1 e será removido no cutover, não duplicado.

## Durable Objects

Existem duas classes no runtime atual:

- `DeviceSession`;
- `EnrollmentSession`.

O destino mantém Durable Objects somente para coordenação de sessão/realtime. Estado de negócio durável deve estar no PostgreSQL; artifacts ficam no R2.

## Deploy

### CI

O workflow `ORDAX Control Plane CI` valida source, contratos e bundle do Worker.

### Produção

O workflow `Deploy ORDAX Control Plane`:

1. faz checkout do SHA exato que passou na CI;
2. valida `production-foundation.json`;
3. só executa o job de deploy quando `deployment_ready=true` e não existem blockers;
4. usa o account id vindo do foundation, sem segunda fonte de verdade;
5. exige `CLOUDFLARE_API_TOKEN` no environment GitHub `cloudflare-v3`;
6. chama `scripts/cloudflare/deploy-production-v3.sh`;
7. executa smoke público depois do deploy.

O deploy rotineiro **não provisiona infraestrutura**.

Como o Worker ainda não existe, o bootstrap e o CI permanente são autoridades distintas:

- criação inicial do Worker: autoridade **Workers Product Admin temporária**, removida após o bootstrap;
- deploys posteriores: **Editor somente no Worker existente**;
- o token rotineiro não recebe Zone/Routes, D1, R2 ou Hyperdrive direct access apenas para publicar bindings.

### Scripts

- `scripts/cloudflare/deploy-production-v3.sh`: deploy rotineiro do Worker já pronto.
- `scripts/cloudflare/deploy-v3.sh`: bootstrap legado. Ele recusa explicitamente criar D1 na conta Cloudflare dedicada do OrdaX.

Não adicionar fallback para account antigo, Worker antigo ou D1 antigo.

## Autenticação operacional legada

O bearer global `ORDAX_OPERATOR_TOKEN` é legado e não pode crescer.

A superfície atual está congelada por teste nos handlers:

- `createProductGrant`;
- `createProductGrantFromLink`;
- `listProductGrants`;
- `resolveProductGrantAdmin`;
- `revokeProductGrant`;
- `provisionDevice`;
- `deleteDevice`;
- `enqueueJob`;
- `getJob`.

Novos handlers não podem chamar `operatorAuthorized()`. A allowlist só deve encolher conforme cada rota migra para authority autenticada e least-privilege. Se a superfície mudar, a CI exige atualização explícita do contrato.

## Segurança

Regras permanentes:

- PostgreSQL é o SSOT persistente;
- sem D1 novo;
- sem dual-write;
- sem backend secret genérico do Supabase no Worker de produção;
- sem bearer global `ORDAX_OPERATOR_TOKEN` no Worker de produção;
- rotas administrativas precisam de authority autenticada e least-privilege compatível com sua semântica;
- credenciais runtime devem ser least-privilege;
- token CI deve ser novo e dedicado à conta OrdaX;
- 2FA é requisito de produção;
- raw device token não deve ser persistido;
- modelo/contexto nunca amplia grants;
- sem shell remoto genérico;
- DNS só muda após gates independentes e rollback comprovado.

O único membro administrativo já possui 2FA habilitado. O enforcement account-level continua sendo uma camada separada e deve ser ativado apenas por um fluxo administrativo em que o estado resultante possa ser verificado sem risco de lockout.

## DNS

A zone `ordax.com.br` ainda não deve ser movida.

O blocker atual é a dependência `catalogo-media`, que pertence a Catálogo/Achegue-se e precisa ser realocada antes do cutover da zone. O workstream Cloudflare do OrdaX não deve alterar recursos Tonecos/Achegue-se durante essa migração.

## Blockers de produção

A lista executável está somente em `production-foundation.json`. No estado atual ela inclui:

- adapter Worker -> Hyperdrive ainda não implementado;
- cutover D1 ainda incompleto;
- autenticação operacional legada por `ORDAX_OPERATOR_TOKEN` ainda não removida/substituída;
- Worker de produção ainda não provisionado;
- token CI permanente Worker-scoped ainda não provisionado;

Não remover blocker por expectativa. Cada blocker só sai depois de evidência live + source/CI coerentes.

## Provisionamento local do Device Agent

O setup oficial do Windows continua em:

`scripts/windows/ordax-device-agent-setup.ps1`

A credencial de dispositivo é gerada localmente e o backend recebe somente material derivado/hash conforme o contrato do runtime. Mudanças nesse fluxo devem preservar machine binding, fencing de execução e replay idempotente.

## Princípio de cutover

A ordem correta é:

1. fechar authorities PostgreSQL faltantes;
2. provisionar LOGIN runtime least-privilege;
3. provisionar Hyperdrive — concluído;
4. substituir os adapters D1/REST pelo caminho Hyperdrive/PostgreSQL;
5. habilitar R2 e provisionar o bucket canônico;
6. migrar somente artifacts necessários, com integridade;
7. remover D1 do `wrangler.toml` e do runtime;
8. remover/substituir `ORDAX_OPERATOR_TOKEN` por authorities explícitas;
9. criar o primeiro Worker com autoridade temporária de bootstrap;
10. substituir a autoridade de bootstrap por token CI Editor somente naquele Worker e validar deploy/E2E;
11. habilitar 2FA e enforcement de account — 2FA do membro concluído; enforcement account-level permanece separado;
12. resolver a dependência DNS de Catálogo;
13. somente depois executar cutover de `ordax.com.br`.

Sem delete antecipado na origem e sem paliativos para atravessar gates.
