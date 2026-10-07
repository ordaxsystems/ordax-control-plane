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

A auditoria de cutover encontrou 10 tabelas D1 legadas. Product devices/grants/action queue/audit já possuem authorities PostgreSQL canônicas. Artifact metadata/multipart e a queue genérica de engenharia ainda dependem do contrato acompanhado em **#42**. Não criar tabelas PostgreSQL apenas para reproduzir o schema D1 1:1.

## Product PostgreSQL

O destino correto é:

`Worker -> Hyperdrive -> PostgreSQL`

O runtime PostgreSQL deve usar uma credencial LOGIN dedicada e least-privilege associada ao boundary `ordax_edge_executor`.

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

Estado atual da conta dedicada: R2 ainda precisa ser habilitado administrativamente pelo Dashboard. A API retorna `10042: Please enable R2 through the Cloudflare Dashboard` e o OpenAPI atual não oferece operação de ativação da conta R2.

Depois de habilitado:

1. criar somente o bucket canônico;
2. manter bytes no R2;
3. manter metadata persistente no PostgreSQL;
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

### Scripts

- `scripts/cloudflare/deploy-production-v3.sh`: deploy rotineiro do Worker já pronto.
- `scripts/cloudflare/deploy-v3.sh`: bootstrap legado. Ele recusa explicitamente criar D1 na conta Cloudflare dedicada do OrdaX.

Não adicionar fallback para account antigo, Worker antigo ou D1 antigo.

## Segurança

Regras permanentes:

- PostgreSQL é o SSOT persistente;
- sem D1 novo;
- sem dual-write;
- sem backend secret genérico do Supabase no Worker de produção;
- credenciais runtime devem ser least-privilege;
- token CI deve ser novo e dedicado à conta OrdaX;
- 2FA é requisito de produção;
- raw device token não deve ser persistido;
- modelo/contexto nunca amplia grants;
- sem shell remoto genérico;
- DNS só muda após gates independentes e rollback comprovado.

A conta dedicada ainda não deve ter `enforce_twofactor=true` enquanto o único membro não tiver 2FA habilitado, para evitar lockout. Primeiro habilitar 2FA no usuário; depois aplicar enforcement de conta.

## DNS

A zone `ordax.com.br` ainda não deve ser movida.

O blocker atual é a dependência `catalogo-media`, que pertence a Catálogo/Achegue-se e precisa ser realocada antes do cutover da zone. O workstream Cloudflare do OrdaX não deve alterar recursos Tonecos/Achegue-se durante essa migração.

## Blockers de produção

A lista executável está somente em `production-foundation.json`. No estado atual ela inclui:

- R2 ainda não habilitado;
- Hyperdrive ainda não provisionado;
- runtime LOGIN PostgreSQL ainda não provisionado;
- adapter Worker -> Hyperdrive ainda não implementado;
- cutover D1 ainda incompleto;
- token CI dedicado ainda não rotacionado/provisionado;
- 2FA do account ainda não habilitado.

Não remover blocker por expectativa. Cada blocker só sai depois de evidência live + source/CI coerentes.

## Provisionamento local do Device Agent

O setup oficial do Windows continua em:

`scripts/windows/ordax-device-agent-setup.ps1`

A credencial de dispositivo é gerada localmente e o backend recebe somente material derivado/hash conforme o contrato do runtime. Mudanças nesse fluxo devem preservar machine binding, fencing de execução e replay idempotente.

## Princípio de cutover

A ordem correta é:

1. fechar authorities PostgreSQL faltantes;
2. provisionar LOGIN runtime least-privilege;
3. provisionar Hyperdrive;
4. substituir os adapters D1/REST pelo caminho Hyperdrive/PostgreSQL;
5. habilitar/provisionar R2 e migrar somente artifacts necessários, com integridade;
6. remover D1 do `wrangler.toml` e do runtime;
7. provisionar token CI dedicado e validar deploy/E2E;
8. habilitar 2FA e enforcement de account;
9. resolver a dependência DNS de Catálogo;
10. somente depois executar cutover de `ordax.com.br`.

Sem delete antecipado na origem e sem paliativos para atravessar gates.
