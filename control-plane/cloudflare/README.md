# OrdaX Control Plane v3 — Cloudflare

Este diretório contém o Control Plane remoto de produção do OrdaX Device Agent.

## Runtime

- **Worker**: autenticação de dispositivo, API administrativa e gateway HTTP de artifacts.
- **Durable Object por dispositivo**: WebSocket persistente, entrega serializada de jobs,
  leases, progresso e terminal reports.
- **D1**: dispositivos, jobs, eventos, metadados de artifacts e contratos persistidos de Product grants/auditoria.
- **R2**: bytes de screenshots, snapshots e exports.

O `ActionRegistry` local continua sendo a autoridade final. O backend não
adiciona shell remoto genérico.

## Provisionamento

O setup oficial do Windows usa:

`scripts/windows/ordax-device-agent-setup.ps1`

A credencial é gerada localmente em:

`%LOCALAPPDATA%\OrdaX\DevAgent\device-token.cloudflare-v3.txt`

Somente o SHA-256 é enviado ao Worker.

`agent-settings.json` mantém `control_plane_protocol`, `control_plane_url`
e `device_id`.

## Deploy

O workflow **Deploy Cloudflare v3 Control Plane** cria/localiza os recursos,
aplica migrations, publica o Worker, valida `/health` e executa o E2E remoto.

Configuração:

- `wrangler.toml`: configuração de produção.
- `wrangler.ci.toml`: configuração isolada para CI/local.
- `migrations/`: schema D1.
- `src/index.ts`: Worker e Durable Objects.

## Artifact integrity

Uploads de até 90 MiB são enviados diretamente ao R2 com SHA-256 fornecido pelo
Agent como checksum nativo. O backend registra tamanho e digest em D1 e só
publica o artifact depois de validar a integridade.

Arquivos maiores usam multipart R2 com sessão idempotente em D1. Cada parte é
autenticada e verificada por SHA-256 no Worker; na conclusão o objeto inteiro é
relido como stream e validado por SHA-256 antes da publicação. O Agent usa partes
de 64 MiB e até 10.000 partes, mantendo cada request abaixo do limite do Worker.
Uploads multipart abandonados são descartados pelo lifecycle do R2 e as sessões
D1 antigas são limpas antes de novos uploads.

O endpoint `/health` publica capacidades explícitas. O Agent só ativa multipart
quando o Worker anuncia `artifact_multipart_v1`; contra um Worker anterior ele
mantém artifacts grandes localmente em vez de tentar uma API incompatível. Isso
permite rollout seguro na ordem Worker primeiro, Agent depois.

## Product grants (administração somente)

A migration `0005_product_grants_audit.sql` adiciona o armazenamento durável de
grants e o schema da trilha de auditoria do futuro Product MCP/OrdaX Web.

O Worker expõe somente administração autenticada pelo token de operador:

- `POST /v3/product-grants`: cria um grant explicitamente read-only;
- `GET /v3/product-grants`: lista grants para operação/diagnóstico;
- `DELETE /v3/product-grants/{id}`: revoga logicamente sem apagar histórico;
- `POST /v3/product-grants/resolve`: diagnóstico administrativo que resolve um
  grant ativo para subject/Space/device/action/project.

A resolução é fail-closed: ignora grants revogados/expirados, respeita Space,
device, action e project e prefere grants mais específicos. Ela anuncia
`product_grant_resolution_v1` em `/health`.

Os grants aceitam apenas a superfície read-only já definida pelo Action Gateway.
Resolver um grant **não autentica o usuário e não executa ação**. Não existe rota
Product para enfileirar/executar uma ação nesta etapa.

O token de operador **não é identidade do usuário Product** e não pode ser reutilizado
pelo Product MCP para agir em nome de um usuário.

O Worker agora possui uma fundação de autenticação Product separada:
`GET /v3/product/session` aceita somente JWT assinado e valida issuer, audience,
expiração, not-before e assinatura via JWKS HTTPS. A autenticação é provider-neutral
e só é habilitada quando `PRODUCT_AUTH_ISSUER`, `PRODUCT_AUTH_AUDIENCE` e
`PRODUCT_AUTH_JWKS_URL` estão configurados. Sem essa configuração, a rota falha
fechado. Nesta etapa ela apenas comprova o `subject_id`; não resolve grants nem
enfileira ações.

## Segurança

- token administrativo separado do token do dispositivo e da futura identidade Product;
- token do dispositivo armazenado somente como SHA-256 no D1;
- binding máquina/dispositivo;
- API tipada e allow-list local;
- URLs temporárias de leitura para artifacts;
- sem shell remoto genérico.

### Terminal report replay

Terminal job results carry a unique `report_id` stored in D1. An identical replay
with the same lease, execution epoch, runtime identity, status, result digest,
canonical result JSON and error code is acknowledged as already committed. Any divergent
replay is rejected as `terminal_report_conflict`.

### Durable terminal outbox

The Device Agent persists terminal reports under its local state directory before
network delivery. Startup recovery uses `POST /v3/device/recover-report` with the
device credential and the original execution context, before opening the device
WebSocket. D1 accepts the report only if that execution context is still current,
or acknowledges it if the identical terminal report was already committed.

A `running` job is never re-leased automatically. It fences later jobs for that
device until terminal recovery succeeds or an operator resolves the stalled job.
This prevents an expired lease from becoming an implicit second execution of a
Blender/Unity/Git mutation.


## Product identity provider

Production deploys are configured to use the OrdaX Supabase Auth project as the
Product identity provider:

- issuer: `https://eobcxuyvhkvdmkbaihwh.supabase.co/auth/v1`
- audience: `authenticated`
- JWKS: the project's `/.well-known/jwks.json`

These values are public verification metadata, not secrets. The deploy performs
a live preflight and refuses to publish the Worker unless the JWKS endpoint is
HTTPS and exposes at least one usable RS256 or ES256 key with a `kid`. This
prevents a legacy HS256 configuration from making Product authentication appear
ready when the Worker cannot verify it safely.


## Production deployment gate

Cloudflare v3 production deployment can still be started manually, but normal
mainline deployment is now chained to the repository's `Bridge CI` workflow.
The deploy job runs only when that workflow completed successfully for
`main`, and it checks out the exact `workflow_run.head_sha` that passed CI.

This prevents production from racing ahead of Python tests, Worker compilation
or the Cloudflare v3 E2E gate. The existing JWKS preflight and post-deploy
`product_auth_configured=true` health requirement remain mandatory.
