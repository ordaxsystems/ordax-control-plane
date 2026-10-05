# OrdaX Action Gateway — contrato read-only inicial

Status: foundation only. This module is **not** a public network server.

## Objetivo

`ProductActionGateway` is the shared execution facade intended for future
OrdaX Product MCP and OrdaX Web clients. It reuses the Device Agent's existing
typed actions instead of creating a second backend or a second permission model.

The Control Plane remains responsible for authenticating identity and resolving
persisted grants. The gateway receives both a verified `ProductRequestContext`
and an already-resolved `ProductGrant`; it fails closed when subject, Space,
device, expiry, action or project scope does not match.

## Initial read-only surface

A superfície remota é o braço autenticado do **ORDAX Studio Remote MCP**. Ela permanece deliberadamente read-only nesta fase e expõe contexto suficiente para uma conversa remota entender e revisar o workspace sem ganhar shell genérico.

- `projects.list`
- `workspace.repository_catalog`
- `project.inventory`
- `project.text_read`
- `project.search_text`
- `project.text_read_batch`
- `project.preview_status`
- `agent.project_health`
- `artifacts.list`
- `git.status`
- `git.diff`
- `artifact.preview`

This first surface intentionally excludes:

- `project.text_write` and `project.text_patch`;
- `git.sync`;
- Blender and Unity execution actions;
- `artifact.read_chunk` bulk transfer;
- generic shell access;
- implicit wildcard grants.

## Privacy boundary

The local Device Agent may legitimately know workstation-specific absolute
paths. Product-facing results remove those details where the existing local
action returns them:

- project roots are removed from project discovery/inventory and repository catalog results;
- health responses remove memory database/context paths and Git command paths;
- preview status removes local URLs, PIDs, ownership tokens, command lines, log paths and absolute image paths;
- Git command arrays are removed because they contain local paths;
- artifact absolute paths are removed from previews;
- project discovery omits private adapter configuration.

The project slug, relative project paths, bounded text content, bounded diffs,
bounded artifact metadata and explicitly granted artifact preview bytes remain
available.

## Execution contract

A Product action executes only when all of these are true:

1. the action exists in the explicit Product read-only catalog;
2. the caller-supplied grant contains that action;
3. project-scoped actions include a project slug;
4. the grant contains that project;
5. the payload contains only fields approved for that action;
6. the mapped local Device Agent action is installed.

There is no default grant.

## Grant provenance and audit

A resolved grant carries a stable grant id, authenticated subject id, explicit
actions/projects, optional Space/device scope and optional expiry. The gateway
validates the grant structure at runtime instead of trusting Python type hints.

Execution also requires an audit sink. Before any local action runs, the gateway
must persist an authorization event. After the local read finishes, it persists
a result event before returning Product-facing data. If pre-execution audit
persistence fails, the local action does not run. If result-audit persistence
fails, the Product result is withheld.

Audit events contain identifiers, action/project, decision, phase and only the
**names** of payload fields. They do not copy text-file contents, Git diffs,
artifact bytes or other payload values into the audit record.

## Control Plane persistence boundary

Cloudflare v3 now has the administrative persistence foundation for this
contract: D1 stores Product grants and the audit schema, and the Worker can
create/list/revoke only the same explicit read-only action set.

The Control Plane also has a shared grant-resolution primitive that evaluates
subject, optional Space/device scope, action, project, expiry and revocation.
Its current HTTP surface is operator-only diagnostic plumbing; the resolver is
intended to be reused after real Product authentication is added.

The operator credential remains administrative only and never becomes the
authenticated Product subject. Product execution now uses the separate JWT/JWKS
identity path, live grant resolution, dedicated read-only jobs and mandatory
gateway audit persistence.

## Product MCP facade

`ordax_dev_agent.product_mcp.ProductMcpFacade` now defines the first read-only
Product MCP tool surface without creating a public server. It maps MCP-friendly
tool names to this gateway and still requires a verified `ProductRequestContext`
plus a resolved `ProductGrant` on every call.

The facade intentionally performs no authentication, grant lookup, network I/O
or credential handling. Mutation tools are not registered. This keeps Product
MCP and OrdaX Web on the same authorization/audit path instead of duplicating
allow-lists.

## Current integration boundary

`/v3/product/session` remains an identity probe only. Actual read-only execution
uses `/v3/product/actions`, live grant resolution and the dedicated
`ordax.product.read.invoke` capability. Any future public MCP host must wrap this
same path rather than re-implementing authentication, allow-lists, grants or
audit. Mutations remain outside the Product surface.


## Authenticated read-only remote flow

The first end-to-end Product execution path is now defined without adding
mutations:

1. `POST /v3/product/actions` authenticates the Product JWT.
2. The Control Plane resolves a live grant for subject/Space/device/action/project.
3. It persists request ownership and enqueues only
   `ordax.product.read.invoke`.
4. The Device Agent intercepts that capability before the normal ActionRegistry
   path and executes it through `ProductActionGateway`.
5. Gateway authorization/result audit events are sent back through the
   device-authenticated `/v3/product/audit` route and bound to the stored
   Product request.
6. `GET /v3/product/actions/{request_id}` returns the already-sanitized result
   only to the same authenticated Product subject.

The generic operator `/v3/jobs` API is not used as Product identity. The Product
surface remains limited to the explicit read-only catalog.


## Device-bound Product targets

Until OrdaX has a persisted Account/Space-to-device ownership model, remote
Product grants must be explicitly scoped to one device. Device-null grants are
not eligible for remote execution.

Authenticated clients can discover their safe execution targets with
`GET /v3/product/targets`. The endpoint is subject-scoped, includes only active,
non-revoked, device-bound grants, and returns device id/name/last-seen plus the
exact grant action/project scopes. It does not expose device tokens, machine
bindings, operator data, or devices belonging only to other subjects.


## Product remote client

`ordax_dev_agent.product_remote_client.ProductRemoteClient` is the reusable
transport client for future Product MCP/Web hosts. It does not implement auth,
grants or policy itself; it only calls the existing authenticated Control Plane
surface:

- `/v3/product/session`
- `/v3/product/targets`
- `/v3/product/actions`
- `/v3/product/actions/{request_id}`

The Product JWT is supplied explicitly on every call and is not stored on the
client object. Polling is bounded and synchronous; there is no background worker
or hidden retry loop.


## Product MCP stdio host

`ordax-product-mcp` is the first real MCP host for the Product path. It is a
stdio MCP process intended to be launched by an MCP-capable client such as a
desktop assistant or development environment.

Configuration:

- `ORDAX_PRODUCT_CONTROL_PLANE_URL` — HTTPS Cloudflare v3 endpoint;
- `ORDAX_PRODUCT_ACCESS_TOKEN` — current Product JWT issued by OrdaX/Supabase.

The JWT is read from the host environment on each tool invocation. It is never
declared as an MCP tool argument and therefore is not exposed to the model as
normal tool input.

The host exposes only explicit read-only tools:

- `product_session`
- `product_targets`
- `projects_list`
- `project_inventory`
- `project_text_read`
- `git_status`
- `git_diff`
- `artifacts_list`
- `artifact_preview`

There is no generic `action_execute`, shell tool, Git mutation or Blender/Unity
execution tool on this Product host. Every remote operation goes through
`ProductRemoteClient` and therefore through Product JWT authentication, target
discovery, live grant resolution, the dedicated Product job capability, local
`ProductActionGateway` enforcement and mandatory audit persistence.
