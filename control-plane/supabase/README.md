# PostgreSQL product remote authority

This directory owns the PostgreSQL migrations for the end-user ORDAX remote
authority. The canonical database is the existing Supabase project
`ordax-control-plane`.

## Architecture

```text
ChatGPT / ORDAX Web / Mobile
            |
            v
    Cloudflare Worker
            |
     +------+------+
     |             |
     v             v
Durable Objects  Supabase/PostgreSQL
hot WebSocket    durable source of truth
session state    grants / actions / receipts / audit
     |
     v
ORDAX Runtime

R2 remains the byte store for large artifacts.
```

Cloudflare is the edge and realtime transport. PostgreSQL is the durable source
of truth for Product identity-linked remote authorization and action state.

This split is deliberate: moving the Worker, Durable Objects and R2 to another
Cloudflare account must not require moving the canonical ORDAX product database.

## No dual-primary fallback

D1 and PostgreSQL must never both accept authoritative Product mutations. During
migration, D1 remains the live legacy authority until an explicit one-way cutover
is proven. Shadow reads are allowed only for verification; dual writes and
automatic D1/PostgreSQL failover are forbidden because they can create split
brain in grants, leases and terminal reports.

## Product vs engineering authority

Product remote execution is intentionally separate from the engineering queue.
Product Web/Mobile/MCP credentials never inherit developer/operator authority.

Canonical Product rows use:

- `public.ordax_product_devices`;
- `public.ordax_space_devices`;
- `public.ordax_device_project_bindings`;
- `public.ordax_remote_capability_grants`;
- private Product action/event/audit tables introduced by the migration in this
  directory.

Device-scoped grants use `scope_kind = 'device'` with no synthetic project.
Project-scoped grants require a real `project_id` and an active device/project
binding.

## Server-only database access

Cloudflare calls reviewed PostgreSQL RPCs through Supabase's Data API. The Worker
uses a dedicated modern `sb_secret_...` key in the `apikey` header only.

The secret is never committed, returned to a Product client, used as a
browser/desktop credential or placed in a bearer authorization header. It should
be a dedicated key for the Control Plane so it can be rotated independently when
Cloudflare infrastructure moves accounts.

Private Product action tables grant no direct access to browser roles or to the
server role. Server authority enters only through narrowly reviewed
`SECURITY DEFINER` RPCs.

## Presence and scale

Durable Objects own hot connection state. Ordinary WebSocket heartbeats must not
write PostgreSQL every few seconds.

The persistence RPC coalesces unchanged presence and writes at most periodically
(currently five minutes) unless connection state, runtime version or capability
digest changes. Connect/disconnect transitions may force an immediate write.

## Cutover gates

D1 can stop being the Product authority only after all of these are proven:

1. PostgreSQL migration is applied and security/performance advisors are reviewed.
2. Worker uses the server-only PostgreSQL adapter for Product targets, grants and action lifecycle.
3. Existing live device identity/pairing is migrated without synthetic IDs.
4. Durable Object delivery uses PostgreSQL leases/fencing and terminal replay.
5. Shadow comparison shows equivalent authorization decisions.
6. ChatGPT -> Product MCP -> Worker -> Runtime -> receipt/audit passes end to end.
7. D1 Product writes are disabled before PostgreSQL Product writes become authoritative.

The Cloudflare-account move is a later infrastructure operation and must not be
combined with the database-authority cutover.
