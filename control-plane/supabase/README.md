# PostgreSQL product remote authority

This directory owns the PostgreSQL migrations for the end-user ORDAX remote
authority.

The canonical persistent database is:

- Supabase project: `ordax-platform-prod`
- project ref: `jhfphsjptrpmtnzkpwud`
- region: `sa-east-1` (São Paulo)
- PostgreSQL: durable source of truth

The previous Supabase project named `ordax-control-plane` is not the canonical
production database for this authority.

## Architecture

```text
ChatGPT / ORDAX Web / Mobile
            |
            v
     remote edge/API
            |
     +------+------+
     |             |
     v             v
realtime/session  Supabase/PostgreSQL
coordination      durable source of truth
                  grants / actions / receipts / audit
                         |
                         v
                   ORDAX Runtime
```

PostgreSQL is the durable authority. Edge/realtime infrastructure may transport
requests or coordinate live sessions, but it must not become a second persistent
authority.

Large binary artifacts belong in an object store, not in PostgreSQL.

## Migration SSOT and provenance

Applied migrations are immutable history. Never edit an applied migration, never
reapply it manually, and never create a second migration with equivalent effects.

The clean product bootstrap migrations `0001_product_foundation` through
`0007_projects_devices_fk_indexes` were originally versioned in
`washingtonmsdj/prototipo-ordax-os/infra/supabase/product/migrations/`. They
remain historical source provenance and are not copied into this directory.

From `20261007150000_product_remote_authority_v1.sql` onward, this directory is
the canonical source owner for Control Plane PostgreSQL authority and hardening.
New PostgreSQL changes in this domain must be introduced here first through a
branch and pull request, then applied once to the canonical project.

The files
`20261007181500_edge_runtime_role.sql` and
`20261007182000_remove_unprovisioned_edge_login.sql` preserve exact migration
history already executed on the canonical project. Their final effect is
intentional: there is no environment LOGIN role provisioned in the database.
Runtime credentials are environment-specific and must never be committed.

## No dual-primary fallback

D1 and PostgreSQL must never both accept authoritative Product mutations.
PostgreSQL is the target durable SSOT. Dual writes and automatic persistent
fallback are forbidden because they can create split brain in grants, leases,
receipts and audit.

## Product vs engineering authority

Product remote execution is intentionally separate from engineering authority.
Product Web/Mobile/MCP credentials never inherit developer/operator authority.

Canonical Product rows use:

- `public.ordax_product_devices`;
- `public.ordax_space_devices`;
- `public.ordax_device_project_bindings`;
- `public.ordax_remote_capability_grants`;
- private Product action/event/audit tables introduced by the migrations in this
  directory.

Device-scoped grants use `scope_kind = 'device'` with no synthetic project.
Project-scoped grants require a real `project_id` and an active device/project
binding.

## Server-only database access

The database exposes reviewed server-side RPCs through the NOLOGIN group role
`ordax_edge_executor`. That role has no direct table/sequence authority and no
access to the `private` schema. It receives only explicit EXECUTE grants on the
required RPCs.

`service_role` is not the executor for these remote-action RPCs and has no direct
DML authority over the Product remote device/presence/binding/grant tables. A future
environment LOGIN credential may inherit `ordax_edge_executor` only when it is
provisioned outside migrations with dedicated secret management. No such LOGIN
role is part of the canonical database baseline.

Private Product action tables grant no direct access to browser roles or to the
edge executor. Server authority enters only through narrowly reviewed
`SECURITY DEFINER` RPCs with pinned `search_path`.

## Default privileges

Future objects created by `postgres` in `public` and `private` are
fail-closed. Default table/sequence access for API roles is revoked, and new
functions do not inherit EXECUTE through `PUBLIC` or server/runtime roles.

Any intentional Data API or server exposure must therefore be granted explicitly
in the same versioned migration that creates or changes the object. RLS and SQL
privileges are separate controls; both must remain correct.

## Grant groups and target projection

Remote capabilities are replaced and revoked as explicit grant groups. The
database derives Product targets only from active, non-expired grants. A
device-scoped grant is owner-bound and has no synthetic Space/Project. A
project-scoped grant requires a real active Space/Project, execute access to the
device, an active project/device binding and capabilities present in that
binding.

The canonical grant-group migration deliberately has no `legacy` backfill. It
requires the empty foundation state that exists before public rollout and fails
closed if data is unexpectedly present.

## Presence and scale

Realtime coordination owns hot connection state. Ordinary heartbeats must not
write PostgreSQL every few seconds.

The persistence RPC coalesces unchanged presence and writes at most periodically
(currently five minutes) unless connection state, runtime version or capability
digest changes. Connect/disconnect transitions may force an immediate write.

## Cutover gates

A persistent predecessor can stop being authoritative only after all of these are
proven:

1. PostgreSQL migrations are applied exactly once and security/performance
   advisors are reviewed.
2. Runtime/edge access uses the dedicated least-privilege PostgreSQL boundary.
3. Existing required device identity is migrated without synthetic IDs.
4. Delivery uses PostgreSQL leases/fencing and terminal replay.
5. Shadow verification, when used, is read-only and never becomes dual-write.
6. Product MCP -> remote boundary -> Runtime -> receipt/audit passes end to end.
7. Legacy Product writes are disabled before PostgreSQL Product writes become
   authoritative.
