# PostgreSQL product remote authority

This directory owns the PostgreSQL migrations for the end-user ORDAX remote
authority.

The canonical persistent database is:

- Supabase project: `ordax-platform` (ref `jhfphsjptrpmtnzkpwud`; production environment unchanged)
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

## Product capability grants: client-scoped execution (proposed)

The canonical grant group and target lookup contract binds both
`client_kind` and `client_id`. Migration
`20261007203000_product_client_grant_isolation_v1.sql` makes action
enqueue use this **same** exact identity, and records `client_id` in
private action requests and audit entries. Replayed idempotency requests
must match the same client. The superseded enqueue/resolver signatures
must not remain executable; the new enqueue requires a non-null client ID.

Cloudflare must derive `client_id` from a verified, bound credential /
OAuth client identity, **never** from request body fields or other
untrusted action payload. This migration **alone does not enable the
Product endpoint cutover**: JWT subject mapping, client verification,
MCP consumer contracts and end-to-end execution tests still gate the
`product_remote_authority` status in
`control-plane/cloudflare/d1-cutover-authority-map.json`.

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

The applied ledger is locked in `migration-registry.json`. It records the exact
canonical project, Supabase ledger version, source repository/path and Git blob
for every approved migration. CI verifies that every SQL file in this directory
matches its locked Git blob and that no unregistered canonical migration exists.

Only historical migrations `0001` through `0007` are approved from the old
`prototipo-ordax-os` migration root. The many later sync/network/legal/quota
migrations that still exist in that historical directory are **not** authorized
for replay into the São Paulo database merely because the files exist.

For a new migration, the operational sequence is:

1. create the SQL on a branch and open a PR before touching the live database;
2. apply it exactly once to `jhfphsjptrpmtnzkpwud`;
3. add the returned Supabase ledger version and the migration Git blob to the
   registry in the same PR;
4. merge only after the registry has no pending entry and CI is green.

The registry also records the few historical cases where the checked-in file is
SQL-equivalent to the ledger but differs only in formatting/comments. Those
files are now pinned and must not drift further.

The files
`20261007181500_edge_runtime_role.sql` and
`20261007182000_remove_unprovisioned_edge_login.sql` preserve exact migration
history already executed on the canonical project. The later
`20261007200000_edge_runtime_login_v1.sql` introduces the stable environment
LOGIN identity `ordax_edge_runtime` only after the Cloudflare boundary is ready.
The role shape is versioned in Git, but the password is provisioned and rotated
out-of-band and must never be committed.

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
DML authority over the Product remote device/presence/binding/grant tables. The environment LOGIN identity `ordax_edge_runtime` inherits only
`ordax_edge_executor`. It receives no direct table/routine authority. Its
credential is deployment state, not migration source, and must be provisioned
out-of-band before Hyperdrive can become ready.

Private Product action tables grant no direct access to browser roles or to the
edge executor. Server authority enters only through narrowly reviewed
`SECURITY DEFINER` RPCs with pinned `search_path`.

## Generic service role is fail-closed

The Supabase `service_role` is not an ORDAX application executor. It has no
direct privileges on canonical ORDAX Product tables and no EXECUTE privilege on
the Product RPC surface.

This is deliberate even though `service_role` can bypass RLS: server-side
product mutation must not depend on a generic bypass credential. Each mutation
domain must expose a reviewed RPC to a dedicated NOLOGIN executor, with any
environment LOGIN credential provisioned separately through secret management.

The Auth bootstrap trigger remains owned by `postgres`; revoking
`service_role` from `ordax_accounts` does not affect account-row bootstrap.

## Custom roles and PUBLIC inheritance

Custom PostgreSQL roles receive privileges granted to `PUBLIC` even when they
have no explicit grant. The canonical database therefore removes `PUBLIC`
USAGE/CREATE from the `public` schema. Data API roles and reviewed executors
keep only their explicit schema grants.

This prevents a future NOLOGIN executor from acquiring the exposed schema merely
because the role was created. Schema USAGE, function EXECUTE and relation
privileges must all be granted intentionally.

Database-level `TEMPORARY` remains a separate platform-wide concern because it
is also inherited from `PUBLIC`; it must not be changed casually without
proving Supabase-managed service compatibility.

## Default privileges

Future objects created by `postgres` in `public` and `private` are
fail-closed. Default table/sequence access for API roles is revoked, and new
functions do not inherit EXECUTE through `PUBLIC` or server/runtime roles.

Any intentional Data API or server exposure must therefore be granted explicitly
in the same versioned migration that creates or changes the object. RLS and SQL
privileges are separate controls; both must remain correct.

## Server-authoritative mutation policies

Authenticated users retain only the table privileges intentionally exposed for
reads and the narrow account display-name update. Dead INSERT/UPDATE/DELETE RLS
policies from the original direct-client foundation are removed once matching
table DML is revoked, so a future accidental GRANT cannot resurrect a hidden
client mutation API.

## Subject-aware authorization SSOT

Server executors must authorize an explicit subject without impersonating
`auth.uid()`. The canonical private helpers therefore centralize Space access,
Space administration, Project access and Product Device access around
`(subject_user_id, resource_id)`.

Existing RLS functions remain thin `auth.uid()` wrappers over those helpers.
The subject-aware helpers are not executable by `anon`, `authenticated`,
`service_role` or `ordax_edge_executor`; they are internal authorization
building blocks for reviewed SECURITY DEFINER boundaries.

## Space authority

Space mutations use a dedicated NOLOGIN/NOINHERIT `ordax_space_executor`.
The role has schema USAGE and explicit EXECUTE only on the reviewed Space RPCs;
it has no direct table/sequence authority and no private-schema access.

`ordax_spaces.owner_user_id` is the only ownership SSOT. Member rows represent
only `admin`, `member` or `viewer`; they cannot create a second owner
concept. Space `kind` is fixed at creation, while the update RPC may change
only name, state and metadata.

No environment LOGIN member is provisioned by the database baseline. Wiring a
runtime credential to this executor is a separate deployment gate.

## Project authority

Project identity mutations use a dedicated NOLOGIN/NOINHERIT
`ordax_project_executor`. The role has no direct relation authority and may
execute only the reviewed create/update Project RPCs.

Projects are provider-neutral Space-scoped identities. Creation requires an
active Space plus Space-admin authority. `created_by_user_id` is immutable
provenance, not a second owner. Project `kind` is fixed at creation; update may
change name, state and metadata. Archiving is the lifecycle boundary instead of
a generic delete RPC.

Repository connections remain a separate read-only metadata surface. The
database enforces explicit GitHub repository selection (positive installation
and repository IDs plus bounded `owner/repository` full name) and one selected
GitHub repository per Project. No connection mutation RPC is created until the
separate approval/audit gateway exists.

## Entitlements and Profile Pack assignment

Entitlement grants are authorization/billing evidence, not a general CRUD
surface. The canonical database retains them as server-owned read-only rows.
No ad-hoc entitlement issuer or billing operator is created here; issuing or
revoking financial/product entitlements requires a separately reviewed source,
idempotency contract and audit boundary.

Profile Pack definitions (`public.ordax_profile_packs`) stay migration-owned
and versioned. Draft/retired manifests are not exposed through the client
SELECT policy, which admits only active catalog versions. The two bootstrap
packs remain draft until a reviewed activation migration.

An active Space administrator may select an existing **active** pack version or
clear the selection through `ordax_profile_pack_executor` (NOLOGIN, NOINHERIT,
NOBYPASSRLS). This executor has no direct table, sequence, or private-schema
authority: only `ordax_select_space_profile_pack_v1` and
`ordax_clear_space_profile_pack_v1` are executable. Both require the trusted
server to authenticate the actor before passing its UUID to the RPC.

The current selection SSOT remains `public.ordax_space_profile_packs`.
Changes are serialized per Space, repeated commands are idempotent, and every
effective selection/clear is recorded in the private append-only
`ordax_space_profile_pack_events` table. This record is not another current
state, and has no direct client/operator access.

Arbitrary per-Space configuration is intentionally unavailable at this stage:
selection stores an empty JSON object rather than accepting an unreviewed
configuration containing credentials or executable instructions.

## Default entitlement ledger (no billing authority)

The canonical `public.ordax_entitlement_grants` table remains the entitlement
state SSOT. Issuance and revocation provenance is recorded through a source
event ID and a private event journal. The pair `(source, source_event_id)` is
unique; retries with identical inputs replay a receipt and different inputs
using the same event ID fail closed.

`ordax_entitlement_default_executor` is a NOLOGIN/NOINHERIT/NOBYPASSRLS
role with **no direct relation privileges**. Only
`ordax_issue_default_entitlement_v1` and
`ordax_revoke_default_entitlement_v1` are callable by that executor.
The source is hard-coded to `product-default`. The issuer obtains value and
duration from an approved version of
`private.ordax_default_entitlement_policies` rather than accepting arbitrary
entitlement JSON, dates, or a caller-selected source. That catalog is empty
at baseline; publishing a policy requires a separate reviewed migration.
Only account-scoped defaults are supported here. Issuance serializes by event
and subject/key to prevent parallel duplicate active default grants.

Revocation preserves the original grant row, shortens its effective validity,
and appends an event; there is no normal hard-delete API. The event journal is
private and has no direct client, service_role, or executor privileges. Events
are cleaned up with their grant/account through FK cascades, subject to the
future account lifecycle policy. No permanent post-deletion personal-data
retention is implied.

**Production remains fail-closed:** creating the NOLOGIN role does not issue
a credential or authorize an external caller. A trusted service must verify
the event's origin and target identity *before* invoking an RPC through a
separately provisioned credential. Billing, promotion, admin issuance, paid
subscription state and event signature validation are deliberately out of scope
until their own signed/verified origin, idempotency, revocation and audit
contracts exist. Do not expose this role via an unauthenticated edge handler.

## Memory authority

Durable Memory uses a dedicated NOLOGIN/NOINHERIT `ordax_memory_executor`
with explicit EXECUTE only on reviewed Memory RPCs and no direct relation
authority.

The durable identity model is intentionally limited to `account`, `space`
and `project`. Project-scoped memory uses the canonical `project_id` plus
`space_id` foreign key; the old textual `project_ref` is removed. Device and
session state are not stored as fake durable Memory scopes without canonical
identity.

Creation binds `owner_user_id` to the explicit actor. Space and Project
scopes require subject-aware access through the canonical authorization helpers.
Scope, kind and ownership remain immutable after creation; normal removal is a
soft state transition to `deleted`, not physical deletion.

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
