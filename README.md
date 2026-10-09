# OrdaX Platform

Canonical remote platform repository for OrdaX: provider-neutral Control Plane, Product MCP, PostgreSQL/Supabase integration, Cloudflare edge foundation and provider connectors.

## Product device discovery — source increment 2026-10-09

`ordax_targets` projects canonical Product fields (`device_name`, reported `online`, `last_seen_at`, `grant_groups`) and legacy D1 fields (`name`, `grants`). Canonical names and capability/access-mode descriptions survive MCP projection. Missing/invalid presence stays `null`; timestamps do not manufacture connectivity. Private fields and internal grant-group identifiers are not exported. Discovery is not authorization, a live reachability guarantee, synchronization or a cloud executor.

The Studio client in `ordaxsystems/ordax-apps` rechecks discovery before new local-device actions. Queue/grant/audit semantics and accepted requests remain unchanged. Platform owns MCP projection, Runtime owns device execution, OS owns Web composition. Tests: `node --test control-plane/tests/*.test.mts`, covering canonical/legacy/offline/malformed/unauthenticated discovery. Source/CI does not prove deployment or a real-device test; production is a separate gate.

**Route cutover still pending (#42):** `index.ts` currently supplies the legacy D1 `listProductTargets` handler to `/mcp` and `/v3/product/targets`. Preserving canonical fields in the projection does not switch that lookup to PostgreSQL. The new `createCanonicalProductMcpDiscoveryHandlers` composes verified OAuth owner/exact-client identity with the existing `ordax_list_product_targets_v1` adapter and shares the public MCP projection. It is tested source for the coordinated cutover, not an activated route. Action/grant/status consumers must migrate together before publication; no mixed authority or fallback is introduced.

Discovery source tests cover signed OAuth identity, spoofed caller fields, distinct clients, offline devices, changed/empty authority results, ineligible accounts, malformed catalogs and PostgreSQL failures. They use signed test tokens and a controlled RPC reader, with the default adapter's unconfigured path also exercised. They do not prove deployed database filtering, OAuth consent, Runtime reachability or E2E execution. See [connection and migration status](docs/PRODUCT_MCP_CONNECT.md#descoberta-dos-dispositivos-da-conta).

Migrated from washingtonmsdj/mcp-blender at commit ce31808f950e04207f028c5925cca2da17d18553 on 2026-10-05.

This repository owns remote protocol/OAuth/grant resolution/queueing/audit and thin provider connectors. It does not own ORDAX Studio portable source or the device Runtime.



## Repository identity

Canonical repository: `ordaxsystems/ordax-platform`.

`ordaxsystems/ordax-control-plane` is the immediately previous repository name after the organization transfer. GitHub redirects are compatibility only and must not be used as a source of truth.
