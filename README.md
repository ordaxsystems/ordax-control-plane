# OrdaX Platform

Canonical remote platform repository for OrdaX: provider-neutral Control Plane, Product MCP, PostgreSQL/Supabase integration, Cloudflare edge foundation and provider connectors.

## Product device discovery — source increment 2026-10-09

`ordax_targets` projects canonical Product fields (`device_name`, reported `online`, `last_seen_at`, `grant_groups`) and legacy D1 fields (`name`, `grants`). Canonical names and capability/access-mode descriptions survive MCP projection. Missing/invalid presence stays `null`; timestamps do not manufacture connectivity. Private fields and internal grant-group identifiers are not exported. Discovery is not authorization, a live reachability guarantee, synchronization or a cloud executor.

The Studio client in `ordaxsystems/ordax-apps` rechecks discovery before new local-device actions. Queue/grant/audit semantics and accepted requests remain unchanged. Platform owns MCP projection, Runtime owns device execution, OS owns Web composition. Tests: `node --test control-plane/tests/*.test.mts`, covering canonical/legacy/offline/malformed/unauthenticated discovery. Source/CI does not prove deployment or a real-device test; production is a separate gate.

Migrated from washingtonmsdj/mcp-blender at commit ce31808f950e04207f028c5925cca2da17d18553 on 2026-10-05.

This repository owns remote protocol/OAuth/grant resolution/queueing/audit and thin provider connectors. It does not own ORDAX Studio portable source or the device Runtime.



## Repository identity

Canonical repository: `ordaxsystems/ordax-platform`.

`ordaxsystems/ordax-control-plane` is the immediately previous repository name after the organization transfer. GitHub redirects are compatibility only and must not be used as a source of truth.
