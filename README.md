# OrdaX Platform

Canonical remote platform repository for OrdaX: provider-neutral Control Plane, Product MCP, PostgreSQL/Supabase integration, Cloudflare edge foundation and provider connectors.

## Studio connector and OS Intelligence boundary

The ChatGPT connector displays **ORDAX Studio**; its stable `ordax-chatgpt`
identity and independent version come from `plugins/ordax-chatgpt/plugin.json`.
The portable app remains owned by Apps and device execution by Runtime/OS.
The canonical integration guide now identifies the existing OS Intelligence
chain, distinguishes app semantics from model/Memory access and records the
public transport/context/egress gates still required. This source change does
not activate OS IA or update an installed connector. See
[provider boundaries](docs/ORDAX_PROVIDER_CONNECTORS.md#relationship-to-ordax-os)
and [connection guide](docs/PRODUCT_MCP_CONNECT.md).

## Product MCP reads — source increment 2026-10-09

Worker transport/source checks previously stranded in Runtime now run in
`tests/test_device_transport_contract.py` at their Platform owner. They cover
multipart integrity, grant/admin revocation, canonical project/browser scopes,
execution fencing and the existing retention deployment blocker. These checks
do not restore the retired D1 retention prototype or activate production.

Canonical device presence now has a source HTTP contract at
`POST /v3/product/device/presence`, wired to the existing PostgreSQL device
credential and presence RPCs. It accepts only device-authenticated observations,
keeps coalesced heartbeat receipts distinct from failure, and adds no D1 write,
grant or execution channel. The current Runtime heartbeat remains legacy and
does not call this route; coordinated consumer migration and production
activation remain pending. See [contract, tests and acceptance](docs/PRODUCT_DEVICE_PRESENCE.md).

`ordax_targets` projects canonical Product fields (`device_name`, reported `online`, `last_seen_at`, `grant_groups`) and legacy D1 fields (`name`, `grants`). Canonical names and capability/access-mode descriptions survive MCP projection. Missing/invalid presence stays `null`; timestamps do not manufacture connectivity. Private fields and internal grant-group identifiers are not exported. Discovery is not authorization, a live reachability guarantee, synchronization or a cloud executor.

The Studio client in `ordaxsystems/ordax-apps` rechecks discovery before new local-device actions. Queue/grant/audit semantics and accepted requests remain unchanged. Platform owns MCP projection, Runtime owns device execution, OS owns Web composition. Tests: `node --test control-plane/tests/*.test.mts`, covering canonical/legacy/offline/malformed/unauthenticated discovery. Source/CI does not prove deployment or a real-device test; production is a separate gate.

**Route cutover still pending (#42):** `index.ts` currently supplies legacy D1 target/action handlers to `/mcp` and Product REST. Preserving canonical fields in the projection does not switch those lookups to PostgreSQL. `createCanonicalProductMcpReadHandlers` in `product_mcp_reads.ts` composes verified OAuth owner/exact-client identity with the existing `ordax_list_product_targets_v1` and `ordax_get_product_action_v1` adapters. It is tested source for the coordinated cutover, not an activated route. Action/grant/status consumers must migrate together before publication; no mixed authority or fallback is introduced.

Discovery source tests cover signed OAuth identity, spoofed caller fields, distinct clients, offline devices, changed/empty authority results, ineligible accounts, malformed catalogs and PostgreSQL failures. They use signed test tokens and a controlled RPC reader, with the default adapter's unconfigured path also exercised. They do not prove deployed database filtering, OAuth consent, Runtime reachability or E2E execution. See [connection and migration status](docs/PRODUCT_MCP_CONNECT.md#descoberta-dos-dispositivos-da-conta).

Status source tests cover the same OAuth boundary, exact request UUID, another owner/client, account ineligibility, all six canonical lifecycle states, malformed records and database failures. Accepted history reads do not enumerate devices, create or replay work. HTTP exposes only the published action fields and the Runtime-owned Product result; canonical `project_id` survives MCP projection without inventing a legacy project slug. MCP JSON and canonical read responses use `Cache-Control: no-store`. Runtime queue/binding migration remains a dependency, documented with pinned consumer evidence in the connection guide.

The existing MCP facade also rejects malformed successful HTTP envelopes: session probes cannot authenticate from HTTP 200 alone; missing catalogs/status/ACKs and unknown lifecycle states become explicit tool errors. A failed status read keeps the accepted request ID without another dispatch. JSON responses are bounded at 2 MiB with UTF-8 validation using the existing stream reader; failed parsing cancels/releases the reader. Exceptions, failed acknowledgement bodies and arbitrary grant-denial columns are not forwarded to the provider. Tests exercise the public MCP handler, including malformed/oversized responses and exactly one dispatch on post-acceptance status failure. These source fixes still require the production gate before publication.

Migrated from washingtonmsdj/mcp-blender at commit ce31808f950e04207f028c5925cca2da17d18553 on 2026-10-05.

This repository owns remote protocol/OAuth/grant resolution/queueing/audit and thin provider connectors. It does not own ORDAX Studio portable source or the device Runtime.



## Repository identity

Canonical repository: `ordaxsystems/ordax-platform`.

`ordaxsystems/ordax-control-plane` is the immediately previous repository name after the organization transfer. GitHub redirects are compatibility only and must not be used as a source of truth.
