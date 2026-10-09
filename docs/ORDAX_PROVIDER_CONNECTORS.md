# ORDAX provider connectors

## Purpose

ORDAX Studio and ORDAX Runtime are provider-neutral.

ChatGPT, Grok, Claude, Gemini, Codex, local models and future AI products are **clients** of the ORDAX capability boundary. They are not separate Studio runtimes and must not fork the local implementation of files, Git, processes, computer control, Blender, Unity or other capabilities.

## Canonical flow

```text
AI client / provider integration
        │
        │ provider-facing auth/protocol
        ▼
ORDAX provider connector
        │
        │ authenticated ORDAX protocol / MCP
        ▼
ORDAX Control Plane
        │
        ▼
ORDAX device/platform runtime
        │
        ▼
typed capability implementation
```

On Windows, the device/platform runtime is `ORDAX Runtime.exe`.
On OrdaX OS, equivalent capabilities are provided by platform-owned runtime ports/services. The Studio app consumes those ports rather than bundling a second operating-system runtime.

## Naming

The user-facing application and ChatGPT connector display name are **ORDAX Studio**.
The connector's stable package identity remains `ordax-chatgpt`; its display name
and version are owned by `plugins/ordax-chatgpt/plugin.json`. The existing builder
packages that single source. Sharing a display name does not transfer app, Runtime
or platform ownership to the connector. Future providers retain their own thin
protocol boundary and independent versioning.

`Codex` has no structural role in ORDAX. If an authorized Codex integration exists, it is another client/connector under the same rules and receives no implicit privilege.

## Client metadata

Provider/product identity may travel with an authenticated request for policy, audit, revocation and UX:

```text
actor
client.type
client.provider
client.product
device
grant
action
payload
```

Examples of metadata values might include `provider=openai, product=chatgpt` or `provider=xai, product=grok`.

Metadata is not authority. Execution still requires the normal ORDAX authentication, device binding, grants and local/device policy.

## Connector responsibilities

A provider connector may own:

- provider-facing manifest/discovery metadata;
- provider OAuth or another supported provider authentication flow;
- translation between provider tool protocol and the ORDAX typed protocol;
- connector-specific UX/copy required by that provider;
- provider-specific quota/cost disclosures where applicable;
- connector versioning and compatibility checks.

A connector must not own or duplicate:

- ORDAX Identity;
- ORDAX grant minting authority;
- device pairing authority;
- local filesystem/computer policy;
- capability execution implementations;
- Memory/Intelligence platform implementations;
- updater/trust roots;
- unrestricted terminal or shell authority.

## Capability invariance

The same authorized capability must execute through the same runtime handler regardless of provider.

Correct:

```text
ChatGPT ─┐
Grok ────┼─> ORDAX action `computer.text_read` ─> one runtime implementation
Other ───┘
```

Incorrect:

```text
chatgpt_text_read()
grok_text_read()
codex_text_read()
```

Provider-specific behavior belongs at the connector/protocol edge, not inside the capability implementation.

## Security

- connector identity does not bypass grants;
- Studio UI is not an authorization boundary;
- the Control Plane cannot bypass local device policy;
- connectors cannot mint local authority;
- sensitive provider credentials stay in the appropriate provider/auth boundary and are never embedded in Studio source;
- capability calls remain typed and auditable;
- mutating actions retain the same confirmation/policy semantics regardless of provider;
- removing a connector must not damage Studio data or platform state.

## Versioning

Studio, Runtime and connectors version independently.

App, Runtime and connector versions come from their own canonical manifests;
the shared display name does not couple releases. Compatibility is defined by
published ORDAX protocol/contract versions.

## Relationship to OrdaX OS

The portable Studio app source is owned by
[ordaxsystems/ordax-apps](https://github.com/ordaxsystems/ordax-apps/blob/main/docs/STUDIO-BOUNDARY.md).
Windows/device execution is owned by `ordaxsystems/ordax-runtime`; OS services
and composition are owned by `ordaxsystems/ordax-os`. This repository owns the
remote Control Plane, Product MCP and thin connectors. Source ownership does
not prove package distribution, installed compatibility or production activation.

OS Intelligence reuse follows its existing composition: Identity/Space → Memory
→ Intelligence → Model Router → Local AI. See the
[canonical OS contract and composition](https://github.com/ordaxsystems/ordax-os/blob/main/docs/INTELLIGENCE.md).
The [context-continuity fix](https://github.com/ordaxsystems/ordax-os/pull/1556)
rejects pending old-owner/Space results; it is source evidence, not plugin activation.
The connector translates protocols and presents results; it must not reproduce
Memory retrieval policy, model selection, profiles or execution authority.

Currently `app_intelligence_catalog` and `app_intelligence_detail` read declarative,
version-bound app semantics through existing typed device actions. They do not
invoke the OS model, retrieve global/account Memory or grant execution. Device
presence also proves no such capability. The plugin does not yet invoke OS IA.

Remote OS Intelligence consumption requires a public authenticated transport,
an exact client/device binding and explicit context/egress authorization, with
bounded provenance-bearing results and account/Space continuity. It must respect
the OS's consultative `authority=none` boundary; executing a proposed action
still uses the canonical capability/grant/audit path. Do not expose a private
Native endpoint, infer local Memory access from login or silently retarget/replay
a request. Until those owner contracts and consumers are implemented and proven,
do not advertise that installing this connector enables OS IA or cloud execution.
