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

The user-facing application is **ORDAX Studio**.

Provider-specific integration surfaces may use names such as:

- `ORDAX for ChatGPT`;
- `ORDAX for Grok`;
- future provider-specific connectors.

These names identify the connector boundary only. They do not rename Studio or Runtime.

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

```text
ORDAX Studio             12.x
ORDAX Runtime            1.x
ORDAX for ChatGPT        3.x
ORDAX for Grok           1.x
```

Compatibility is defined by published ORDAX protocol/contract versions, not by coupling releases together.

## Relationship to OrdaX OS

The long-term first-party Studio app boundary is defined in `washingtonmsdj/ordax-apps/docs/STUDIO-BOUNDARY.md`.

The Windows implementation in this repository is the current source of truth for the Windows host/runtime path until the app package lifecycle and source cutover gates are proven. Do not create a parallel Studio source tree merely to match the target repository layout.
