# Canonical Product device presence — HTTP v1

Owner: `ordaxsystems/ordax-platform`. MVP-04/Studio device discovery; tracking
issue #42. Runtime remains the device execution owner, Apps owns Studio UX,
and OS owns Web composition. This increment exposes the **existing** presence
and device-credential RPCs through the Worker. It creates no identity registry,
grant, command queue, heartbeat loop, device pairing or project mapping.

## Published source contract

`POST /v3/product/device/presence`

Headers:

- `Content-Type: application/json` (optional charset parameter);
- `X-Ordax-Device-Id`: the canonical Product device UUID;
- `X-Ordax-Device-Token`: the existing device credential, 32–512 printable ASCII
  characters. This is not an account/OAuth access token.

Complete metadata snapshot, limited to 16 KiB of decoded UTF-8 JSON:

```json
{
  "online": true,
  "runtime_kind": "desktop-agent",
  "agent_version": "1.30.1",
  "capability_digest": null
}
```

`online` is a boolean. `runtime_kind` is `ordax-os`, `desktop-agent`,
`mobile-client`, `other`, or explicit null. `agent_version` is null or a
1–80-character string without surrounding whitespace/control characters.
`capability_digest` is null or a lowercase SHA-256 hex digest. The digest
describes metadata; it never authorizes a capability. All four fields are
required; extra fields, including owner/client/grant/force/timestamps, fail.
Device display name and ownership remain in their existing identity contract.

The handler computes the credential SHA-256 and calls only
`ordax_authenticate_product_device_v1`, which resolves the matching unrevoked
credential and active device. Only a literal true receipt permits calling
`ordax_record_product_presence_v1` for **that same UUID**, with `force=false`.
Token material is not sent to the presence RPC, echoed or logged. Caller body,
query metadata and bearer identity cannot select another writer.

Success: `{"ok":true,"device_id":"<UUID>","changed":true}`.
The existing authority coalesces unchanged observations inside its five-minute
window; `changed:false` is an accepted receipt, not a failed heartbeat. The
handler does not manufacture `last_seen_at` or claim an observation timestamp
changed on every request. Explicit `online:false` uses the same authenticated
contract.

Responses use `Cache-Control: no-store`. Invalid credentials/revocation yield
401, invalid snapshots 400, unsupported MIME 415, and other methods 405 with
`Allow: POST`. Malformed RPC receipts yield 502. Missing PostgreSQL or a
transport failure yields a bounded public 503 code without SQL, credentials or
backend exception details. There is no D1/DO fallback or automatic retry/write.

## Presence is an observation, not execution readiness

The credential check and presence write reuse two existing RPCs. They do not
establish an atomic execution authorization, agent-session fencing or a command
channel. Concurrent sessions follow the existing presence authority; no local
sequence number or lease is invented. An old session's offline observation and
a newer session's online observation require a canonical session/fencing
contract before stronger ordering guarantees can be announced.

An abrupt shutdown may not send an offline report. The response does not imply
fresh reachability, and this increment adds no arbitrary offline timeout.
Discovery keeps the authority's reported online value and last-seen timestamp;
login alone does not mean online, connected devices do not receive grants, and
presence alone does not release Studio actions or prove Runtime delivery.

Runtime's current single heartbeat/command channel is still the legacy
`/v3/device/ws` transport backed by D1. **It does not call this new endpoint.**
Its consumer must migrate with credential identity, command delivery, existing
gateway/local policies, canonical project bindings, leases/reports and audit.
Do not add a second heartbeat thread or D1/PG dual writes to make the device
appear ready. Devices enrolled in PostgreSQL are not thereby enrolled in the
legacy WebSocket registry.

## Validation, risk and acceptance

`control-plane/tests/product_device_presence.test.mts` tests the public HTTP
handler with controlled RPC transports: same-device credential hashing,
accepted/coalesced/offline snapshots, revocation, caller spoofing, strict
metadata/MIME, bounded/invalid UTF-8 JSON and reader cleanup, malformed RPC
receipts, unavailable authority and no replay. It also checks Worker dispatch
and exercises the default adapter's unconfigured path. The full Node suite,
Python authority/deployment contracts and pinned Wrangler dry-run must pass.
Tests do not exercise a deployed database or authenticated physical device.

Risk: presence could be mistaken for execution availability, or heartbeat
coalescing for failure. Acceptance requires preserving the receipt semantics
and existing production gates, with no changes to grants/queue/bindings.
The source route is wired in `index.ts`; the current production foundation is
still blocked. CI, source wiring and a compile dry-run are **not deployment**,
installation, account/device E2E or plugin activation. Production readiness and
coordinated Runtime/MCP cutover remain separate work.
