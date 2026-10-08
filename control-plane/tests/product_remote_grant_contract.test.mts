import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalRemoteClient,
  canonicalRemoteGrantGroup,
  isCanonicalUuid,
  type RemoteGrantGroupInput,
} from "../cloudflare/src/product_remote_grant_contract.ts";

const ownerUserId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const spaceId = "33333333-3333-4333-8333-333333333333";
const projectId = "44444444-4444-4444-8444-444444444444";
const base = (): RemoteGrantGroupInput => ({
  ownerUserId,
  spaceId: null,
  projectId: null,
  deviceId,
  clientKind: "product-mcp",
  clientId: "assistant:1234",
  profileKey: "computer.read",
  capabilities: [
    { capability: "computer.windows", accessMode: "read" },
    { capability: "computer.screenshot", accessMode: "read" },
  ],
  validUntil: null,
});

test("device-scoped grant keeps null space/project and ordered SQL arrays", () => {
  const args = canonicalRemoteGrantGroup(base());
  assert.ok(args);
  assert.deepEqual(args.p_capabilities, ["computer.windows", "computer.screenshot"]);
  assert.deepEqual(args.p_access_modes, ["read", "read"]);
  assert.equal(args.p_owner_user_id, ownerUserId);
  assert.equal(args.p_client_kind, "product-mcp");
  assert.equal(args.p_space_id, null);
  assert.equal(args.p_project_id, null);
  assert.equal(args.p_valid_until, null);
});

test("project-scoped grant uses actual UUID authority IDs", () => {
  const args = canonicalRemoteGrantGroup({
    ...base(), spaceId, projectId, profileKey: "project.control",
    capabilities: [{ capability: "project.text_write", accessMode: "write" }],
  });
  assert.ok(args);
  assert.equal(args.p_space_id, spaceId);
  assert.equal(args.p_project_id, projectId);
  assert.deepEqual(args.p_access_modes, ["write"]);
});

test("legacy textual subject, Space, and project slug cannot cross boundary", () => {
  assert.equal(isCanonicalUuid("user:name"), false);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), ownerUserId: "user:name" }), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), spaceId: "space-name", projectId }), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), spaceId, projectId: "my-repository" }), null);
});

test("mixed or incomplete device/project scope is rejected", () => {
  assert.equal(canonicalRemoteGrantGroup({ ...base(), spaceId }), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), projectId }), null);
});

test("duplicate, malformed or oversized capabilities and bad access modes fail closed", () => {
  assert.equal(canonicalRemoteGrantGroup({
    ...base(), capabilities: [
      { capability: "computer.windows", accessMode: "read" },
      { capability: "computer.windows", accessMode: "write" },
    ],
  }), null);
  assert.equal(canonicalRemoteGrantGroup({
    ...base(), capabilities: [{ capability: "bad capability", accessMode: "read" }],
  }), null);
  assert.equal(canonicalRemoteGrantGroup({
    ...base(), capabilities: [{ capability: "computer.windows", accessMode: "admin" as "read" }],
  }), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), capabilities: [] }), null);
  assert.equal(canonicalRemoteGrantGroup({
    ...base(), capabilities: Array.from({ length: 129 }, (_, i) => ({
      capability: "computer.action_" + i, accessMode: "read" as const,
    })),
  }), null);
});

test("client binding and profile must match the canonical RPC contract", () => {
  assert.equal(canonicalRemoteClient(ownerUserId, "product-mcp", null)?.p_client_id, null);
  assert.equal(canonicalRemoteClient(ownerUserId, "product-mcp", "short"), null);
  assert.equal(canonicalRemoteClient(ownerUserId, "legacy-client" as "product-mcp", null), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), profileKey: "Not Canonical" }), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), clientId: "invalid/id" }), null);
});

test("expiration must be valid and in the future", () => {
  assert.equal(canonicalRemoteGrantGroup({ ...base(), validUntil: "yesterday" }), null);
  assert.equal(canonicalRemoteGrantGroup({ ...base(), validUntil: "2000-01-01T00:00:00Z" }), null);
  assert.equal(
    canonicalRemoteGrantGroup({ ...base(), validUntil: "2099-01-01T00:00:00Z" })?.p_valid_until,
    "2099-01-01T00:00:00.000Z",
  );
});
