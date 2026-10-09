import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";

async function listTargets(targets: unknown[], authenticated = true) {
  let created = 0;
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json", authorization: "Bearer fixture" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ordax_targets", arguments: {} } }),
  }), {
    session: async () => Response.json({ ok: authenticated }, { status: authenticated ? 200 : 401 }),
    targets: async request => {
      assert.equal(request.headers.get("authorization"), "Bearer fixture");
      return Response.json({ ok: true, targets });
    },
    createAction: async () => { created++; return Response.json({ ok: false }); },
    getAction: async () => Response.json({ ok: false }),
  });
  assert.equal(created, 0);
  return { status: response.status, body: await response.json() };
}

test("canonical target identity, offline presence and authorized grant groups remain visible to the plugin", async () => {
  const { body } = await listTargets([{
    device_id: "desktop-1", device_name: "Desktop principal", online: false,
    last_seen_at: "2026-10-09T12:00:00Z", device_kind: "desktop", channel: "stable",
    private_token: "must-not-leak", raw_path: "C:/private",
    grant_groups: [{ grant_group_id: "internal", profile_key: "project-read", space_id: "space-1", project_id: "project-1", valid_until: null,
      capabilities: [{ capability: "workspace.text_read", access_mode: "read", secret: "never" }] }],
  }]);
  const result = body.result.structuredContent;
  assert.equal(body.result.isError, false);
  assert.equal(result.targets[0].name, "Desktop principal"); assert.equal(result.targets[0].device_name, "Desktop principal");
  assert.equal(result.targets[0].online, false); assert.equal(result.targets[0].last_seen_at, "2026-10-09T12:00:00.000Z");
  assert.deepEqual(result.targets[0].grant_groups[0], {
    profile_key: "project-read", space_id: "space-1", project_id: "project-1", valid_until: null,
    capabilities: [{ capability: "workspace.text_read", access_mode: "read" }],
  });
  assert.ok(!JSON.stringify(result).includes("must-not-leak")); assert.ok(!JSON.stringify(result).includes("C:/private"));
  assert.ok(!JSON.stringify(result).includes("internal")); assert.ok(!JSON.stringify(result).includes("never"));
});

test("legacy presence stays unknown and timestamps do not manufacture connectivity", async () => {
  const { body } = await listTargets([{ device_id: "legacy", name: "Legado", last_seen_at: "2026-10-09T12:00:00Z", grants: [{ space_id: "space", actions: ["git.status"], projects: ["demo"] }] }]);
  const target = body.result.structuredContent.targets[0];
  assert.equal(target.name, "Legado"); assert.equal(target.online, null);
  assert.deepEqual(target.grants, [{ space_id: "space", actions: ["git.status"], projects: ["demo"] }]);
  assert.deepEqual(target.grant_groups, []);
});

test("invalid presence, scope data and unbounded groups cannot become capabilities", async () => {
  const { body } = await listTargets([null, { device_id: "../escape" }, {
    device_id: "valid", online: "true", last_seen_at: "invalid",
    grant_groups: Array(140).fill({ profile_key: "x".repeat(129), capabilities: [null, { capability: "computer.click", access_mode: "admin" }] }),
  }]);
  const targets = body.result.structuredContent.targets;
  assert.equal(targets.length, 1); assert.equal(targets[0].online, null); assert.equal(targets[0].last_seen_at, null);
  assert.equal(targets[0].grant_groups.length, 128); assert.equal(targets[0].grant_groups[0].profile_key, null);
  assert.deepEqual(targets[0].grant_groups[0].capabilities, []);
});

test("unauthenticated discovery remains unavailable", async () => {
  const result = await listTargets([{ device_id: "private-device" }], false);
  assert.equal(result.status, 401); assert.ok(!JSON.stringify(result.body).includes("private-device"));
});
