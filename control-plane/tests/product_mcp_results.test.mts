import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { scopeProductResult } from "../cloudflare/src/product_results.ts";

for (const status of ["queued", "leased", "running", "succeeded", "failed", "cancelled"]) {
  test(`action status preserves ${status} and its continuation id`, async () => {
    const handlers = {
      session: async () => Response.json({ ok: true }),
      targets: async () => Response.json({ ok: true, targets: [] }),
      createAction: async () => Response.json({ ok: true, request_id: "request-1" }),
      getAction: async () => Response.json({ ok: true, action: { request_id: "request-1", action: "git.status", status, result: null } }),
    };
    for (const name of ["ordax_action_status", "git_status"]) {
      const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
          name, arguments: { request_id: "request-1", device_id: "device-1", project: "review", wait_for_completion_ms: 0 },
        } }),
      }), handlers);
      const { result } = await response.json();
      const pending = ["queued", "leased", "running"].includes(status);
      assert.equal(result.structuredContent.pending, pending);
      assert.equal(result.structuredContent.request_id, "request-1");
      if (name === "ordax_action_status") assert.equal(result.structuredContent.action.status, status);
      if (pending) assert.equal(result.isError, false);
      else if (name === "git_status") assert.equal(result.isError, status !== "succeeded");
    }
  });
}

const legacyResult = { ok: true, summary: "projects", data: {
  default_project: "private", active_project: "private", root: "C:/private",
  projects: [
    { slug: "review", apps: [], available: true, path: "C:/review", repository: { branch: "main", root: "C:/review" } },
    { slug: "private", apps: ["blender"], available: true },
  ],
} };

for (const action of ["projects.list", "workspace.repository_catalog"]) {
  test(`${action} filters older agent results with the original grant`, () => {
    const result = scopeProductResult(action, legacyResult, '["review"]') as any;
    assert.deepEqual(result.data.projects.map((item: any) => item.slug), ["review"]);
    assert.equal(result.data.default_project, undefined);
    assert.equal(result.data.active_project, undefined);
    assert.equal(JSON.stringify(result).includes("C:/"), false);
    assert.deepEqual(legacyResult.data.projects.map((item) => item.slug), ["review", "private"]);
  });
  for (const grant of [null, "invalid", "[]", '["review",42]']) {
    test(`${action} fails closed for grant ${grant}`, () => {
      const result = scopeProductResult(action, legacyResult, grant) as any;
      assert.deepEqual(result.data.projects, []);
    });
  }
}

test("authorized default and project-specific results remain available", () => {
  const result = scopeProductResult("projects.list", legacyResult, '["private"]') as any;
  assert.equal(result.data.default_project, "private");
  assert.equal(scopeProductResult("project.text_read", legacyResult, null), legacyResult);
  assert.equal(scopeProductResult("projects.list", null, '["review"]'), null);
});
