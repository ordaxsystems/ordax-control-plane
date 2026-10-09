import assert from "node:assert/strict";
import test from "node:test";
import { createCanonicalProductMcpReadHandlers } from "../cloudflare/src/product_mcp_reads.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { env, owner, otherOwner, client, otherClient, device, token, withIssuer, request, catalog } from "./product_mcp_test_fixtures.mts";

test("signed owner and exact OAuth client reach canonical discovery, ignoring caller-selected identity", async () => {
  await withIssuer(async () => {
    const calls: unknown[] = [];
    const handlers = createCanonicalProductMcpReadHandlers(env, { listTargets: async (receivedEnv, identity) => {
      assert.equal(receivedEnv, env);
      calls.push(identity);
      return catalog();
    } });
    for (const signedClient of [client, otherClient]) {
      const response = await handlers.targets(request(await token({ client_id: signedClient }),
        "/v3/product/targets?owner_user_id=" + otherOwner + "&client_id=" + otherClient));
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("cache-control"), "no-store");
      const body = await response.json();
      assert.deepEqual(body.targets.map((item: any) => [item.name, item.online]), [["Meu desktop", true], ["Notebook", false]]);
      assert.equal(body.targets[1].last_seen_at, "2026-10-09T12:00:00.000Z");
      assert.equal(JSON.stringify(body).includes("private-device-token"), false);
      assert.equal(JSON.stringify(body).includes("internal-group"), false);
    }
    assert.deepEqual(calls, [
      { ownerUserId: owner, clientKind: "product-mcp", clientId: client },
      { ownerUserId: owner, clientKind: "product-mcp", clientId: otherClient },
    ]);
  });
});

test("session identifies OAuth owner without interpreting login as a device grant", async () => {
  await withIssuer(async () => {
    const handlers = createCanonicalProductMcpReadHandlers(env, { listTargets: async () => { assert.fail("session must not read grants"); } });
    const response = await handlers.session(request(await token(), "/v3/product/session"));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    const body = await response.json();
    assert.equal(body.session.subject_id, owner);
    assert.equal(body.session.client_id, client);
    assert.equal(body.session.client_kind, "product-mcp");
    assert.equal("targets" in body, false);
    assert.equal("grants" in body, false);
  });
});

test("plain user login, invalid OAuth role and expired token cannot call the target authority", async () => {
  await withIssuer(async () => {
    const handlers = createCanonicalProductMcpReadHandlers(env, { listTargets: async () => { assert.fail("unauthorized RPC call"); } });
    for (const [claims, status] of [
      [{ client_id: undefined, user_metadata: { client_id: client } }, 403],
      [{ role: "anon" }, 403],
      [{ exp: Math.floor(Date.now() / 1000) - 3600 }, 401],
    ] as const) {
      const req = request(await token(claims));
      assert.equal((await handlers.session(req)).status, status);
      assert.equal((await handlers.targets(req)).status, status);
    }
    assert.equal((await handlers.targets(new Request("https://ordax.example/v3/product/targets"))).status, 401);
  });
});

test("each discovery re-reads authority; empty grants and ineligible account remain distinct", async () => {
  await withIssuer(async () => {
    let calls = 0;
    const handlers = createCanonicalProductMcpReadHandlers(env, { listTargets: async () => {
      calls++;
      if (calls === 1) return catalog();
      if (calls === 2) return { ok: true, targets: [] };
      return { ok: false, error: "product_owner_auth_ineligible", private_detail: "never-export" };
    } });
    const req = request(await token());
    assert.equal((await (await handlers.targets(req)).json()).targets.length, 2);
    assert.deepEqual(await (await handlers.targets(req)).json(), { ok: true, targets: [] });
    const denied = await handlers.targets(req);
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { ok: false, error: "product_owner_auth_ineligible" });
    assert.equal(calls, 3);
  });
});

test("unconfigured PostgreSQL and transport failure cannot fall back to legacy authority or leak secrets", async () => {
  await withIssuer(async () => {
    const req = request(await token());
    const unconfigured = await createCanonicalProductMcpReadHandlers(env).targets(req);
    assert.equal(unconfigured.status, 503);
    assert.deepEqual(await unconfigured.json(), { ok: false, error: "product_postgres_unconfigured" });
    const unavailable = await createCanonicalProductMcpReadHandlers(env, { listTargets: async () => {
      throw new Error("postgres://private-secret@internal-db SQL private details");
    } }).targets(req);
    assert.equal(unavailable.status, 503);
    assert.deepEqual(await unavailable.json(), { ok: false, error: "product_targets_unavailable" });
    assert.equal(unavailable.headers.get("cache-control"), "no-store");
  });
});

test("malformed canonical catalogs fail rather than fabricating an empty available registry", async () => {
  await withIssuer(async () => {
    for (const result of [null, {}, { ok: true }, { ok: true, targets: {} },
      { ok: true, targets: [{ device_id: "legacy:device" }] },
      { ok: true, targets: [{ device_id: device }, { device_id: device.toUpperCase() }] },
      { ok: false, error: "private-server-details" },
    ]) {
      const handlers = createCanonicalProductMcpReadHandlers(env, { listTargets: async () => result as any });
      const response = await handlers.targets(request(await token()));
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_invalid_response" });
    }
  });
});

test("MCP request through signed session, canonical reader and public projection preserves offline devices", async () => {
  await withIssuer(async () => {
    let reads = 0;
    const handlers = createCanonicalProductMcpReadHandlers(env, { listTargets: async (_, identity) => {
      reads++;
      assert.deepEqual(identity, { ownerUserId: owner, clientKind: "product-mcp", clientId: client });
      return catalog();
    } });
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
      method: "POST", headers: { authorization: "Bearer " + await token(), "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
        name: "ordax_targets", arguments: { owner_user_id: otherOwner, client_id: otherClient },
      } }),
    }), {
      ...handlers,
      createAction: async () => { assert.fail("discovery must not enqueue an action"); },
      getAction: async () => { assert.fail("discovery must not inspect an action"); },
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.result.isError, false);
    assert.equal(body.result.structuredContent.targets[1].online, false);
    assert.equal(reads, 1);
    assert.equal(JSON.stringify(body).includes("private-device-token"), false);
  });
});
