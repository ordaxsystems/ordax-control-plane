import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { createCanonicalProductMcpDiscoveryHandlers } from "../cloudflare/src/product_mcp_discovery.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";

const issuer = "https://discovery-project.supabase.co/auth/v1";
const env = {
  PRODUCT_AUTH_ISSUER: issuer,
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: issuer + "/.well-known/jwks.json",
};
const owner = "11111111-1111-4111-8111-111111111111";
const otherOwner = "22222222-2222-4222-8222-222222222222";
const client = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const otherClient = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const device = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const secondDevice = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const encoder = new TextEncoder();
const b64 = (value: string | Uint8Array) => Buffer.from(value).toString("base64url");
const keys = webcrypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"],
);

async function token(overrides: Record<string, unknown> = {}) {
  const pair = await keys;
  const unsigned = b64(JSON.stringify({ alg: "RS256", kid: "discovery-1" })) + "." + b64(JSON.stringify({
    iss: issuer, aud: "authenticated", role: "authenticated", sub: owner,
    client_id: client, exp: Math.floor(Date.now() / 1000) + 900, ...overrides,
  }));
  const signature = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, encoder.encode(unsigned));
  return unsigned + "." + b64(new Uint8Array(signature));
}

async function withIssuer(run: () => Promise<void>) {
  const pair = await keys;
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const previous = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(String(url), env.PRODUCT_AUTH_JWKS_URL);
    return Response.json({ keys: [{ ...jwk, kid: "discovery-1", alg: "RS256" }] });
  };
  try { await run(); } finally { globalThis.fetch = previous; }
}

function request(jwt: string, path = "/v3/product/targets") {
  return new Request("https://ordax.example" + path, {
    headers: { authorization: "Bearer " + jwt, "x-ordax-client-id": otherClient, "x-ordax-owner-user-id": otherOwner },
  });
}

function catalog() {
  return { ok: true, targets: [
    { device_id: device, device_name: "Meu desktop", online: true, private_token: "private-device-token",
      grant_groups: [{ grant_group_id: "internal-group", profile_key: "project-read", space_id: null, project_id: null,
        valid_until: null, capabilities: [{ capability: "computer.windows", access_mode: "read" }] }] },
    { device_id: secondDevice, device_name: "Notebook", online: false, last_seen_at: "2026-10-09T12:00:00Z" },
  ] };
}

test("signed owner and exact OAuth client reach canonical discovery, ignoring caller-selected identity", async () => {
  await withIssuer(async () => {
    const calls: unknown[] = [];
    const handlers = createCanonicalProductMcpDiscoveryHandlers(env, async (receivedEnv, identity) => {
      assert.equal(receivedEnv, env);
      calls.push(identity);
      return catalog();
    });
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
    const handlers = createCanonicalProductMcpDiscoveryHandlers(env, async () => { assert.fail("session must not read grants"); });
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
    const handlers = createCanonicalProductMcpDiscoveryHandlers(env, async () => { assert.fail("unauthorized RPC call"); });
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
    const handlers = createCanonicalProductMcpDiscoveryHandlers(env, async () => {
      calls++;
      if (calls === 1) return catalog();
      if (calls === 2) return { ok: true, targets: [] };
      return { ok: false, error: "product_owner_auth_ineligible", private_detail: "never-export" };
    });
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
    const unconfigured = await createCanonicalProductMcpDiscoveryHandlers(env).targets(req);
    assert.equal(unconfigured.status, 503);
    assert.deepEqual(await unconfigured.json(), { ok: false, error: "product_postgres_unconfigured" });
    const unavailable = await createCanonicalProductMcpDiscoveryHandlers(env, async () => {
      throw new Error("postgres://private-secret@internal-db SQL private details");
    }).targets(req);
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
      const handlers = createCanonicalProductMcpDiscoveryHandlers(env, async () => result as any);
      const response = await handlers.targets(request(await token()));
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_invalid_response" });
    }
  });
});

test("MCP request through signed session, canonical reader and public projection preserves offline devices", async () => {
  await withIssuer(async () => {
    let reads = 0;
    const handlers = createCanonicalProductMcpDiscoveryHandlers(env, async (_, identity) => {
      reads++;
      assert.deepEqual(identity, { ownerUserId: owner, clientKind: "product-mcp", clientId: client });
      return catalog();
    });
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
