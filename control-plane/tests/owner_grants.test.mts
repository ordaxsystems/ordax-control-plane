import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createOwnerDeviceComputerGrant, OWNER_DEVICE_COMPUTER_GRANT_PROFILES } from "../cloudflare/src/product_device_grants.ts";
import { createOwnerProjectGrant } from "../cloudflare/src/product_project_grants.ts";
import { COMPUTER_DEVICE_ACTIONS } from "../cloudflare/src/product_action_scope.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { readBoundedJsonObject } from "../cloudflare/src/request_json.ts";

const linkId = "11111111-1111-4111-8111-111111111111";
const subjectId = "22222222-2222-4222-8222-222222222222";
const env: any = { PRODUCT_AUTH_ISSUER: "https://identity.example", PRODUCT_AUTH_AUDIENCE: "ordax", PRODUCT_AUTH_JWKS_URL: "https://identity.example/jwks" };
let token: string;
const realFetch = globalThis.fetch;
before(async () => {
  const keys = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  globalThis.fetch = (async () => Response.json({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] })) as typeof fetch;
  const encoded = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const input = `${encoded({ alg: "RS256", kid: "test-key" })}.${encoded({ iss: env.PRODUCT_AUTH_ISSUER, aud: "ordax", sub: subjectId, exp: Math.floor(Date.now() / 1000) + 300 })}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, new TextEncoder().encode(input));
  token = `${input}.${Buffer.from(signature).toString("base64url")}`;
});
after(() => { globalThis.fetch = realFetch; });

function request(body: unknown) {
  return new Request("https://ordax.example/grants", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
}
function database() {
  const inserts: any[] = [];
  const queries: string[] = [];
  return { inserts, queries, prepare(sql: string) {
    queries.push(sql);
    let values: any[];
    const statement = {
      bind(...args: any[]) { values = args; return statement; },
      async first() { return sql.includes("JOIN ordax_devices") ? { id: linkId, subject_id: subjectId, device_id: "device-1", space_id: "space-1" } : null; },
      async run() { inserts.push(values); return { meta: { changes: 1 } }; },
    };
    return statement;
  } };
}

for (const mode of ["__proto__", "constructor", "toString", "hasOwnProperty", "unknown"]) {
  test(`owner endpoints reject inherited/unknown profile ${mode} before DB access`, async () => {
    for (const handler of [createOwnerDeviceComputerGrant, createOwnerProjectGrant]) {
      const DB = database();
      const response = await handler(request({ link_id: linkId, mode, projects: ["review"] }), { ...env, DB });
      assert.equal(response.status, 400);
      assert.equal(DB.queries.length, 0);
    }
    // Computer requests exclude projects; exercise lookup rather than key rejection.
    const DB = database();
    assert.equal((await createOwnerDeviceComputerGrant(request({ link_id: linkId, mode }), { ...env, DB })).status, 400);
    assert.equal(DB.queries.length, 0);
  });
}
for (const mode of ["full-computer-control", ...Object.keys(OWNER_DEVICE_COMPUTER_GRANT_PROFILES)]) {
  test(`owner ${mode} persists only canonical actions`, async () => {
    const DB = database();
    const response = await createOwnerDeviceComputerGrant(request({ link_id: linkId, mode }), { ...env, DB });
    assert.equal(response.status, 201);
    const { grant } = await response.json() as any;
    const expected = mode === "full-computer-control" ? [...COMPUTER_DEVICE_ACTIONS] : [...OWNER_DEVICE_COMPUTER_GRANT_PROFILES[mode]];
    assert.deepEqual(grant.actions, expected.sort());
    assert.deepEqual(grant.projects, []);
    assert.equal(grant.subject_id, subjectId);
    assert.equal(grant.device_id, "device-1");
    assert.equal(DB.inserts.length, 1);
  });
}
test("MCP hints use the same canonical profiles and preserve authorization failure", async () => {
  const handlers = {
    session: async () => Response.json({ ok: true }), targets: async () => Response.json({ ok: true }),
    createAction: async () => Response.json({ ok: false, error: "product_grant_not_resolved" }, { status: 403 }),
    getAction: async () => { throw new Error("unauthorized action must never be polled"); },
  };
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }), handlers);
  const { result } = await response.json() as any;
  for (const tool of result.tools.filter((tool: any) => tool.name.startsWith("computer_"))) {
    assert.equal(tool._meta["openai/toolInvocation/invoking"].includes("ÔÇ"), false);
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool.name, arguments: { device_id: "device-1" } } }) }), handlers);
    const { result } = await response.json() as any;
    assert.equal(result.isError, true);
    const profile = result.structuredContent.required_owner_profile;
    assert.ok(OWNER_DEVICE_COMPUTER_GRANT_PROFILES[profile].includes(tool.name.replace("computer_", "computer.")));
  }
});
test("bounded JSON counts UTF-8 bytes, accepts split Unicode, and rejects malformed input", async () => {
  const bytes = new TextEncoder().encode('{"text":"ação"}');
  const stream = new ReadableStream({ start(controller) {
    for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
    controller.close();
  } });
  assert.deepEqual(await readBoundedJsonObject(new Request("https://test", { method: "POST", body: stream, duplex: "half" } as any), bytes.length), { text: "ação" });
  assert.equal(await readBoundedJsonObject(new Request("https://test", { method: "POST", body: bytes }), bytes.length - 1), null);
  for (const body of ["[]", "null", "{bad", new Uint8Array([0xff])]) {
    assert.equal(await readBoundedJsonObject(new Request("https://test", { method: "POST", body }), 100), null);
  }
});
test("bounded parser cancels an oversized stream before consuming the remainder", async () => {
  let cancelled = false;
  const stream = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(100)); }, cancel() { cancelled = true; } });
  assert.equal(await readBoundedJsonObject(new Request("https://test", { method: "POST", body: stream, duplex: "half" } as any), 20), null);
  assert.equal(cancelled, true);
});

test("bounded reader enforces the actual UTF-8 byte limit even with misleading content-length", async () => {
  const body = '{"description":"' + "á".repeat(6) + '"}';
  const bytes = new TextEncoder().encode(body);
  const request = new Request("https://ordax.example/api", {
    method: "POST",
    headers: { "content-length": "2" },
    body: bytes,
  });
  assert.equal(await readBoundedJsonObject(request, bytes.byteLength - 1), null);
  const valid = new Request("https://ordax.example/api", { method: "POST", body: bytes });
  assert.deepEqual(await readBoundedJsonObject(valid, bytes.byteLength), { description: "á".repeat(6) });
});

test("bounded reader stops infinite chunked requests before consuming a full body", async () => {
  let chunksRead = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      chunksRead++;
      controller.enqueue(new Uint8Array(8192));
    },
    cancel() { cancelled = true; },
  });
  assert.equal(await readBoundedJsonObject(
    new Request("https://ordax.example/api", { method: "POST", body, duplex: "half" } as any), 16 * 1024,
  ), null);
  assert.equal(chunksRead, 3);
  assert.equal(cancelled, true);
});
