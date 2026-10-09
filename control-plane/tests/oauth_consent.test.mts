import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { oauthConsentResponse } from "../cloudflare/src/oauth_consent.ts";

const foundation = JSON.parse(
  readFileSync(new URL("../cloudflare/production-foundation.json", import.meta.url), "utf8"),
) as { postgres: { project_ref: string } };
const wrangler = readFileSync(new URL("../cloudflare/wrangler.toml", import.meta.url), "utf8");
const source = readFileSync(new URL("../cloudflare/src/oauth_consent.ts", import.meta.url), "utf8");
const getVar = (name: string): string => {
  const match = new RegExp(`^${name} = "([^"]+)"$`, "m").exec(wrangler);
  assert.ok(match, `Missing ${name} in Wrangler vars`);
  return match[1];
};
const issuer = getVar("PRODUCT_AUTH_ISSUER");
const publishableKey = getVar("SUPABASE_PUBLISHABLE_KEY");
const env = {
  PRODUCT_AUTH_ISSUER: issuer,
  SUPABASE_PUBLISHABLE_KEY: publishableKey,
};
const request = new Request("https://ordax.example/oauth/consent?authorization_id=request-123");

test("canonical issuer alone defines the consent project origin", async () => {
  assert.equal(issuer, `https://${foundation.postgres.project_ref}.supabase.co/auth/v1`);
  assert.match(publishableKey, /^sb_publishable_[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(source, /eobcxuyvhkvdmkbaihwh|GQUBlAVTzgNtscw9iE5vLQ_GGtdmsL5/);
  const response = oauthConsentResponse(request, env);
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.ok(html.includes(`createClient("https://${foundation.postgres.project_ref}.supabase.co","${publishableKey}"`));
  assert.ok(response.headers.get("content-security-policy")?.includes(
    `connect-src https://${foundation.postgres.project_ref}.supabase.co;`,
  ));
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("OAuth consent fails closed on absent or incorrect identity configuration", () => {
  for (const invalid of [
    {},
    { PRODUCT_AUTH_ISSUER: issuer },
    { SUPABASE_PUBLISHABLE_KEY: publishableKey },
    { ...env, PRODUCT_AUTH_ISSUER: "https://attacker.invalid/auth/v1" },
    { ...env, PRODUCT_AUTH_ISSUER: "http://other.supabase.co/auth/v1" },
    { ...env, PRODUCT_AUTH_ISSUER: "https://other.supabase.co/auth/v1/trailing" },
    { ...env, SUPABASE_PUBLISHABLE_KEY: "legacy-or-secret" },
  ]) {
    const response = oauthConsentResponse(request, invalid);
    assert.equal(response.status, 503, JSON.stringify(invalid));
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
});

test("invalid OAuth request cannot become an authorization", async () => {
  const response = oauthConsentResponse(new Request("https://ordax.example/oauth/consent"), env);
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.ok(html.includes('<code>authorization_id</code> ausente.'));
  assert.match(html, /if\(!authorizationId\)\{show\('missing'\);return\}/);
  assert.match(html, /q\('approve'\)\.disabled=true/);
  assert.match(html, /getAuthorizationDetails\(authorizationId\)/);
  assert.match(html, /q\('approve'\)\.disabled=false/);
});

test("magic link never silently registers a new account", async () => {
  const html = await oauthConsentResponse(request, env).text();
  assert.match(html, /signInWithOtp\(\{email,options:\{emailRedirectTo:returnUrl,shouldCreateUser:false\}\}\)/);
  assert.match(html, /approveAuthorization\(authorizationId\)/);
  assert.match(html, /denyAuthorization\(authorizationId\)/);
});
