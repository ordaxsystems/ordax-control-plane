var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.ts
import { DurableObject } from "cloudflare:workers";

// src/product_auth.ts
var PRODUCT_SUBJECT_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
var JWT_ALGORITHMS = /* @__PURE__ */ new Set(["RS256", "ES256"]);
var CLOCK_SKEW_SECONDS = 60;
function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord, "isRecord");
function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + padding;
  try {
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}
__name(decodeBase64Url, "decodeBase64Url");
function decodeJsonPart(value) {
  const bytes = decodeBase64Url(value);
  if (!bytes) return null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
__name(decodeJsonPart, "decodeJsonPart");
function audienceMatches(value, expected) {
  return value === expected || Array.isArray(value) && value.every((item) => typeof item === "string") && value.includes(expected);
}
__name(audienceMatches, "audienceMatches");
async function importVerificationKey(jwk, alg) {
  if (alg === "RS256") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  }
  if (alg === "ES256") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  }
  throw new Error("unsupported_jwt_algorithm");
}
__name(importVerificationKey, "importVerificationKey");
async function verifySignature(alg, key, signingInput, signature) {
  if (alg === "RS256") {
    return crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      signature,
      signingInput
    );
  }
  if (alg === "ES256") {
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      signingInput
    );
  }
  return false;
}
__name(verifySignature, "verifySignature");
async function loadJwk(env, kid, alg) {
  const jwksUrl = env.PRODUCT_AUTH_JWKS_URL ?? "";
  let parsed;
  try {
    parsed = new URL(jwksUrl);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:") return null;
  const response = await fetch(parsed.toString(), {
    method: "GET",
    headers: { accept: "application/json" },
    redirect: "manual",
    signal: AbortSignal.timeout(1e4)
  });
  if (!response.ok) return null;
  const body = await response.json();
  if (!isRecord(body) || !Array.isArray(body.keys)) return null;
  for (const raw of body.keys) {
    if (isRecord(raw) && raw.kid === kid && (raw.alg == null || raw.alg === alg) && typeof raw.kty === "string") {
      return raw;
    }
  }
  return null;
}
__name(loadJwk, "loadJwk");
function productAuthConfigured(env) {
  const issuer = env.PRODUCT_AUTH_ISSUER ?? "";
  const audience = env.PRODUCT_AUTH_AUDIENCE ?? "";
  const jwksUrl = env.PRODUCT_AUTH_JWKS_URL ?? "";
  if (!issuer || !audience || !jwksUrl) return false;
  try {
    const issuerUrl = new URL(issuer);
    const jwks = new URL(jwksUrl);
    return issuerUrl.protocol === "https:" && jwks.protocol === "https:";
  } catch {
    return false;
  }
}
__name(productAuthConfigured, "productAuthConfigured");
async function authenticateProductRequest(request, env) {
  if (!productAuthConfigured(env)) {
    return { ok: false, error: "product_auth_unconfigured", status: 503 };
  }
  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ") || authorization.length > 16384) {
    return { ok: false, error: "product_auth_required", status: 401 };
  }
  const token = authorization.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return { ok: false, error: "product_token_invalid", status: 401 };
  }
  const header = decodeJsonPart(parts[0]);
  const payload = decodeJsonPart(parts[1]);
  const signature = decodeBase64Url(parts[2]);
  if (!header || !payload || !signature) {
    return { ok: false, error: "product_token_invalid", status: 401 };
  }
  const alg = typeof header.alg === "string" ? header.alg : "";
  const kid = typeof header.kid === "string" ? header.kid : "";
  if (!JWT_ALGORITHMS.has(alg) || !kid || kid.length > 256) {
    return { ok: false, error: "product_token_algorithm_invalid", status: 401 };
  }
  const issuer = env.PRODUCT_AUTH_ISSUER;
  const audience = env.PRODUCT_AUTH_AUDIENCE;
  const subjectId = typeof payload.sub === "string" ? payload.sub : "";
  const exp = typeof payload.exp === "number" && Number.isFinite(payload.exp) ? payload.exp : 0;
  const nbf = typeof payload.nbf === "number" && Number.isFinite(payload.nbf) ? payload.nbf : null;
  const now = Math.floor(Date.now() / 1e3);
  if (payload.iss !== issuer || !audienceMatches(payload.aud, audience) || !PRODUCT_SUBJECT_RE.test(subjectId) || exp <= now - CLOCK_SKEW_SECONDS || nbf !== null && nbf > now + CLOCK_SKEW_SECONDS) {
    return { ok: false, error: "product_token_claims_invalid", status: 401 };
  }
  let jwk = null;
  try {
    jwk = await loadJwk(env, kid, alg);
  } catch {
    return { ok: false, error: "product_jwks_unavailable", status: 503 };
  }
  if (!jwk) {
    return { ok: false, error: "product_signing_key_not_found", status: 401 };
  }
  try {
    const key = await importVerificationKey(jwk, alg);
    const signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
    const valid = await verifySignature(alg, key, signingInput, signature);
    if (!valid) {
      return { ok: false, error: "product_signature_invalid", status: 401 };
    }
  } catch {
    return { ok: false, error: "product_signature_invalid", status: 401 };
  }
  return {
    ok: true,
    subjectId,
    issuer,
    audience: payload.aud,
    expiresAt: exp
  };
}
__name(authenticateProductRequest, "authenticateProductRequest");

// src/product_action_scope.ts
var PROJECT_BROWSER_ACTIONS = /* @__PURE__ */ new Set([
  "browser.click",
  "browser.list",
  "browser.navigate",
  "browser.screenshot",
  "browser.snapshot",
  "browser.start",
  "browser.status",
  "browser.stop",
  "browser.type"
]);
var APP_INTELLIGENCE_DEVICE_ACTIONS = /* @__PURE__ */ new Set([
  "intelligence.app_catalog",
  "intelligence.app_detail"
]);
var COMPUTER_DEVICE_ACTIONS = /* @__PURE__ */ new Set([
  "computer.access_status",
  "computer.active_window",
  "computer.click",
  "computer.clipboard_read",
  "computer.clipboard_write",
  "computer.directory_create",
  "computer.directory_list",
  "computer.drag",
  "computer.file_stat",
  "computer.focus_window",
  "computer.hotkey",
  "computer.launch_app",
  "computer.mouse_move",
  "computer.path_move",
  "computer.path_remove",
  "computer.processes",
  "computer.screen_info",
  "computer.screenshot",
  "computer.scroll",
  "computer.search",
  "computer.terminate_process",
  "computer.text_patch",
  "computer.text_read",
  "computer.text_write",
  "computer.type",
  "computer.windows"
]);
var DEVICE_SCOPED_ACTIONS = /* @__PURE__ */ new Set([
  ...COMPUTER_DEVICE_ACTIONS,
  ...APP_INTELLIGENCE_DEVICE_ACTIONS
]);
function productActionScope(action, projectScopedActions) {
  if (DEVICE_SCOPED_ACTIONS.has(action)) return "device";
  return projectScopedActions.has(action) ? "project" : "device";
}
__name(productActionScope, "productActionScope");
function projectBindingMatchesScope(action, project, projectScopedActions) {
  const scope = productActionScope(action, projectScopedActions);
  return scope === "device" ? project === null : project !== null;
}
__name(projectBindingMatchesScope, "projectBindingMatchesScope");

// src/product_device_grants.ts
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var FULL_COMPUTER_CONTROL_MODE = "full-computer-control";
var INTERACTIVE_COMPUTER_CONTROL_MODE = "interactive-computer-control";
var FILESYSTEM_COMPUTER_CONTROL_MODE = "computer-filesystem";
var CLIPBOARD_COMPUTER_CONTROL_MODE = "computer-clipboard";
var PROCESS_COMPUTER_CONTROL_MODE = "computer-process-control";
var MAX_BODY_BYTES = 16 * 1024;
var OWNER_DEVICE_COMPUTER_GRANT_PROFILES = {
  [INTERACTIVE_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.active_window",
    "computer.click",
    "computer.drag",
    "computer.focus_window",
    "computer.hotkey",
    "computer.launch_app",
    "computer.mouse_move",
    "computer.processes",
    "computer.screen_info",
    "computer.screenshot",
    "computer.scroll",
    "computer.type",
    "computer.windows"
  ],
  [FILESYSTEM_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.directory_create",
    "computer.directory_list",
    "computer.file_stat",
    "computer.path_move",
    "computer.path_remove",
    "computer.search",
    "computer.text_patch",
    "computer.text_read",
    "computer.text_write"
  ],
  [CLIPBOARD_COMPUTER_CONTROL_MODE]: [
    "computer.clipboard_read",
    "computer.clipboard_write"
  ],
  [PROCESS_COMPUTER_CONTROL_MODE]: [
    "computer.processes",
    "computer.terminate_process"
  ]
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
__name(json, "json");
function isRecord2(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord2, "isRecord");
async function parseSmallJson(request) {
  const raw = await request.text();
  if (!raw || raw.length > MAX_BODY_BYTES) return null;
  try {
    const parsed = JSON.parse(raw);
    return isRecord2(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
__name(parseSmallJson, "parseSmallJson");
function parseExpiry(value) {
  if (value == null) return null;
  if (typeof value !== "string") return void 0;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
    return void 0;
  }
  return parsed.toISOString();
}
__name(parseExpiry, "parseExpiry");
function stableComputerActions() {
  return [...COMPUTER_DEVICE_ACTIONS].sort();
}
__name(stableComputerActions, "stableComputerActions");
function actionsForOwnerDeviceMode(mode) {
  if (mode === FULL_COMPUTER_CONTROL_MODE) return stableComputerActions();
  const profile = OWNER_DEVICE_COMPUTER_GRANT_PROFILES[mode];
  if (!profile || profile.length === 0) return null;
  if (profile.some((action) => !COMPUTER_DEVICE_ACTIONS.has(action))) return null;
  return [...profile].sort();
}
__name(actionsForOwnerDeviceMode, "actionsForOwnerDeviceMode");
function ownerDeviceModeForActions(actions) {
  const normalized = [...actions].sort();
  const full = stableComputerActions();
  if (JSON.stringify(normalized) === JSON.stringify(full)) return FULL_COMPUTER_CONTROL_MODE;
  for (const [mode, profile] of Object.entries(OWNER_DEVICE_COMPUTER_GRANT_PROFILES)) {
    const expected = [...profile].sort();
    if (JSON.stringify(normalized) === JSON.stringify(expected)) return mode;
  }
  return "custom-device-grant";
}
__name(ownerDeviceModeForActions, "ownerDeviceModeForActions");
function onlyAllowedCreateKeys(body) {
  const allowed = /* @__PURE__ */ new Set(["link_id", "mode", "expires_at"]);
  return Object.keys(body).every((key) => allowed.has(key));
}
__name(onlyAllowedCreateKeys, "onlyAllowedCreateKeys");
function publicGrant(row) {
  let actions = [];
  let projects = [];
  try {
    actions = JSON.parse(row.actions_json);
  } catch {
    actions = [];
  }
  try {
    projects = JSON.parse(row.projects_json);
  } catch {
    projects = [];
  }
  const safeActions = Array.isArray(actions) ? actions.filter((action) => typeof action === "string") : [];
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    mode: ownerDeviceModeForActions(safeActions),
    actions: safeActions,
    projects: Array.isArray(projects) ? projects : [],
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at
  };
}
__name(publicGrant, "publicGrant");
async function linkedDeviceForOwner(env, subjectId, linkId) {
  return env.DB.prepare(
    `SELECT l.id, l.subject_id, l.space_id, l.device_id
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.id = ?1
       AND l.subject_id = ?2
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL`
  ).bind(linkId, subjectId).first();
}
__name(linkedDeviceForOwner, "linkedDeviceForOwner");
function rowIsDeviceComputerGrant(row) {
  let actions;
  let projects;
  try {
    actions = JSON.parse(row.actions_json);
  } catch {
    return false;
  }
  try {
    projects = JSON.parse(row.projects_json);
  } catch {
    return false;
  }
  return Array.isArray(actions) && actions.length > 0 && actions.every(
    (action) => typeof action === "string" && COMPUTER_DEVICE_ACTIONS.has(action)
  ) && Array.isArray(projects) && projects.length === 0;
}
__name(rowIsDeviceComputerGrant, "rowIsDeviceComputerGrant");
async function createOwnerDeviceComputerGrant(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  const body = await parseSmallJson(request);
  if (!body || !onlyAllowedCreateKeys(body)) {
    return json({ ok: false, error: "owner_device_grant_invalid" }, 400);
  }
  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const mode = typeof body.mode === "string" ? body.mode : "";
  const actions = actionsForOwnerDeviceMode(mode);
  const expiresAt = parseExpiry(body.expires_at);
  if (!UUID_RE.test(linkId) || actions === null || expiresAt === void 0) {
    return json({ ok: false, error: "owner_device_grant_invalid" }, 400);
  }
  const link = await linkedDeviceForOwner(env, identity.subjectId, linkId);
  if (!link) {
    return json({ ok: false, error: "product_device_link_not_found" }, 404);
  }
  const actionsJson = JSON.stringify(actions);
  const projectsJson = "[]";
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const existing = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants
     WHERE subject_id = ?1
       AND device_id = ?2
       AND ((space_id IS NULL AND ?3 = '') OR space_id = ?3)
       AND actions_json = ?4
       AND projects_json = ?5
       AND revoked_at IS NULL
       AND ((expires_at IS NULL AND ?6 IS NULL) OR expires_at = ?6)
     ORDER BY created_at DESC
     LIMIT 1`
  ).bind(
    identity.subjectId,
    link.device_id,
    link.space_id,
    actionsJson,
    projectsJson,
    expiresAt
  ).first();
  if (existing) {
    return json({
      ok: true,
      replayed: true,
      mode,
      grant: publicGrant(existing),
      provenance: { link_id: link.id }
    });
  }
  const grantId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO ordax_product_grants
      (id, subject_id, space_id, device_id, actions_json, projects_json,
       expires_at, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)`
  ).bind(
    grantId,
    identity.subjectId,
    link.space_id || null,
    link.device_id,
    actionsJson,
    projectsJson,
    expiresAt,
    now
  ).run();
  const created = {
    id: grantId,
    subject_id: identity.subjectId,
    space_id: link.space_id || null,
    device_id: link.device_id,
    actions_json: actionsJson,
    projects_json: projectsJson,
    expires_at: expiresAt,
    created_at: now,
    revoked_at: null
  };
  return json({
    ok: true,
    replayed: false,
    mode,
    grant: publicGrant(created),
    provenance: { link_id: link.id }
  }, 201);
}
__name(createOwnerDeviceComputerGrant, "createOwnerDeviceComputerGrant");
async function listOwnerDeviceComputerGrants(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  const url = new URL(request.url);
  const linkId = (url.searchParams.get("link_id") || "").trim();
  if (linkId && !UUID_RE.test(linkId)) {
    return json({ ok: false, error: "owner_device_grant_link_id_invalid" }, 400);
  }
  const query = linkId ? `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE g.subject_id = ?1
         AND l.id = ?2
         AND l.revoked_at IS NULL
         AND d.revoked_at IS NULL
       ORDER BY g.created_at DESC` : `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE g.subject_id = ?1
         AND l.revoked_at IS NULL
         AND d.revoked_at IS NULL
       ORDER BY g.created_at DESC`;
  const statement = env.DB.prepare(query);
  const result = linkId ? await statement.bind(identity.subjectId, linkId).all() : await statement.bind(identity.subjectId).all();
  const grants = (result.results ?? []).filter(rowIsDeviceComputerGrant).map(publicGrant);
  return json({ ok: true, grants });
}
__name(listOwnerDeviceComputerGrants, "listOwnerDeviceComputerGrants");
async function revokeOwnerDeviceComputerGrant(request, env, grantId) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE.test(grantId)) {
    return json({ ok: false, error: "owner_device_grant_id_invalid" }, 400);
  }
  const row = await env.DB.prepare(
    `SELECT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
            g.projects_json, g.expires_at, g.created_at, g.revoked_at
     FROM ordax_product_grants g
     JOIN ordax_product_device_links l
       ON l.subject_id = g.subject_id
      AND l.device_id = g.device_id
      AND l.space_id = COALESCE(g.space_id, '')
     WHERE g.id = ?1
       AND g.subject_id = ?2
       AND l.revoked_at IS NULL
     LIMIT 1`
  ).bind(grantId, identity.subjectId).first();
  if (!row || !rowIsDeviceComputerGrant(row)) {
    return json({ ok: false, error: "owner_device_grant_not_found" }, 404);
  }
  if (row.revoked_at) {
    return json({ ok: true, revoked: false, already_revoked: true, grant: publicGrant(row) });
  }
  const revokedAt = (/* @__PURE__ */ new Date()).toISOString();
  const update = await env.DB.prepare(
    `UPDATE ordax_product_grants
     SET revoked_at = ?1
     WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL`
  ).bind(revokedAt, grantId, identity.subjectId).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "owner_device_grant_revoke_conflict" }, 409);
  }
  return json({
    ok: true,
    revoked: true,
    grant: publicGrant({ ...row, revoked_at: revokedAt })
  });
}
__name(revokeOwnerDeviceComputerGrant, "revokeOwnerDeviceComputerGrant");

// src/product_project_grants.ts
var UUID_RE2 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var PROJECT_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
var MAX_BODY_BYTES2 = 16 * 1024;
var MAX_PROJECTS = 20;
var PROJECT_BROWSER_AUTOMATION_MODE = "project-browser-automation";
var OWNER_PROJECT_GRANT_PROFILES = {
  [PROJECT_BROWSER_AUTOMATION_MODE]: [...PROJECT_BROWSER_ACTIONS].sort()
};
function json2(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
__name(json2, "json");
function isRecord3(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord3, "isRecord");
async function parseSmallJson2(request) {
  const raw = await request.text();
  if (!raw || raw.length > MAX_BODY_BYTES2) return null;
  try {
    const parsed = JSON.parse(raw);
    return isRecord3(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
__name(parseSmallJson2, "parseSmallJson");
function parseExpiry2(value) {
  if (value == null) return null;
  if (typeof value !== "string") return void 0;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
    return void 0;
  }
  return parsed.toISOString();
}
__name(parseExpiry2, "parseExpiry");
function normalizedProjects(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_PROJECTS) {
    return null;
  }
  const projects = /* @__PURE__ */ new Set();
  for (const item of value) {
    if (typeof item !== "string" || !PROJECT_SLUG_RE.test(item)) return null;
    projects.add(item);
  }
  if (projects.size < 1) return null;
  return [...projects].sort();
}
__name(normalizedProjects, "normalizedProjects");
function actionsForMode(mode) {
  const actions = OWNER_PROJECT_GRANT_PROFILES[mode];
  return actions?.length ? [...actions].sort() : null;
}
__name(actionsForMode, "actionsForMode");
function modeForActions(actions) {
  const normalized = [...actions].sort();
  for (const [mode, expectedActions] of Object.entries(OWNER_PROJECT_GRANT_PROFILES)) {
    if (JSON.stringify(normalized) === JSON.stringify([...expectedActions].sort())) {
      return mode;
    }
  }
  return "custom-project-grant";
}
__name(modeForActions, "modeForActions");
function onlyAllowedCreateKeys2(body) {
  const allowed = /* @__PURE__ */ new Set(["link_id", "mode", "projects", "expires_at"]);
  return Object.keys(body).every((key) => allowed.has(key));
}
__name(onlyAllowedCreateKeys2, "onlyAllowedCreateKeys");
function parsedGrant(row) {
  let actions;
  let projects;
  try {
    actions = JSON.parse(row.actions_json);
  } catch {
    return null;
  }
  try {
    projects = JSON.parse(row.projects_json);
  } catch {
    return null;
  }
  if (!Array.isArray(actions) || actions.length < 1 || !actions.every((item) => typeof item === "string") || !Array.isArray(projects) || projects.length < 1 || !projects.every((item) => typeof item === "string" && PROJECT_SLUG_RE.test(item))) {
    return null;
  }
  return { actions, projects };
}
__name(parsedGrant, "parsedGrant");
function rowIsOwnerProjectGrant(row) {
  const parsed = parsedGrant(row);
  return Boolean(parsed && modeForActions(parsed.actions) !== "custom-project-grant");
}
__name(rowIsOwnerProjectGrant, "rowIsOwnerProjectGrant");
function publicGrant2(row) {
  const parsed = parsedGrant(row) ?? { actions: [], projects: [] };
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    mode: modeForActions(parsed.actions),
    actions: parsed.actions,
    projects: parsed.projects,
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at
  };
}
__name(publicGrant2, "publicGrant");
async function linkedDeviceForOwner2(env, subjectId, linkId) {
  return env.DB.prepare(
    `SELECT l.id, l.subject_id, l.space_id, l.device_id
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.id = ?1
       AND l.subject_id = ?2
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL`
  ).bind(linkId, subjectId).first();
}
__name(linkedDeviceForOwner2, "linkedDeviceForOwner");
async function createOwnerProjectGrant(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json2({ ok: false, error: identity.error }, identity.status);
  const body = await parseSmallJson2(request);
  if (!body || !onlyAllowedCreateKeys2(body)) {
    return json2({ ok: false, error: "owner_project_grant_invalid" }, 400);
  }
  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const mode = typeof body.mode === "string" ? body.mode : "";
  const actions = actionsForMode(mode);
  const projects = normalizedProjects(body.projects);
  const expiresAt = parseExpiry2(body.expires_at);
  if (!UUID_RE2.test(linkId) || actions === null || projects === null || expiresAt === void 0) {
    return json2({ ok: false, error: "owner_project_grant_invalid" }, 400);
  }
  const link = await linkedDeviceForOwner2(env, identity.subjectId, linkId);
  if (!link) {
    return json2({ ok: false, error: "product_device_link_not_found" }, 404);
  }
  const actionsJson = JSON.stringify(actions);
  const projectsJson = JSON.stringify(projects);
  const existing = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants
     WHERE subject_id = ?1
       AND device_id = ?2
       AND ((space_id IS NULL AND ?3 = '') OR space_id = ?3)
       AND actions_json = ?4
       AND projects_json = ?5
       AND revoked_at IS NULL
       AND ((expires_at IS NULL AND ?6 IS NULL) OR expires_at = ?6)
     ORDER BY created_at DESC
     LIMIT 1`
  ).bind(
    identity.subjectId,
    link.device_id,
    link.space_id,
    actionsJson,
    projectsJson,
    expiresAt
  ).first();
  if (existing) {
    return json2({
      ok: true,
      replayed: true,
      mode,
      grant: publicGrant2(existing),
      provenance: { link_id: link.id }
    });
  }
  const grantId = crypto.randomUUID();
  const createdAt = (/* @__PURE__ */ new Date()).toISOString();
  await env.DB.prepare(
    `INSERT INTO ordax_product_grants
      (id, subject_id, space_id, device_id, actions_json, projects_json,
       expires_at, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)`
  ).bind(
    grantId,
    identity.subjectId,
    link.space_id || null,
    link.device_id,
    actionsJson,
    projectsJson,
    expiresAt,
    createdAt
  ).run();
  const created = {
    id: grantId,
    subject_id: identity.subjectId,
    space_id: link.space_id || null,
    device_id: link.device_id,
    actions_json: actionsJson,
    projects_json: projectsJson,
    expires_at: expiresAt,
    created_at: createdAt,
    revoked_at: null
  };
  return json2({
    ok: true,
    replayed: false,
    mode,
    grant: publicGrant2(created),
    provenance: { link_id: link.id }
  }, 201);
}
__name(createOwnerProjectGrant, "createOwnerProjectGrant");
async function listOwnerProjectGrants(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json2({ ok: false, error: identity.error }, identity.status);
  const url = new URL(request.url);
  const linkId = (url.searchParams.get("link_id") || "").trim();
  if (linkId && !UUID_RE2.test(linkId)) {
    return json2({ ok: false, error: "owner_project_grant_link_id_invalid" }, 400);
  }
  const query = linkId ? `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE g.subject_id = ?1
         AND l.id = ?2
         AND l.revoked_at IS NULL
         AND d.revoked_at IS NULL
       ORDER BY g.created_at DESC` : `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE g.subject_id = ?1
         AND l.revoked_at IS NULL
         AND d.revoked_at IS NULL
       ORDER BY g.created_at DESC`;
  const statement = env.DB.prepare(query);
  const result = linkId ? await statement.bind(identity.subjectId, linkId).all() : await statement.bind(identity.subjectId).all();
  return json2({
    ok: true,
    grants: (result.results ?? []).filter(rowIsOwnerProjectGrant).map(publicGrant2)
  });
}
__name(listOwnerProjectGrants, "listOwnerProjectGrants");
async function revokeOwnerProjectGrant(request, env, grantId) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json2({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE2.test(grantId)) {
    return json2({ ok: false, error: "owner_project_grant_id_invalid" }, 400);
  }
  const row = await env.DB.prepare(
    `SELECT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
            g.projects_json, g.expires_at, g.created_at, g.revoked_at
     FROM ordax_product_grants g
     JOIN ordax_product_device_links l
       ON l.subject_id = g.subject_id
      AND l.device_id = g.device_id
      AND l.space_id = COALESCE(g.space_id, '')
     WHERE g.id = ?1
       AND g.subject_id = ?2
       AND l.revoked_at IS NULL
     LIMIT 1`
  ).bind(grantId, identity.subjectId).first();
  if (!row || !rowIsOwnerProjectGrant(row)) {
    return json2({ ok: false, error: "owner_project_grant_not_found" }, 404);
  }
  if (row.revoked_at) {
    return json2({ ok: true, revoked: false, already_revoked: true, grant: publicGrant2(row) });
  }
  const revokedAt = (/* @__PURE__ */ new Date()).toISOString();
  const update = await env.DB.prepare(
    `UPDATE ordax_product_grants
     SET revoked_at = ?1
     WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL`
  ).bind(revokedAt, grantId, identity.subjectId).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json2({ ok: false, error: "owner_project_grant_revoke_conflict" }, 409);
  }
  return json2({
    ok: true,
    revoked: true,
    grant: publicGrant2({ ...row, revoked_at: revokedAt })
  });
}
__name(revokeOwnerProjectGrant, "revokeOwnerProjectGrant");

// src/product_intelligence_grants.ts
var UUID_RE3 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var APP_INTELLIGENCE_READ_MODE = "app-intelligence-read";
var MAX_BODY_BYTES3 = 16 * 1024;
function json3(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
__name(json3, "json");
function isRecord4(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord4, "isRecord");
async function parseSmallJson3(request) {
  const raw = await request.text();
  if (!raw || raw.length > MAX_BODY_BYTES3) return null;
  try {
    const parsed = JSON.parse(raw);
    return isRecord4(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
__name(parseSmallJson3, "parseSmallJson");
function parseExpiry3(value) {
  if (value == null) return null;
  if (typeof value !== "string") return void 0;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) return void 0;
  return parsed.toISOString();
}
__name(parseExpiry3, "parseExpiry");
function stableActions() {
  return [...APP_INTELLIGENCE_DEVICE_ACTIONS].sort();
}
__name(stableActions, "stableActions");
function publicGrant3(row) {
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    mode: APP_INTELLIGENCE_READ_MODE,
    actions: stableActions(),
    projects: [],
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at
  };
}
__name(publicGrant3, "publicGrant");
function rowIsAppIntelligenceGrant(row) {
  try {
    const actions = JSON.parse(row.actions_json);
    const projects = JSON.parse(row.projects_json);
    return Array.isArray(actions) && JSON.stringify([...actions].sort()) === JSON.stringify(stableActions()) && Array.isArray(projects) && projects.length === 0;
  } catch {
    return false;
  }
}
__name(rowIsAppIntelligenceGrant, "rowIsAppIntelligenceGrant");
async function linkedDeviceForOwner3(env, subjectId, linkId) {
  return env.DB.prepare(
    `SELECT l.id, l.subject_id, l.space_id, l.device_id
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.id = ?1
       AND l.subject_id = ?2
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL`
  ).bind(linkId, subjectId).first();
}
__name(linkedDeviceForOwner3, "linkedDeviceForOwner");
async function createOwnerDeviceIntelligenceGrant(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json3({ ok: false, error: identity.error }, identity.status);
  const body = await parseSmallJson3(request);
  if (!body || Object.keys(body).some((key) => !["link_id", "mode", "expires_at"].includes(key))) {
    return json3({ ok: false, error: "owner_app_intelligence_grant_invalid" }, 400);
  }
  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const mode = typeof body.mode === "string" ? body.mode : "";
  const expiresAt = parseExpiry3(body.expires_at);
  if (!UUID_RE3.test(linkId) || mode !== APP_INTELLIGENCE_READ_MODE || expiresAt === void 0) {
    return json3({ ok: false, error: "owner_app_intelligence_grant_invalid" }, 400);
  }
  const link = await linkedDeviceForOwner3(env, identity.subjectId, linkId);
  if (!link) return json3({ ok: false, error: "product_device_link_not_found" }, 404);
  const actionsJson = JSON.stringify(stableActions());
  const projectsJson = "[]";
  const existing = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants
     WHERE subject_id = ?1
       AND device_id = ?2
       AND ((space_id IS NULL AND ?3 = '') OR space_id = ?3)
       AND actions_json = ?4
       AND projects_json = ?5
       AND revoked_at IS NULL
       AND ((expires_at IS NULL AND ?6 IS NULL) OR expires_at = ?6)
     ORDER BY created_at DESC
     LIMIT 1`
  ).bind(
    identity.subjectId,
    link.device_id,
    link.space_id,
    actionsJson,
    projectsJson,
    expiresAt
  ).first();
  if (existing) {
    return json3({
      ok: true,
      replayed: true,
      mode,
      grant: publicGrant3(existing),
      provenance: { link_id: link.id }
    });
  }
  const grantId = crypto.randomUUID();
  const createdAt = (/* @__PURE__ */ new Date()).toISOString();
  await env.DB.prepare(
    `INSERT INTO ordax_product_grants
      (id, subject_id, space_id, device_id, actions_json, projects_json,
       expires_at, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)`
  ).bind(
    grantId,
    identity.subjectId,
    link.space_id || null,
    link.device_id,
    actionsJson,
    projectsJson,
    expiresAt,
    createdAt
  ).run();
  const created = {
    id: grantId,
    subject_id: identity.subjectId,
    space_id: link.space_id || null,
    device_id: link.device_id,
    actions_json: actionsJson,
    projects_json: projectsJson,
    expires_at: expiresAt,
    created_at: createdAt,
    revoked_at: null
  };
  return json3({
    ok: true,
    replayed: false,
    mode,
    grant: publicGrant3(created),
    provenance: { link_id: link.id }
  }, 201);
}
__name(createOwnerDeviceIntelligenceGrant, "createOwnerDeviceIntelligenceGrant");
async function listOwnerDeviceIntelligenceGrants(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json3({ ok: false, error: identity.error }, identity.status);
  const url = new URL(request.url);
  const linkId = (url.searchParams.get("link_id") || "").trim();
  if (linkId && !UUID_RE3.test(linkId)) {
    return json3({ ok: false, error: "owner_app_intelligence_grant_link_id_invalid" }, 400);
  }
  const query = linkId ? `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       WHERE g.subject_id = ?1
         AND l.id = ?2
         AND l.revoked_at IS NULL
       ORDER BY g.created_at DESC` : `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       WHERE g.subject_id = ?1
         AND l.revoked_at IS NULL
       ORDER BY g.created_at DESC`;
  const statement = env.DB.prepare(query);
  const result = linkId ? await statement.bind(identity.subjectId, linkId).all() : await statement.bind(identity.subjectId).all();
  return json3({
    ok: true,
    grants: (result.results ?? []).filter(rowIsAppIntelligenceGrant).map(publicGrant3)
  });
}
__name(listOwnerDeviceIntelligenceGrants, "listOwnerDeviceIntelligenceGrants");
async function revokeOwnerDeviceIntelligenceGrant(request, env, grantId) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json3({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE3.test(grantId)) {
    return json3({ ok: false, error: "owner_app_intelligence_grant_id_invalid" }, 400);
  }
  const row = await env.DB.prepare(
    `SELECT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
            g.projects_json, g.expires_at, g.created_at, g.revoked_at
     FROM ordax_product_grants g
     JOIN ordax_product_device_links l
       ON l.subject_id = g.subject_id
      AND l.device_id = g.device_id
      AND l.space_id = COALESCE(g.space_id, '')
     WHERE g.id = ?1
       AND g.subject_id = ?2
       AND l.revoked_at IS NULL
     LIMIT 1`
  ).bind(grantId, identity.subjectId).first();
  if (!row || !rowIsAppIntelligenceGrant(row)) {
    return json3({ ok: false, error: "owner_app_intelligence_grant_not_found" }, 404);
  }
  if (row.revoked_at) {
    return json3({ ok: true, revoked: false, already_revoked: true, grant: publicGrant3(row) });
  }
  const revokedAt = (/* @__PURE__ */ new Date()).toISOString();
  const update = await env.DB.prepare(
    "UPDATE ordax_product_grants SET revoked_at = ?1 WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL"
  ).bind(revokedAt, grantId, identity.subjectId).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json3({ ok: false, error: "owner_app_intelligence_grant_revoke_conflict" }, 409);
  }
  return json3({
    ok: true,
    revoked: true,
    grant: publicGrant3({ ...row, revoked_at: revokedAt })
  });
}
__name(revokeOwnerDeviceIntelligenceGrant, "revokeOwnerDeviceIntelligenceGrant");

// src/mcp_http.ts
var STRING = { type: "string" };
var OAUTH_SCOPES = ["openid", "email", "offline_access"];
var NUMBER = { type: "number" };
var BOOLEAN = { type: "boolean" };
var DEVICE = { type: "string", description: "ORDAX device UUID returned by ordax_targets." };
var PROJECT = { type: "string", description: "Registered ORDAX project slug." };
var SPACE = { type: "string", description: "Optional Product Space id used by the grant." };
var WAIT = { type: "integer", minimum: 0, maximum: 2e4, default: 8e3, description: "How long the gateway waits for completion before returning a request_id." };
var STRING_ARRAY = { type: "array", items: STRING, minItems: 1, maxItems: 256 };
var ENV_OBJECT = { type: "object", maxProperties: 64, additionalProperties: { anyOf: [{ type: "string" }, { type: "number" }, { type: "boolean" }] } };
var PROCESS_ENV_OBJECT = { type: "object", maxProperties: 64, additionalProperties: { type: "string" } };
var PROCESS_ARGV = { type: "array", items: { type: "string", minLength: 1, maxLength: 8192 }, minItems: 1, maxItems: 128 };
var PROCESS_STDIN_TEXT = { type: "string", maxLength: 65536 };
var REPLACEMENTS = {
  type: "array",
  minItems: 1,
  maxItems: 100,
  items: {
    type: "object",
    properties: {
      old: STRING,
      new: STRING,
      expected_count: { type: "integer", minimum: 1, maximum: 1e4 }
    },
    required: ["old", "new"],
    additionalProperties: false
  }
};
var MCP_TOOL_SURFACE_REVISION = "2026-10-06.1";
var TOOLS = [
  { name: "ordax_session", description: "Inspect whether the current ORDAX Product connection is authenticated." },
  { name: "ordax_profile", description: "Return the stable opaque profile id represented by the authenticated ORDAX credentials." },
  { name: "ordax_targets", description: "List ORDAX devices, Spaces and grants visible to the authenticated user." },
  { name: "ordax_action_status", description: "Read the status/result of a previously queued ORDAX action.", properties: { request_id: STRING }, required: ["request_id"] },
  { name: "app_intelligence_catalog", description: "Read the compact version-bound App Intelligence catalog from the connected ORDAX device. Use this only to discover which app semantics are available; it grants no execution authority.", action: "intelligence.app_catalog", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "app_intelligence_detail", description: "Read declarative instructions, intents, parameters and examples for one exact app_id from the connected ORDAX device. This never grants permission to execute the app.", action: "intelligence.app_detail", properties: { device_id: DEVICE, space_id: SPACE, app_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "app_id"] },
  { name: "repository_catalog", description: "List canonical repositories on an ORDAX device; use this to disambiguate a named project/repository before resuming work.", action: "workspace.repository_catalog", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "handoff_get", description: "Load an expiring ORDAX continuation handoff for a fresh client conversation.", action: "handoff.get", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, handoff_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "handoff_id"] },
  { name: "handoff_create", description: "Create an expiring continuation handoff so work can resume in a fresh client conversation.", action: "handoff.create", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, summary: STRING, next_action: STRING, completed: { type: "array", items: STRING, maxItems: 100 }, blockers: { type: "array", items: STRING, maxItems: 100 }, changed_paths: { type: "array", items: STRING, maxItems: 100 }, ttl_hours: { type: "integer", minimum: 1, maximum: 168 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "summary"] },
  { name: "project_inventory", description: "Inspect a bounded inventory of one registered project.", action: "project.inventory", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, max_depth: { type: "integer", minimum: 1, maximum: 12 }, max_entries: { type: "integer", minimum: 1, maximum: 1e4 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "project_text_read", description: "Read a granted text file inside a registered project.", action: "project.text_read", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "project_text_write", description: "Write a granted project text file with SHA-256 concurrency protection.", action: "project.text_write", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, content: STRING, expected_sha256: STRING, create: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "content"] },
  { name: "project_text_patch", description: "Patch a granted project text file using exact replacements and a SHA-256 precondition.", action: "project.text_patch", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, expected_sha256: STRING, replacements: { type: "array", items: { type: "object" }, maxItems: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "expected_sha256", "replacements"] },
  { name: "projects_list", description: "List granted projects. Use this first when the user asks to continue/resume project work but the target project is not yet known.", action: "projects.list", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "project_create", description: "Create and register a new project inside the device's configured ORDAX workspace.", action: "workspace.project_create", properties: { device_id: DEVICE, space_id: SPACE, slug: STRING, name: STRING, apps: { type: "array", items: { type: "string", enum: ["blender", "unity"] }, maxItems: 2, uniqueItems: true }, set_default: BOOLEAN, git_init: BOOLEAN, readme: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "slug"] },
  { name: "project_import", description: "Register an existing directory inside the configured ORDAX workspace; arbitrary paths outside the workspace are rejected by the runtime.", action: "workspace.bind_project", properties: { device_id: DEVICE, space_id: SPACE, slug: STRING, relative_path: STRING, apps: { type: "array", items: { type: "string", enum: ["blender", "unity"] }, maxItems: 2, uniqueItems: true }, set_default: BOOLEAN, blender_scripts_dir: STRING, blend_file: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "slug", "relative_path"] },
  { name: "project_search", description: "Search text across a granted project.", action: "project.search_text", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, query: STRING, max_results: { type: "integer", minimum: 1, maximum: 100 }, max_files: { type: "integer", minimum: 50, maximum: 5e3 }, case_sensitive: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "query"] },
  { name: "project_read_batch", description: "Read several granted project text files in one bounded call.", action: "project.text_read_batch", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, paths: { type: "array", items: STRING, minItems: 1, maxItems: 16 }, max_total_bytes: { type: "integer", minimum: 65536, maximum: 786432 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "paths"] },
  { name: "project_health", description: "Inspect sanitized project, Git, memory and adapter health.", action: "agent.project_health", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "project_briefing", description: "Load durable project state plus bounded relevant memory/source context. In a fresh chat, use this after identifying the project when the user asks to continue, resume, pick up, or review ongoing project work; pass the user intent as query when useful.", action: "agent.project_briefing", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, query: STRING, recall_limit: { type: "integer", minimum: 1, maximum: 50 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "continuity_state", description: "Read the non-expiring continuation state for a granted project.", action: "continuity.get", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "continuity_update", description: "Persist non-expiring project progress for future conversations.", action: "continuity.update", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, summary: STRING, next_action: STRING, completed: { type: "array", items: STRING, maxItems: 100 }, blockers: { type: "array", items: STRING, maxItems: 100 }, changed_paths: { type: "array", items: STRING, maxItems: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "summary"] },
  { name: "project_preview_status", description: "Inspect the project's supervised preview/runtime state.", action: "project.preview_status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "workspace_file_stat", description: "Inspect any path inside a granted project.", action: "workspace.file_stat", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "workspace_directory_list", description: "List directories anywhere inside a granted project.", action: "workspace.directory_list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, max_depth: { type: "integer", minimum: 1, maximum: 12 }, max_entries: { type: "integer", minimum: 1, maximum: 5e3 }, include_hidden: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "workspace_text_read", description: "Read UTF-8 text anywhere inside a granted project with optional line ranges.", action: "workspace.text_read", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, start_line: { type: "integer", minimum: 1 }, end_line: { type: "integer", minimum: 1 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "workspace_text_write", description: "Create or replace project text with SHA-256 concurrency protection.", action: "workspace.text_write", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, content: STRING, expected_sha256: STRING, create: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "content"] },
  { name: "workspace_text_patch", description: "Patch arbitrary project text using exact replacements and SHA-256 guards.", action: "workspace.text_patch", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, expected_sha256: STRING, replacements: REPLACEMENTS, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "expected_sha256", "replacements"] },
  { name: "workspace_directory_create", description: "Create a directory inside a granted project.", action: "workspace.directory_create", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, parents: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "workspace_path_remove", description: "Remove a project path. Recursive directory removal requires recursive=true.", action: "workspace.path_remove", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, expected_sha256: STRING, recursive: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "workspace_path_move", description: "Move or rename a path inside a granted project.", action: "workspace.path_move", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, source: STRING, destination: STRING, expected_sha256: STRING, overwrite: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "source", "destination"] },
  { name: "git_status", description: "Read bounded Git status for a granted project.", action: "git.status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "git_diff", description: "Read a bounded Git diff for a granted project.", action: "git.diff", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, paths: { type: "array", items: STRING, maxItems: 50 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "git_command", description: "Run an approved Git subcommand against a granted project. Repository hooks may execute, but credential/config inspection is blocked and authenticated remote URLs are redacted.", action: "git.command", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, args: { type: "array", items: STRING, minItems: 1, maxItems: 128 }, timeout_seconds: { type: "integer", minimum: 1, maximum: 1800 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "args"] },
  { name: "terminal_exec", description: "Execute a foreground command with the local OS user's permissions. Requires an explicit terminal.exec grant.", action: "terminal.exec", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, cwd: STRING, argv: STRING_ARRAY, command: STRING, shell: BOOLEAN, timeout_seconds: { type: "integer", minimum: 1, maximum: 1800 }, env: ENV_OBJECT, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "process_status", description: "Inspect one ORDAX-owned persistent process.", action: "process.status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, process_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id"] },
  { name: "process_list", description: "List ORDAX-owned persistent processes for a granted project.", action: "process.list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "process_logs", description: "Read a bounded log tail from an ORDAX-owned persistent process.", action: "process.logs", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, process_id: STRING, max_bytes: { type: "integer", minimum: 1024, maximum: 262144 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id"] },
  { name: "process_start", description: "Start a persistent argv-based process supervised by ORDAX inside a granted project. Requires an explicit process.start grant.", action: "process.start", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, argv: PROCESS_ARGV, cwd: STRING, env: PROCESS_ENV_OBJECT, wait_seconds: { type: "number", minimum: 0.1, maximum: 5 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "argv"] },
  { name: "process_write_stdin", description: "Send bounded stdin to an ORDAX-owned persistent process. Requires an explicit process.write_stdin grant.", action: "process.write_stdin", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, process_id: STRING, text: PROCESS_STDIN_TEXT, newline: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id", "text"] },
  { name: "process_stop", description: "Stop an ORDAX-owned persistent process. Requires an explicit process.stop grant.", action: "process.stop", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, process_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id"] },
  { name: "browser_status", description: "Read status for one ORDAX-managed Chromium session.", action: "browser.status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "browser_list", description: "List ORDAX-managed Chromium sessions for a granted project.", action: "browser.list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "browser_snapshot", description: "Read a bounded DOM/text snapshot from an ORDAX-managed Chromium session.", action: "browser.snapshot", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, max_elements: { type: "integer", minimum: 20, maximum: 500 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "browser_screenshot", description: "Capture an ORDAX-managed browser page through CDP, including while the Studio preview is not foreground.", action: "browser.screenshot", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, width: { type: "integer", minimum: 320, maximum: 2560 }, height: { type: "integer", minimum: 240, maximum: 1600 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "browser_start", description: "Start an isolated ORDAX-managed Chromium session. Consumer AI pages remain protected from programmatic browser automation.", action: "browser.start", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, url: STRING, headless: BOOLEAN, wait_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "browser_navigate", description: "Navigate an ORDAX-managed Chromium session to an allowed http/https URL.", action: "browser.navigate", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, url: STRING, wait_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id", "url"] },
  { name: "browser_click", description: "Click an element identified by a current ORDAX browser snapshot.", action: "browser.click", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, node_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id", "node_id"] },
  { name: "browser_type", description: "Enter text into an editable element in an ORDAX-managed browser session.", action: "browser.type", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, node_id: STRING, text: STRING, clear: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id", "node_id", "text"] },
  { name: "browser_stop", description: "Stop an ORDAX-owned Chromium session.", action: "browser.stop", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "computer_windows", description: "List visible windows on the interactive Windows desktop.", action: "computer.windows", properties: { device_id: DEVICE, space_id: SPACE, max_items: { type: "integer", minimum: 1, maximum: 500 }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_active_window", description: "Inspect the current foreground Windows desktop window.", action: "computer.active_window", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_screenshot", description: "Capture the full Windows desktop or active window for visual inspection.", action: "computer.screenshot", properties: { device_id: DEVICE, space_id: SPACE, mode: { type: "string", enum: ["desktop", "active_window"] }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_screen_info", description: "Inspect monitor geometry, virtual desktop bounds and cursor position.", action: "computer.screen_info", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_clipboard_read", description: "Read bounded Unicode text from the interactive Windows clipboard.", action: "computer.clipboard_read", properties: { device_id: DEVICE, space_id: SPACE, max_bytes: { type: "integer", minimum: 1, maximum: 1048576 }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_focus_window", description: "Bring one visible Windows window to the foreground.", action: "computer.focus_window", properties: { device_id: DEVICE, space_id: SPACE, handle: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "handle"] },
  { name: "computer_click", description: "Send a bounded mouse click to the interactive Windows desktop. Requires an explicit grant.", action: "computer.click", properties: { device_id: DEVICE, space_id: SPACE, x: { type: "integer" }, y: { type: "integer" }, button: { type: "string", enum: ["left", "right", "middle"] }, clicks: { type: "integer", minimum: 1, maximum: 3 }, wait_for_completion_ms: WAIT }, required: ["device_id", "x", "y"] },
  { name: "computer_mouse_move", description: "Move the pointer to a validated virtual-desktop coordinate.", action: "computer.mouse_move", properties: { device_id: DEVICE, space_id: SPACE, x: { type: "integer" }, y: { type: "integer" }, duration_ms: { type: "integer", minimum: 0, maximum: 5e3 }, wait_for_completion_ms: WAIT }, required: ["device_id", "x", "y"] },
  { name: "computer_drag", description: "Perform one bounded drag gesture on the interactive Windows desktop.", action: "computer.drag", properties: { device_id: DEVICE, space_id: SPACE, from_x: { type: "integer" }, from_y: { type: "integer" }, to_x: { type: "integer" }, to_y: { type: "integer" }, button: { type: "string", enum: ["left", "right", "middle"] }, duration_ms: { type: "integer", minimum: 50, maximum: 5e3 }, wait_for_completion_ms: WAIT }, required: ["device_id", "from_x", "from_y", "to_x", "to_y"] },
  { name: "computer_clipboard_write", description: "Replace Unicode text in the interactive Windows clipboard. Requires an explicit grant.", action: "computer.clipboard_write", properties: { device_id: DEVICE, space_id: SPACE, text: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "text"] },
  { name: "computer_launch_app", description: "Launch one validated Windows executable without shell expansion. Requires an explicit grant.", action: "computer.launch_app", properties: { device_id: DEVICE, space_id: SPACE, application: STRING, args: { type: "array", items: STRING, maxItems: 32 }, wait_for_completion_ms: WAIT }, required: ["device_id", "application"] },
  { name: "computer_scroll", description: "Send bounded scrolling to the interactive Windows desktop.", action: "computer.scroll", properties: { device_id: DEVICE, space_id: SPACE, amount: { type: "integer", minimum: -100, maximum: 100 }, horizontal: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "amount"] },
  { name: "computer_type", description: "Type bounded Unicode text into the interactive Windows desktop. Requires an explicit grant.", action: "computer.type", properties: { device_id: DEVICE, space_id: SPACE, text: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "text"] },
  { name: "computer_hotkey", description: "Send a bounded validated hotkey chord to the interactive Windows desktop. Requires an explicit grant.", action: "computer.hotkey", properties: { device_id: DEVICE, space_id: SPACE, keys: { type: "array", items: STRING, minItems: 1, maxItems: 6 }, wait_for_completion_ms: WAIT }, required: ["device_id", "keys"] },
  { name: "computer_access_status", description: "Read the local ORDAX computer-access policy and allowed filesystem roots.", action: "computer.access_status", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_file_stat", description: "Inspect a file or directory allowed by the local computer-access policy.", action: "computer.file_stat", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_directory_list", description: "List a directory tree allowed by the local computer-access policy.", action: "computer.directory_list", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, max_depth: { type: "integer", minimum: 1, maximum: 12 }, max_entries: { type: "integer", minimum: 1, maximum: 5e3 }, include_hidden: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_text_read", description: "Read bounded UTF-8 text from an allowed computer path.", action: "computer.text_read", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, start_line: { type: "integer", minimum: 1 }, end_line: { type: "integer", minimum: 1 }, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_search", description: "Search names or bounded text content under an allowed computer root.", action: "computer.search", properties: { device_id: DEVICE, space_id: SPACE, root: STRING, query: STRING, mode: { type: "string", enum: ["name", "content", "both"] }, max_results: { type: "integer", minimum: 1, maximum: 500 }, max_depth: { type: "integer", minimum: 1, maximum: 12 }, include_hidden: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "root", "query"] },
  { name: "computer_processes", description: "List bounded system process metadata on the authorized computer.", action: "computer.processes", properties: { device_id: DEVICE, space_id: SPACE, query: STRING, max_items: { type: "integer", minimum: 1, maximum: 1e3 }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_terminate_process", description: "Terminate one non-critical process only when expected_name still matches the PID.", action: "computer.terminate_process", properties: { device_id: DEVICE, space_id: SPACE, pid: { type: "integer", minimum: 1 }, expected_name: STRING, force: BOOLEAN, tree: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "pid", "expected_name"] },
  { name: "computer_text_write", description: "Create or replace text at an allowed computer path with SHA-256 concurrency protection.", action: "computer.text_write", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, content: STRING, expected_sha256: STRING, create: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path", "content"] },
  { name: "computer_text_patch", description: "Patch allowed computer text using exact replacements and a SHA-256 precondition.", action: "computer.text_patch", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, expected_sha256: STRING, replacements: REPLACEMENTS, wait_for_completion_ms: WAIT }, required: ["device_id", "path", "expected_sha256", "replacements"] },
  { name: "computer_directory_create", description: "Create a directory within the local computer-access policy.", action: "computer.directory_create", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, parents: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_path_move", description: "Move or rename an allowed computer path.", action: "computer.path_move", properties: { device_id: DEVICE, space_id: SPACE, source: STRING, destination: STRING, overwrite: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "source", "destination"] },
  { name: "computer_path_remove", description: "Remove an allowed computer path. Recursive directory removal requires recursive=true.", action: "computer.path_remove", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, recursive: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "artifacts_list", description: "List bounded artifact metadata for a granted project.", action: "artifacts.list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, max_items: { type: "integer", minimum: 1, maximum: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "artifact_preview", description: "Read a bounded preview of a granted project artifact.", action: "artifact.preview", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, artifact_name: STRING, project_artifact_path: STRING, thumbnail: BOOLEAN, max_bytes: { type: "integer", minimum: 1, maximum: 262144 }, max_width: { type: "integer", minimum: 1, maximum: 4096 }, max_height: { type: "integer", minimum: 1, maximum: 4096 }, quality: { type: "integer", minimum: 1, maximum: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_status", description: "Read sanitized live Blender status for a project.", action: "blender.live_status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_scene_snapshot", description: "Inspect a bounded snapshot of the live Blender scene.", action: "blender.live_scene_snapshot", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, max_objects: { type: "integer", minimum: 1, maximum: 1e4 }, object_names: { type: "array", items: STRING, maxItems: 256 }, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_object_inspect", description: "Inspect one live Blender object by name or ORDAX object id.", action: "blender.live_object_inspect", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, object_name: STRING, ordax_object_id: STRING, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_modeling_schema", description: "Read the validated live Blender modeling contracts and guards.", action: "blender.live_modeling_schema", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_start", description: "Adopt or start the project's visible Blender session without opening duplicate windows.", action: "blender.live_start", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_seconds: NUMBER, timeout_seconds: NUMBER, pid: { type: "integer", minimum: 1 }, adopt_blank: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_transform", description: "Apply a validated transform to one live Blender object.", action: "blender.live_object_transform", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, object_name: STRING, ordax_object_id: STRING, location: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, rotation_euler: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, scale: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, dimensions: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_create_primitive", description: "Create a bounded validated primitive in the live Blender scene.", action: "blender.live_create_primitive", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, name: STRING, primitive: STRING, location: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, size: NUMBER, radius: NUMBER, depth: NUMBER, segments: { type: "integer" }, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "name", "primitive"] },
  { name: "blender_apply_material", description: "Apply a validated material to one live Blender object.", action: "blender.live_material_apply", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, object_name: STRING, ordax_object_id: STRING, material_name: STRING, base_color: { type: "array", items: NUMBER, minItems: 3, maxItems: 4 }, roughness: NUMBER, metallic: NUMBER, transmission: NUMBER, alpha: NUMBER, ior: NUMBER, surface_render_method: STRING, transparency_overlap: BOOLEAN, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "material_name"] },
  { name: "blender_save", description: "Save the granted live Blender project.", action: "blender.live_save", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, target_path: STRING, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] }
];
var READ_ONLY_TOOLS = /* @__PURE__ */ new Set([
  "ordax_session",
  "ordax_profile",
  "ordax_targets",
  "ordax_action_status",
  "app_intelligence_catalog",
  "app_intelligence_detail",
  "repository_catalog",
  "handoff_get",
  "project_inventory",
  "project_text_read",
  "projects_list",
  "project_search",
  "project_read_batch",
  "project_health",
  "project_briefing",
  "continuity_state",
  "project_preview_status",
  "workspace_file_stat",
  "workspace_directory_list",
  "workspace_text_read",
  "git_status",
  "git_diff",
  "artifacts_list",
  "artifact_preview",
  "blender_status",
  "blender_scene_snapshot",
  "blender_object_inspect",
  "blender_modeling_schema",
  "browser_status",
  "browser_list",
  "browser_snapshot",
  "browser_screenshot",
  "computer_windows",
  "computer_active_window",
  "computer_screenshot",
  "computer_screen_info",
  "computer_clipboard_read",
  "computer_access_status",
  "computer_file_stat",
  "computer_directory_list",
  "computer_text_read",
  "computer_search",
  "computer_processes",
  "process_status",
  "process_list",
  "process_logs"
]);
var DESTRUCTIVE_TOOLS = /* @__PURE__ */ new Set([
  "project_text_write",
  "project_text_patch",
  "continuity_update",
  "workspace_text_write",
  "workspace_text_patch",
  "workspace_path_remove",
  "workspace_path_move",
  "git_command",
  "terminal_exec",
  "process_start",
  "process_write_stdin",
  "process_stop",
  "blender_transform",
  "blender_apply_material",
  "blender_save",
  "browser_click",
  "browser_type",
  "browser_stop",
  "computer_click",
  "computer_drag",
  "computer_type",
  "computer_hotkey",
  "computer_text_write",
  "computer_text_patch",
  "computer_path_move",
  "computer_path_remove",
  "computer_terminate_process"
]);
var NON_DESTRUCTIVE_WRITE_TOOLS = /* @__PURE__ */ new Set([
  "project_create",
  "project_import",
  "handoff_create",
  "workspace_directory_create",
  "blender_start",
  "blender_create_primitive",
  "browser_start",
  "browser_navigate",
  "computer_focus_window",
  "computer_mouse_move",
  "computer_scroll",
  "computer_clipboard_write",
  "computer_launch_app",
  "computer_directory_create"
]);
var OPEN_WORLD_TOOLS = /* @__PURE__ */ new Set([
  "git_command",
  "terminal_exec",
  "process_start",
  "process_write_stdin",
  "browser_snapshot",
  "browser_screenshot",
  "browser_start",
  "browser_navigate",
  "browser_click",
  "browser_type",
  "computer_click",
  "computer_mouse_move",
  "computer_drag",
  "computer_type",
  "computer_hotkey",
  "computer_launch_app"
]);
var TOOL_TITLES = {
  ordax_session: "Check ORDAX account session",
  ordax_profile: "Identify connected ORDAX account",
  ordax_targets: "List connected ORDAX devices",
  ordax_action_status: "Check ORDAX action status",
  app_intelligence_catalog: "List App Intelligence catalog",
  app_intelligence_detail: "Read App Intelligence detail",
  repository_catalog: "List device repositories",
  handoff_get: "Load continuation handoff",
  handoff_create: "Create continuation handoff",
  project_inventory: "Inspect project inventory",
  project_text_read: "Read project text file",
  project_text_write: "Write project text file",
  project_text_patch: "Patch project text file",
  projects_list: "List device projects",
  project_create: "Create ORDAX project",
  project_import: "Import existing ORDAX project",
  project_search: "Search project text",
  project_read_batch: "Read project files",
  project_health: "Inspect project health",
  project_briefing: "Load project briefing",
  continuity_state: "Read project continuity",
  continuity_update: "Update project continuity",
  project_preview_status: "Inspect project preview",
  workspace_file_stat: "Inspect project path",
  workspace_directory_list: "List project directory",
  workspace_text_read: "Read workspace text",
  workspace_text_write: "Write workspace text",
  workspace_text_patch: "Patch workspace text",
  workspace_directory_create: "Create workspace directory",
  workspace_path_remove: "Remove workspace path",
  workspace_path_move: "Move workspace path",
  git_status: "Read Git status",
  git_diff: "Read Git diff",
  git_command: "Run Git command",
  terminal_exec: "Run project command",
  process_status: "Inspect persistent process",
  process_list: "List persistent processes",
  process_logs: "Read persistent process logs",
  process_start: "Start persistent process",
  process_write_stdin: "Send process input",
  process_stop: "Stop persistent process",
  browser_status: "Inspect managed browser status",
  browser_list: "List managed browsers",
  browser_snapshot: "Inspect browser page",
  browser_screenshot: "Capture browser page",
  browser_start: "Start managed browser",
  browser_navigate: "Navigate managed browser",
  browser_click: "Click browser element",
  browser_type: "Type in browser element",
  browser_stop: "Stop managed browser",
  computer_windows: "List desktop windows",
  computer_active_window: "Inspect active desktop window",
  computer_screenshot: "Capture desktop",
  computer_screen_info: "Inspect desktop screens",
  computer_clipboard_read: "Read desktop clipboard",
  computer_focus_window: "Focus desktop window",
  computer_click: "Click desktop",
  computer_mouse_move: "Move desktop pointer",
  computer_drag: "Drag on desktop",
  computer_clipboard_write: "Write desktop clipboard",
  computer_launch_app: "Launch desktop application",
  computer_scroll: "Scroll desktop",
  computer_type: "Type on desktop",
  computer_hotkey: "Send desktop hotkey",
  computer_access_status: "Inspect computer access policy",
  computer_file_stat: "Inspect computer path",
  computer_directory_list: "List computer directory",
  computer_text_read: "Read computer text",
  computer_search: "Search computer files",
  computer_processes: "List system processes",
  computer_terminate_process: "Terminate system process",
  computer_text_write: "Write computer text",
  computer_text_patch: "Patch computer text",
  computer_directory_create: "Create computer directory",
  computer_path_move: "Move computer path",
  computer_path_remove: "Remove computer path",
  artifacts_list: "List project artifacts",
  artifact_preview: "Preview project artifact",
  blender_status: "Inspect Blender status",
  blender_scene_snapshot: "Inspect Blender scene",
  blender_object_inspect: "Inspect Blender object",
  blender_modeling_schema: "Read Blender modeling capabilities",
  blender_start: "Start or adopt Blender",
  blender_transform: "Transform Blender object",
  blender_create_primitive: "Create Blender primitive",
  blender_apply_material: "Apply Blender material",
  blender_save: "Save Blender project"
};
function toolAnnotations(name) {
  const readOnly = READ_ONLY_TOOLS.has(name);
  const destructive = DESTRUCTIVE_TOOLS.has(name);
  const nonDestructiveWrite = NON_DESTRUCTIVE_WRITE_TOOLS.has(name);
  const effectClassCount = Number(readOnly) + Number(destructive) + Number(nonDestructiveWrite);
  if (effectClassCount !== 1) {
    throw new Error(`MCP tool must have exactly one explicit effect classification: ${name}`);
  }
  return {
    readOnlyHint: readOnly,
    destructiveHint: destructive,
    openWorldHint: OPEN_WORLD_TOOLS.has(name),
    idempotentHint: readOnly
  };
}
__name(toolAnnotations, "toolAnnotations");
function toolInvocationText(name) {
  const title = TOOL_TITLES[name] ?? name.replace(/_/g, " ");
  return {
    invoking: `${title}\xD4\xC7\xAA`.slice(0, 64),
    invoked: `${title} complete`.slice(0, 64)
  };
}
__name(toolInvocationText, "toolInvocationText");
function responseJson(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}
__name(responseJson, "responseJson");
function rpcResult(id, result) {
  return responseJson({ jsonrpc: "2.0", id, result });
}
__name(rpcResult, "rpcResult");
function rpcError(id, code, message, data) {
  return responseJson({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...data === void 0 ? {} : { data } } });
}
__name(rpcError, "rpcError");
async function bodyJson(response) {
  try {
    const value = await response.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}
__name(bodyJson, "bodyJson");
function sanitizeTargets(payload) {
  const rawTargets = Array.isArray(payload.targets) ? payload.targets : [];
  const targets = rawTargets.flatMap((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
    const target = raw;
    const rawGrants = Array.isArray(target.grants) ? target.grants : [];
    const grants = rawGrants.flatMap((rawGrant) => {
      if (!rawGrant || typeof rawGrant !== "object" || Array.isArray(rawGrant)) return [];
      const grant = rawGrant;
      return [{
        space_id: typeof grant.space_id === "string" ? grant.space_id : null,
        actions: Array.isArray(grant.actions) ? grant.actions.filter((item) => typeof item === "string") : [],
        projects: Array.isArray(grant.projects) ? grant.projects.filter((item) => typeof item === "string") : []
      }];
    });
    return [{
      device_id: typeof target.device_id === "string" ? target.device_id : "",
      name: typeof target.name === "string" ? target.name : "ORDAX device",
      link_id: typeof target.link_id === "string" ? target.link_id : null,
      grants
    }];
  });
  return { ok: payload.ok !== false, targets };
}
__name(sanitizeTargets, "sanitizeTargets");
function sanitizeActionPayload(payload, requestId) {
  if (payload.pending === true) {
    return {
      ok: payload.ok !== false,
      pending: true,
      request_id: requestId ?? (typeof payload.request_id === "string" ? payload.request_id : ""),
      message: typeof payload.message === "string" ? payload.message : "Action is still running."
    };
  }
  const rawAction = payload.action;
  if (rawAction && typeof rawAction === "object" && !Array.isArray(rawAction)) {
    const action = rawAction;
    const status = typeof action.status === "string" ? action.status : "";
    const pending = !["succeeded", "failed", "cancelled"].includes(status);
    return {
      ok: payload.ok !== false,
      pending,
      request_id: requestId ?? (typeof action.request_id === "string" ? action.request_id : ""),
      action: {
        name: typeof action.action === "string" ? action.action : "",
        project: typeof action.project === "string" ? action.project : null,
        status,
        result: action.result ?? null,
        error_code: typeof action.error_code === "string" ? action.error_code : null
      }
    };
  }
  if (payload.ok === false) {
    return {
      ok: false,
      pending: false,
      error: typeof payload.error === "string" ? payload.error : "ordax_action_failed"
    };
  }
  return { ok: payload.ok !== false, pending: false };
}
__name(sanitizeActionPayload, "sanitizeActionPayload");
function textToolResult(payload, isError = false) {
  const text = JSON.stringify(payload, null, 2);
  const structured = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : { value: payload };
  return { content: [{ type: "text", text }], structuredContent: structured, isError };
}
__name(textToolResult, "textToolResult");
function cloneWithAuth(source, url, method, body) {
  const headers = new Headers();
  const auth = source.headers.get("authorization");
  if (auth) headers.set("authorization", auth);
  if (body !== void 0) headers.set("content-type", "application/json");
  return new Request(url, { method, headers, body: body === void 0 ? void 0 : JSON.stringify(body) });
}
__name(cloneWithAuth, "cloneWithAuth");
function toolDefinitions() {
  return TOOLS.map((tool) => {
    const invocation = toolInvocationText(tool.name);
    return {
      name: tool.name,
      title: TOOL_TITLES[tool.name] ?? tool.name.replace(/_/g, " "),
      description: tool.description,
      securitySchemes: [{ type: "oauth2", scopes: OAUTH_SCOPES }],
      annotations: toolAnnotations(tool.name),
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: OAUTH_SCOPES }],
        ...tool.name === "ordax_profile" ? { "openai/profile": true } : {},
        "openai/toolInvocation/invoking": invocation.invoking,
        "openai/toolInvocation/invoked": invocation.invoked
      },
      inputSchema: {
        type: "object",
        properties: tool.properties ?? {},
        required: tool.required ?? [],
        additionalProperties: false
      },
      outputSchema: tool.name === "ordax_profile" ? {
        type: "object",
        properties: {
          id: { type: "string", minLength: 1, pattern: "\\S" }
        },
        required: ["id"],
        additionalProperties: false
      } : {
        type: "object",
        additionalProperties: true
      }
    };
  });
}
__name(toolDefinitions, "toolDefinitions");
function specFor(name) {
  return TOOLS.find((tool) => tool.name === name);
}
__name(specFor, "specFor");
var COMPUTER_GRANT_SURFACE = "ORDAX Studio > Acesso ao computador";
var BROWSER_GRANT_SURFACE = "ORDAX Studio > Navegador gerenciado";
var APP_INTELLIGENCE_GRANT_SURFACE = "ORDAX Studio > Intelig\xEAncia de aplicativos";
var OWNER_GRANT_HINT_BY_ACTION = new Map([
  ...[
    "intelligence.app_catalog",
    "intelligence.app_detail"
  ].map((action) => [action, { profile: "app-intelligence-read", surface: APP_INTELLIGENCE_GRANT_SURFACE }]),
  ...[
    "computer.active_window",
    "computer.click",
    "computer.drag",
    "computer.focus_window",
    "computer.hotkey",
    "computer.launch_app",
    "computer.mouse_move",
    "computer.processes",
    "computer.screen_info",
    "computer.screenshot",
    "computer.scroll",
    "computer.type",
    "computer.windows"
  ].map((action) => [action, { profile: "interactive-computer-control", surface: COMPUTER_GRANT_SURFACE }]),
  ...[
    "computer.directory_create",
    "computer.directory_list",
    "computer.file_stat",
    "computer.path_move",
    "computer.path_remove",
    "computer.search",
    "computer.text_patch",
    "computer.text_read",
    "computer.text_write"
  ].map((action) => [action, { profile: "computer-filesystem", surface: COMPUTER_GRANT_SURFACE }]),
  ...[
    "computer.clipboard_read",
    "computer.clipboard_write"
  ].map((action) => [action, { profile: "computer-clipboard", surface: COMPUTER_GRANT_SURFACE }]),
  ["computer.terminate_process", { profile: "computer-process-control", surface: COMPUTER_GRANT_SURFACE }],
  ...[
    "browser.click",
    "browser.list",
    "browser.navigate",
    "browser.screenshot",
    "browser.snapshot",
    "browser.start",
    "browser.status",
    "browser.stop",
    "browser.type"
  ].map((action) => [action, { profile: "project-browser-automation", surface: BROWSER_GRANT_SURFACE }])
]);
function authorizationHintForAction(action) {
  const hint = OWNER_GRANT_HINT_BY_ACTION.get(action);
  if (!hint) return null;
  return {
    required_owner_profile: hint.profile,
    authorization_surface: hint.surface,
    authorization_required: true
  };
}
__name(authorizationHintForAction, "authorizationHintForAction");
async function waitForAction(source, requestId, timeoutMs, handlers) {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    const statusRequest = cloneWithAuth(source, new URL(`/v3/product/actions/${requestId}`, source.url).toString(), "GET");
    const statusResponse = await handlers.getAction(statusRequest, requestId);
    const payload = await bodyJson(statusResponse);
    if (!statusResponse.ok) return { ok: false, pending: false, request_id: requestId, upstream_status: statusResponse.status, response: payload };
    const action = payload.action;
    if (action && typeof action === "object" && !Array.isArray(action)) {
      const state = String(action.status ?? "");
      if (["succeeded", "failed", "cancelled"].includes(state)) return sanitizeActionPayload({ ...payload, pending: false }, requestId);
    }
    if (Date.now() >= deadline) return sanitizeActionPayload({ ok: true, pending: true, request_id: requestId, message: "Action is still running; call ordax_action_status with this request_id." }, requestId);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}
__name(waitForAction, "waitForAction");
async function callTool(source, name, args, handlers) {
  if (name === "ordax_session") {
    const response = await handlers.session(cloneWithAuth(source, new URL("/v3/product/session", source.url).toString(), "GET"));
    return textToolResult(
      response.ok ? {
        ok: true,
        authenticated: true,
        mcp_tool_surface_revision: MCP_TOOL_SURFACE_REVISION,
        mcp_tool_count: TOOLS.length
      } : {
        ok: false,
        authenticated: false,
        error: "authentication_required",
        mcp_tool_surface_revision: MCP_TOOL_SURFACE_REVISION,
        mcp_tool_count: TOOLS.length
      },
      !response.ok
    );
  }
  if (name === "ordax_profile") {
    const response = await handlers.session(cloneWithAuth(source, new URL("/v3/product/session", source.url).toString(), "GET"));
    const payload = await bodyJson(response);
    const session = payload.session;
    const subjectId = session && typeof session === "object" && !Array.isArray(session) ? session.subject_id : null;
    if (!response.ok || typeof subjectId !== "string" || !subjectId.trim()) {
      return textToolResult({ ok: false, error: "profile_unavailable" }, true);
    }
    return textToolResult({ id: subjectId });
  }
  if (name === "ordax_targets") {
    const response = await handlers.targets(cloneWithAuth(source, new URL("/v3/product/targets", source.url).toString(), "GET"));
    const payload = await bodyJson(response);
    return textToolResult(response.ok ? sanitizeTargets(payload) : { ok: false, error: "targets_unavailable" }, !response.ok);
  }
  if (name === "ordax_action_status") {
    const requestId2 = typeof args.request_id === "string" ? args.request_id : "";
    if (!requestId2) return textToolResult({ ok: false, error: "request_id_required" }, true);
    const response = await handlers.getAction(cloneWithAuth(source, new URL(`/v3/product/actions/${requestId2}`, source.url).toString(), "GET"), requestId2);
    const payload = await bodyJson(response);
    return textToolResult(response.ok ? sanitizeActionPayload(payload, requestId2) : { ok: false, error: "action_status_unavailable" }, !response.ok);
  }
  const spec = specFor(name);
  if (!spec?.action) return textToolResult({ ok: false, error: "tool_not_found", tool: name }, true);
  const deviceId = typeof args.device_id === "string" ? args.device_id : "";
  const project = spec.projectRequired && typeof args.project === "string" ? args.project : null;
  const spaceId = typeof args.space_id === "string" ? args.space_id : null;
  const rawWait = typeof args.wait_for_completion_ms === "number" ? args.wait_for_completion_ms : 8e3;
  const waitMs = Math.max(0, Math.min(2e4, Math.floor(rawWait)));
  const actionArgs = {};
  for (const [key, value] of Object.entries(args)) {
    if (!["device_id", "project", "space_id", "wait_for_completion_ms"].includes(key)) actionArgs[key] = value;
  }
  const createRequest = cloneWithAuth(source, new URL("/v3/product/actions", source.url).toString(), "POST", {
    device_id: deviceId,
    space_id: spaceId,
    action: spec.action,
    project,
    arguments: actionArgs
  });
  const created = await handlers.createAction(createRequest);
  const createdPayload = await bodyJson(created);
  if (!created.ok) {
    if (createdPayload.error === "product_grant_not_resolved") {
      const hint = authorizationHintForAction(spec.action);
      return textToolResult(hint ? { ...createdPayload, ...hint } : createdPayload, true);
    }
    return textToolResult(createdPayload, true);
  }
  const requestId = typeof createdPayload.request_id === "string" ? createdPayload.request_id : "";
  if (!requestId) return textToolResult({ ok: false, error: "product_request_id_missing", response: createdPayload }, true);
  const finalPayload = await waitForAction(source, requestId, waitMs, handlers);
  const action = finalPayload.action;
  const failed = finalPayload.ok === false || Boolean(action && typeof action === "object" && !Array.isArray(action) && String(action.status ?? "") !== "succeeded" && !finalPayload.pending);
  return textToolResult(finalPayload, failed);
}
__name(callTool, "callTool");
async function handleOrdaxMcp(request, handlers) {
  if (request.method === "GET") return new Response(null, { status: 405, headers: { allow: "POST" } });
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "GET, POST" } });
  const sessionProbe = await handlers.session(cloneWithAuth(request, new URL("/v3/product/session", request.url).toString(), "GET"));
  if (!sessionProbe.ok) {
    const headers = new Headers(sessionProbe.headers);
    headers.set("www-authenticate", `Bearer resource_metadata="${new URL("/.well-known/oauth-protected-resource", request.url).toString()}"`);
    return new Response(sessionProbe.body, { status: sessionProbe.status, headers });
  }
  let message;
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid");
    message = raw;
  } catch {
    return rpcError(null, -32700, "Parse error");
  }
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string") return rpcError(message.id, -32600, "Invalid Request");
  const id = message.id;
  const method = message.method;
  if (method === "notifications/initialized") return new Response(null, { status: 202 });
  if (method === "ping") return rpcResult(id, {});
  if (method === "initialize") return rpcResult(id, {
    protocolVersion: "2025-06-18",
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: "ORDAX Control Plane", version: "0.4.2" },
    instructions: "Use ORDAX Studio only when the user asks to work with a connected ORDAX device or one of its registered projects. List connected devices before project-scoped work when the target is unknown. Respect project boundaries and the user's explicit intent. Write, execute, Git and Blender mutation tools remain grant- and audit-protected by the ORDAX Runtime."
  });
  if (method === "tools/list") return rpcResult(id, { tools: toolDefinitions() });
  if (method === "tools/call") {
    const params = message.params;
    if (!params || typeof params !== "object" || Array.isArray(params)) return rpcError(id, -32602, "Invalid params");
    const name = typeof params.name === "string" ? String(params.name) : "";
    const rawArgs = params.arguments;
    const args = rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs) ? rawArgs : {};
    if (!specFor(name)) return rpcError(id, -32601, "Tool not found", { tool: name });
    try {
      return rpcResult(id, await callTool(request, name, args, handlers));
    } catch (error) {
      return rpcResult(id, textToolResult({ ok: false, error: "ordax_mcp_internal_error", detail: error instanceof Error ? error.message : String(error) }, true));
    }
  }
  return rpcError(id, -32601, "Method not found");
}
__name(handleOrdaxMcp, "handleOrdaxMcp");

// src/product_results.ts
function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
__name(object, "object");
function scopeProductResult(action, result, projectsJson) {
  if (action !== "projects.list" && action !== "workspace.repository_catalog") return result;
  const envelope = object(result);
  const data = object(envelope?.data);
  if (!envelope || !data) return null;
  let projects = null;
  try {
    projects = typeof projectsJson === "string" ? JSON.parse(projectsJson) : null;
  } catch {
  }
  const allowed = new Set(Array.isArray(projects) && projects.every((item) => typeof item === "string") ? projects : []);
  const entries = Array.isArray(data.projects) ? data.projects : [];
  const safeProjects = entries.flatMap((entry) => {
    const item = object(entry);
    if (!item || typeof item.slug !== "string" || !allowed.has(item.slug)) return [];
    const safe = {};
    for (const key of ["slug", "apps", "available", "allowed_branches", "preview_mode"]) {
      if (key in item) safe[key] = item[key];
    }
    const repository = object(item.repository);
    if (action === "workspace.repository_catalog" && repository) {
      const publicRepository = {};
      for (const key of ["is_repository", "branch", "remote", "has_origin", "dirty", "changed_entries", "status_available"]) {
        if (key in repository) publicRepository[key] = repository[key];
      }
      safe.repository = publicRepository;
    }
    return [safe];
  });
  const safeData = { projects: safeProjects };
  const selectedKey = action === "projects.list" ? "default_project" : "active_project";
  if (typeof data[selectedKey] === "string" && allowed.has(data[selectedKey])) safeData[selectedKey] = data[selectedKey];
  if (object(data.agent_timings)) safeData.agent_timings = data.agent_timings;
  return { ok: envelope.ok, summary: envelope.summary, data: safeData };
}
__name(scopeProductResult, "scopeProductResult");

// src/oauth_consent.ts
var AUTH_ORIGIN = "https://eobcxuyvhkvdmkbaihwh.supabase.co";
var SUPABASE_PUBLISHABLE_KEY = "sb_publishable_GQUBlAVTzgNtscw9iE5vLQ_GGtdmsL5";
var SUPABASE_JS = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm";
function jsonForScript(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}
__name(jsonForScript, "jsonForScript");
function oauthConsentResponse(request) {
  const url = new URL(request.url);
  const authorizationId = url.searchParams.get("authorization_id") ?? "";
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const redirectUrl = `${url.origin}/oauth/consent?authorization_id=${encodeURIComponent(authorizationId)}`;
  const html2 = `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Autorizar acesso ao ORDAX</title>
<style nonce="${nonce}">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#080f19;color:#e2ebf7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}.card{width:min(560px,100%);background:#111e30;border:1px solid #243249;border-radius:20px;padding:28px;box-shadow:0 24px 80px #0008}.eyebrow{color:#a9c9f7;font-size:12px;letter-spacing:.16em;text-transform:uppercase}h1{font-size:28px;font-weight:450;margin:10px 0 8px}p{color:#8e9db4;line-height:1.55}.panel{background:#090f1b;border:1px solid #243249;border-radius:14px;padding:16px;margin:18px 0}.row{display:flex;gap:10px;flex-wrap:wrap}input{width:100%;background:#080f19;color:#e2ebf7;border:1px solid #34445e;border-radius:10px;padding:12px;margin:6px 0}button{border:0;border-radius:10px;padding:12px 16px;font-weight:600;cursor:pointer;background:#d1e4ff;color:#172b47}.secondary{background:#1a2a40;color:#c9d8eb}.danger{background:#35212a;color:#ffc7d7}.muted{font-size:13px;color:#8e9db4}.status{white-space:pre-wrap;font-size:13px;margin-top:12px}.hidden{display:none}.details dt{font-size:12px;color:#8e9db4;margin-top:10px}.details dd{margin:3px 0 0;overflow-wrap:anywhere}code{font-size:12px;color:#a9c9f7}
</style></head><body><main class="card"><div class="eyebrow">ORDAX</div><h1>Autorizar conex\xE3o</h1><p>Autorize este cliente a acessar capabilities ORDAX no seu dispositivo. O acesso continua limitado pelos grants, pelo v\xEDnculo do dispositivo e pela pol\xEDtica local; todas as a\xE7\xF5es permanecem audit\xE1veis.</p>
<div id="missing" class="panel hidden">Solicita\xE7\xE3o OAuth inv\xE1lida: <code>authorization_id</code> ausente.</div>
<section id="login" class="hidden"><div class="panel"><strong>Entre na sua conta ORDAX</strong><p class="muted">A senha \xE9 enviada diretamente ao Supabase Auth e nunca passa pelo Worker do ORDAX.</p><input id="email" type="email" autocomplete="email" placeholder="E-mail"><input id="password" type="password" autocomplete="current-password" placeholder="Senha"><div class="row"><button id="passwordLogin">Entrar</button><button id="magicLogin" class="secondary">Enviar link de acesso</button></div><div id="loginStatus" class="status"></div></div></section>
<section id="consent" class="hidden"><div class="panel"><div class="muted">Conectado como</div><div id="userEmail"></div><dl class="details"><dt>Cliente</dt><dd id="clientName"></dd><dt>Redirecionamento</dt><dd id="redirectUri"></dd><dt>Permiss\xF5es OAuth</dt><dd id="scopes"></dd></dl></div><div class="row"><button id="approve">Autorizar</button><button id="deny" class="danger">Negar</button><button id="signOut" class="secondary">Trocar conta</button></div><div id="consentStatus" class="status"></div></section>
</main><script type="module" nonce="${nonce}">
import { createClient } from "${SUPABASE_JS}";
const authorizationId=${jsonForScript(authorizationId)};
const returnUrl=${jsonForScript(redirectUrl)};
const client=createClient(${jsonForScript(AUTH_ORIGIN)},${jsonForScript(SUPABASE_PUBLISHABLE_KEY)},{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}});
const q=(id)=>document.getElementById(id); const show=(id,on=true)=>q(id).classList.toggle('hidden',!on); const status=(id,msg)=>q(id).textContent=msg||'';
async function load(){if(!authorizationId){show('missing');return}const {data:{session}}=await client.auth.getSession();if(!session){show('login');show('consent',false);return}show('login',false);show('consent');q('userEmail').textContent=session.user.email||session.user.id;const {data,error}=await client.auth.oauth.getAuthorizationDetails(authorizationId);if(error){status('consentStatus',error.message);return}if(!('authorization_id' in data)){location.href=data.redirect_url;return}q('clientName').textContent=data.client?.name||data.client_id||'Cliente ORDAX';q('redirectUri').textContent=data.redirect_uri||'';q('scopes').textContent=data.scope||'openid email offline_access'}
q('passwordLogin').onclick=async()=>{status('loginStatus','Entrando\u2026');const {error}=await client.auth.signInWithPassword({email:q('email').value.trim(),password:q('password').value});if(error){status('loginStatus',error.message);return}location.reload()};
q('magicLogin').onclick=async()=>{const email=q('email').value.trim();if(!email){status('loginStatus','Informe seu e-mail.');return}status('loginStatus','Enviando link\u2026');const {error}=await client.auth.signInWithOtp({email,options:{emailRedirectTo:returnUrl}});status('loginStatus',error?error.message:'Link enviado. Abra o e-mail neste navegador para continuar.')};
q('approve').onclick=async()=>{status('consentStatus','Autorizando\u2026');const {data,error}=await client.auth.oauth.approveAuthorization(authorizationId);if(error){status('consentStatus',error.message);return}location.href=data.redirect_url};
q('deny').onclick=async()=>{const {data,error}=await client.auth.oauth.denyAuthorization(authorizationId);if(error){status('consentStatus',error.message);return}location.href=data.redirect_url};
q('signOut').onclick=async()=>{await client.auth.signOut();location.reload()};
await load();
<\/script></body></html>`;
  return new Response(html2, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}' https://cdn.jsdelivr.net; style-src 'nonce-${nonce}'; connect-src ${AUTH_ORIGIN}; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` } });
}
__name(oauthConsentResponse, "oauthConsentResponse");

// src/public_pages.ts
var PRODUCT_NAME = "ORDAX";
var REPOSITORY_URL = "https://github.com/washingtonmsdj/ordax-control-plane";
var SUPPORT_URL = "https://github.com/washingtonmsdj/ordax-control-plane/issues";
function html(title, body) {
  const document = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} \xB7 ${PRODUCT_NAME}</title>
<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#071019;color:#e9f4ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,#071019,#0a1622)}
main{max-width:860px;margin:0 auto;padding:64px 28px 80px}nav{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:48px}
a{color:#9dccff}nav a{text-decoration:none}h1{font-size:42px;letter-spacing:-.03em;margin:0 0 18px}
h2{margin-top:36px;font-size:22px}p,li{color:#b7c8d8;line-height:1.7}code{color:#b9d9ff}
.card{border:1px solid #1d3850;border-radius:18px;background:#0c1b28;padding:22px;margin:22px 0}
.small{font-size:13px;color:#819db3}
</style>
</head>
<body><main>
<nav>
<a href="/">ORDAX</a>
<a href="/support">Support</a>
<a href="/privacy">Privacy</a>
<a href="/terms">Terms</a>
</nav>
${body}
</main></body></html>`;
  return new Response(document, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=300",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY"
    }
  });
}
__name(html, "html");
function publicProductPage(pathname) {
  if (pathname === "/") {
    return html("Home", `
<h1>ORDAX</h1>
<p>ORDAX connects authorized clients to typed capabilities on devices the user controls. Provider-specific connectors such as ORDAX for ChatGPT use the same grant-scoped Control Plane and device Runtime.</p>
<div class="card">
<strong>What it can do</strong>
<ul>
<li>Work with explicitly registered project files and repositories.</li>
<li>Inspect Git status and run granted Git operations.</li>
<li>Use bounded project commands when the user has granted terminal access.</li>
<li>Use typed Computer Control and specialized adapters when explicitly authorized.</li>
</ul>
</div>
<p>ORDAX does not expose the whole computer by default. Remote actions are limited by device, scope and action grants plus local Runtime policy.</p>
<p><a href="${REPOSITORY_URL}">Source repository and technical documentation</a></p>
<p class="small">ORDAX Control Plane \xB7 Cloudflare</p>`);
  }
  if (pathname === "/support") {
    return html("Support", `
<h1>Support</h1>
<p>For ORDAX installation, connection, connector or tool issues, open a support issue in the project repository.</p>
<div class="card">
<p><a href="${SUPPORT_URL}">Open or review support issues</a></p>
<p>Include the affected ORDAX component/version, device or project scope and a concise description of the problem. Do not include passwords, access tokens or private project content.</p>
</div>
<p>Security-sensitive reports should not include exploit details or credentials in a public issue. Use the repository owner's private contact channel when available.</p>`);
  }
  if (pathname === "/privacy") {
    return html("Privacy Policy", `
<h1>Privacy Policy</h1>
<p>Effective: 1 October 2026.</p>
<p>ORDAX is a capability platform that connects an authorized client to devices and scopes the user explicitly connects.</p>
<h2>Data processed</h2>
<ul>
<li><strong>Account and authentication data:</strong> authentication identifiers required to verify the connected ORDAX account. Authentication is currently provided by Supabase Auth; passwords are handled by the identity provider and are not stored by the ORDAX Control Plane.</li>
<li><strong>Device and authorization data:</strong> device identifiers and names, project or Space scopes, grants, allowed actions and connection state needed to route authorized requests.</li>
<li><strong>Requested capability data:</strong> file contents, Git information, Computer Control results, adapter metadata, command results or artifacts only when an authorized tool is invoked for that data.</li>
<li><strong>Operational and audit data:</strong> action names, scope, request/status identifiers, authorization decisions, execution status and timestamps needed for security, reliability and abuse investigation.</li>
</ul>
<h2>How data is used</h2>
<p>Data is used to authenticate connections, enforce grants, route tool calls to the selected device, return requested results, maintain reliability and provide security/audit controls. ORDAX does not request the full conversation history of an external AI client.</p>
<h2>Infrastructure</h2>
<p>The remote Control Plane uses Cloudflare services for compute and storage. Account authentication currently uses Supabase Auth. Local project/device data remains on the user's device unless an authorized tool invocation requires selected data or an artifact to transit the Control Plane to fulfill the request.</p>
<h2>Sharing and sale</h2>
<p>ORDAX does not sell personal data. Data is shared with infrastructure providers only as needed to operate the service or when required by law.</p>
<h2>Retention</h2>
<ul>
<li><strong>OAuth credentials:</strong> ORDAX verifies bearer tokens for requests but does not persist the user's OAuth access token in the Control Plane. Authentication records held by the identity provider follow the account lifecycle and the provider's applicable policy.</li>
<li><strong>Temporary Product artifacts:</strong> signed download links expire after 1 hour. Artifact bytes and their Product metadata are retained for no more than 7 days, then the daily retention process deletes both the Cloudflare R2 object and its D1 record.</li>
<li><strong>Product action and audit history:</strong> completed action records, request metadata and audit entries are retained for no more than 30 days for reliability, security and abuse investigation.</li>
<li><strong>Device pairings:</strong> pairing secrets expire and expired pairing records are deleted by the next daily retention cycle.</li>
<li><strong>Device links and grants:</strong> active links and grants remain while the user keeps them active. Revoked or expired authorization metadata is retained for no more than 30 days after it becomes inactive, once no retained action history depends on it.</li>
</ul>
<p>These retention periods apply to the ORDAX Product/MCP service. Files that remain only on the user's computer are not copied to the Control Plane unless an authorized tool request needs selected content or an artifact to fulfill that request.</p>
<h2>User control</h2>
<p>Users can stop the local Runtime, revoke device/scope grants, disconnect a provider connector and remove installed software. Access is designed to fail closed when authentication or grants are missing. Retained Product metadata can also be addressed through the <a href="/support">support channel</a>.</p>
<h2>Security</h2>
<p>Device credentials are scoped separately from user authentication. Remote actions are checked against explicit device, scope and action grants plus local policy where applicable. Do not place secrets in prompts or project files unless necessary for the task.</p>
<p>Questions about this policy can be raised through the <a href="/support">support page</a>.</p>`);
  }
  if (pathname === "/terms") {
    return html("Terms of Service", `
<h1>Terms of Service</h1>
<p>Effective: 1 October 2026.</p>
<p>By using ORDAX, you agree to use it only on computers, repositories, accounts and data that you are authorized to access.</p>
<h2>User responsibility</h2>
<p>You are responsible for reviewing requested writes, Git, terminal, Computer Control and specialized adapter actions before authorizing them and for maintaining appropriate backups and version control for important work.</p>
<h2>Service behavior</h2>
<p>ORDAX is provided as evolving software. Availability may change during updates, maintenance or third-party service outages. The service may reject actions that lack a valid grant, exceed safety limits or cannot be verified.</p>
<h2>Prohibited use</h2>
<p>You may not use ORDAX to access systems without authorization, bypass security controls, distribute malicious software, or violate applicable law or third-party rights.</p>
<h2>Third-party services</h2>
<p>ORDAX relies on third-party infrastructure including Cloudflare and the configured identity provider. Provider-specific connectors can also be subject to the terms of their respective providers.</p>
<h2>Changes</h2>
<p>Material changes to these terms will be reflected on this page with an updated effective date.</p>
<p>Questions can be raised through the <a href="/support">support page</a>.</p>`);
  }
  return null;
}
__name(publicProductPage, "publicProductPage");
function openAiAppsChallenge(env) {
  const token = (env.OPENAI_APPS_CHALLENGE ?? "").trim();
  if (!token || token.length > 4096 || /[\r\n]/.test(token)) {
    return new Response("not configured", {
      status: 404,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff"
      }
    });
  }
  return new Response(token, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
}
__name(openAiAppsChallenge, "openAiAppsChallenge");

// src/retention.ts
var PRODUCT_ARTIFACT_RETENTION_DAYS = 7;
var PRODUCT_HISTORY_RETENTION_DAYS = 30;
var PRODUCT_INACTIVE_AUTHZ_RETENTION_DAYS = 30;
var PRODUCT_MULTIPART_RETENTION_DAYS = 8;
var DAY_MS = 24 * 60 * 60 * 1e3;
var BATCH_SIZE = 100;
function isoBefore(nowMs, days) {
  return new Date(nowMs - days * DAY_MS).toISOString();
}
__name(isoBefore, "isoBefore");
async function purgeProductArtifacts(env, cutoff) {
  let deleted = 0;
  while (true) {
    const page = await env.DB.prepare(
      `SELECT a.id, a.storage_path
       FROM ordax_artifacts a
       JOIN ordax_jobs j ON j.id = a.job_id
       WHERE j.capability = 'ordax.product.invoke'
         AND a.created_at < ?1
       ORDER BY a.created_at
       LIMIT ?2`
    ).bind(cutoff, BATCH_SIZE).all();
    const rows = page.results ?? [];
    if (!rows.length) break;
    let progress = 0;
    for (const row of rows) {
      try {
        await env.ARTIFACTS.delete(row.storage_path);
      } catch {
        continue;
      }
      const result = await env.DB.prepare(
        "DELETE FROM ordax_artifacts WHERE id = ?1 AND storage_path = ?2"
      ).bind(row.id, row.storage_path).run();
      const changes = Number(result.meta?.changes ?? 0);
      deleted += changes;
      progress += changes;
    }
    if (rows.length < BATCH_SIZE || progress === 0) break;
  }
  return deleted;
}
__name(purgeProductArtifacts, "purgeProductArtifacts");
async function purgeStaleProductMultipartUploads(env, cutoff) {
  const page = await env.DB.prepare(
    `SELECT u.artifact_id, u.storage_path, u.upload_id
     FROM ordax_artifact_uploads u
     JOIN ordax_jobs j ON j.id = u.job_id
     WHERE j.capability = 'ordax.product.invoke'
       AND u.created_at < ?1
     ORDER BY u.created_at
     LIMIT ?2`
  ).bind(cutoff, BATCH_SIZE).all();
  let deleted = 0;
  for (const row of page.results ?? []) {
    try {
      await env.ARTIFACTS.resumeMultipartUpload(row.storage_path, row.upload_id).abort();
    } catch {
    }
    const result = await env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1 AND upload_id = ?2"
    ).bind(row.artifact_id, row.upload_id).run();
    deleted += Number(result.meta?.changes ?? 0);
  }
  return deleted;
}
__name(purgeStaleProductMultipartUploads, "purgeStaleProductMultipartUploads");
async function deleteCount(env, sql, ...bindings) {
  const result = await env.DB.prepare(sql).bind(...bindings).run();
  return Number(result.meta?.changes ?? 0);
}
__name(deleteCount, "deleteCount");
async function runProductRetention(env, nowMs = Date.now()) {
  const artifactCutoff = isoBefore(nowMs, PRODUCT_ARTIFACT_RETENTION_DAYS);
  const multipartCutoff = isoBefore(nowMs, PRODUCT_MULTIPART_RETENTION_DAYS);
  const historyCutoff = isoBefore(nowMs, PRODUCT_HISTORY_RETENTION_DAYS);
  const inactiveAuthzCutoff = isoBefore(
    nowMs,
    PRODUCT_INACTIVE_AUTHZ_RETENTION_DAYS
  );
  const nowIso2 = new Date(nowMs).toISOString();
  const artifacts = await purgeProductArtifacts(env, artifactCutoff);
  const multipartUploads = await purgeStaleProductMultipartUploads(
    env,
    multipartCutoff
  );
  const audits = await deleteCount(
    env,
    "DELETE FROM ordax_product_audit WHERE created_at < ?1",
    historyCutoff
  );
  const jobs = await deleteCount(
    env,
    `DELETE FROM ordax_jobs
     WHERE capability = 'ordax.product.invoke'
       AND status IN ('succeeded','failed','cancelled')
       AND COALESCE(finished_at, created_at) < ?1
       AND NOT EXISTS (
         SELECT 1 FROM ordax_artifacts a WHERE a.job_id = ordax_jobs.id
       )`,
    historyCutoff
  );
  const pairings = await deleteCount(
    env,
    "DELETE FROM ordax_product_device_pairings WHERE expires_at < ?1",
    nowIso2
  );
  const deviceLinks = await deleteCount(
    env,
    `DELETE FROM ordax_product_device_links
     WHERE revoked_at IS NOT NULL AND revoked_at < ?1`,
    inactiveAuthzCutoff
  );
  const grants = await deleteCount(
    env,
    `DELETE FROM ordax_product_grants AS g
     WHERE (
       (g.revoked_at IS NOT NULL AND g.revoked_at < ?1)
       OR (g.expires_at IS NOT NULL AND g.expires_at < ?1)
     )
     AND NOT EXISTS (
       SELECT 1 FROM ordax_product_action_requests r WHERE r.grant_id = g.id
     )`,
    inactiveAuthzCutoff
  );
  return {
    artifacts,
    multipart_uploads: multipartUploads,
    audits,
    jobs,
    pairings,
    device_links: deviceLinks,
    grants
  };
}
__name(runProductRetention, "runProductRetention");

// src/index.ts
var UUID_RE4 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var HEX64_RE = /^[0-9a-f]{64}$/i;
var DIRECT_ARTIFACT_MAX_BYTES = 90 * 1024 * 1024;
var MULTIPART_ARTIFACT_MAX_BYTES = DIRECT_ARTIFACT_MAX_BYTES * 1e4;
var MULTIPART_MAX_PARTS = 1e4;
var CONTROL_PLANE_CAPABILITIES = [
  "artifact_multipart_v1",
  "terminal_report_recovery_v1",
  "product_grant_store_v1",
  "product_grant_resolution_v1",
  "product_subject_auth_jwks_v1",
  "product_readonly_actions_v1",
  "product_typed_actions_v2",
  "product_retention_v1"
];
var ACTION_PREFIXES = [
  "blender.",
  "unity.",
  "git.",
  "project.",
  "projects.",
  "workspace.",
  "artifact.",
  "observation.",
  "game_assets.",
  "geo.",
  "visual.",
  "agent.",
  "terminal.",
  "handoff.",
  "continuity.",
  "browser.",
  "computer.",
  "process.",
  "intelligence."
];
var PRODUCT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
var PROJECT_SLUG_RE2 = /^[a-z0-9][a-z0-9_-]{0,63}$/;
var PRODUCT_READ_ONLY_ACTIONS = /* @__PURE__ */ new Set([
  ...APP_INTELLIGENCE_DEVICE_ACTIONS,
  "projects.list",
  "workspace.repository_catalog",
  "project.inventory",
  "project.text_read",
  "workspace.file_stat",
  "workspace.directory_list",
  "workspace.text_read",
  "project.search_text",
  "project.text_read_batch",
  "project.preview_status",
  "agent.project_health",
  "agent.project_briefing",
  "continuity.get",
  "artifacts.list",
  "git.status",
  "git.diff",
  "artifact.preview",
  "handoff.get",
  "browser.status",
  "browser.list",
  "browser.snapshot",
  "browser.screenshot",
  "computer.windows",
  "computer.active_window",
  "computer.screenshot",
  "computer.screen_info",
  "computer.clipboard_read",
  "computer.access_status",
  "computer.file_stat",
  "computer.directory_list",
  "computer.text_read",
  "computer.search",
  "computer.processes",
  "process.status",
  "process.list",
  "process.logs"
]);
var PRODUCT_TYPED_ACTIONS_V2 = /* @__PURE__ */ new Set([
  "continuity.update",
  "workspace.project_create",
  "workspace.bind_project",
  "handoff.create",
  "workspace.text_write",
  "workspace.text_patch",
  "workspace.directory_create",
  "workspace.path_remove",
  "workspace.path_move",
  "git.command",
  "terminal.exec",
  "process.start",
  "process.write_stdin",
  "process.stop",
  "browser.start",
  "browser.navigate",
  "browser.click",
  "browser.type",
  "browser.stop",
  "computer.focus_window",
  "computer.click",
  "computer.mouse_move",
  "computer.drag",
  "computer.scroll",
  "computer.clipboard_write",
  "computer.launch_app",
  "computer.type",
  "computer.hotkey",
  "computer.text_write",
  "computer.text_patch",
  "computer.directory_create",
  "computer.path_move",
  "computer.path_remove",
  "computer.terminate_process",
  "project.text_write",
  "project.text_patch",
  "blender.live_status",
  "blender.live_scene_snapshot",
  "blender.live_object_inspect",
  "blender.live_modeling_schema",
  "blender.live_start",
  "blender.live_object_transform",
  "blender.live_create_primitive",
  "blender.live_material_apply",
  "blender.live_save"
]);
var PRODUCT_ACTIONS = /* @__PURE__ */ new Set([
  ...PRODUCT_READ_ONLY_ACTIONS,
  ...PRODUCT_TYPED_ACTIONS_V2
]);
var PRODUCT_PROJECT_ACTIONS = /* @__PURE__ */ new Set([
  "project.inventory",
  "project.text_read",
  "project.search_text",
  "project.text_read_batch",
  "project.preview_status",
  "project.text_write",
  "project.text_patch",
  "agent.project_health",
  "agent.project_briefing",
  "continuity.get",
  "continuity.update",
  "artifacts.list",
  "git.status",
  "git.diff",
  "artifact.preview",
  "handoff.create",
  "workspace.text_write",
  "workspace.text_patch",
  "workspace.directory_create",
  "workspace.path_remove",
  "workspace.path_move",
  "git.command",
  "terminal.exec",
  "process.status",
  "process.list",
  "process.logs",
  "process.start",
  "process.write_stdin",
  "process.stop",
  ...PROJECT_BROWSER_ACTIONS,
  "project.text_write",
  "project.text_patch",
  "blender.live_status",
  "blender.live_scene_snapshot",
  "blender.live_object_inspect",
  "blender.live_modeling_schema",
  "blender.live_start",
  "blender.live_object_transform",
  "blender.live_create_primitive",
  "blender.live_material_apply",
  "blender.live_save"
]);
function json4(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
__name(json4, "json");
function nowIso() {
  return (/* @__PURE__ */ new Date()).toISOString();
}
__name(nowIso, "nowIso");
function randomHex(bytes = 32) {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return [...value].map((item) => item.toString(16).padStart(2, "0")).join("");
}
__name(randomHex, "randomHex");
async function sha256Text(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
}
__name(sha256Text, "sha256Text");
function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
__name(bytesToBase64, "bytesToBase64");
function hexToArrayBuffer(value) {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes.buffer;
}
__name(hexToArrayBuffer, "hexToArrayBuffer");
function arrayBufferToHex(value) {
  return [...new Uint8Array(value)].map((item) => item.toString(16).padStart(2, "0")).join("");
}
__name(arrayBufferToHex, "arrayBufferToHex");
function isRecord5(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
__name(isRecord5, "isRecord");
function canonicalJsonValue(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalJsonValue(item));
  if (isRecord5(value)) {
    const normalized = {};
    for (const key of Object.keys(value).sort()) {
      normalized[key] = canonicalJsonValue(value[key]);
    }
    return normalized;
  }
  return value;
}
__name(canonicalJsonValue, "canonicalJsonValue");
function stableJson(value) {
  return JSON.stringify(canonicalJsonValue(value));
}
__name(stableJson, "stableJson");
function canonicalStoredJson(value) {
  if (!value) return null;
  try {
    return stableJson(JSON.parse(value));
  } catch {
    return null;
  }
}
__name(canonicalStoredJson, "canonicalStoredJson");
function actionAllowed(value) {
  return value === "ordax.dev.adapter.invoke" || ACTION_PREFIXES.some((prefix) => value.startsWith(prefix));
}
__name(actionAllowed, "actionAllowed");
async function operatorAuthorized(request, env) {
  const auth = request.headers.get("authorization") ?? "";
  if (!env.ORDAX_OPERATOR_TOKEN || !auth.startsWith("Bearer ")) return false;
  const supplied = auth.slice(7);
  if (supplied.length !== env.ORDAX_OPERATOR_TOKEN.length) return false;
  const [a, b] = await Promise.all([
    sha256Text(supplied),
    sha256Text(env.ORDAX_OPERATOR_TOKEN)
  ]);
  return a === b;
}
__name(operatorAuthorized, "operatorAuthorized");
async function authenticateDevice(env, deviceId, rawToken) {
  if (!UUID_RE4.test(deviceId) || rawToken.length < 32 || rawToken.length > 512) {
    return { ok: false, error: "device_auth_required" };
  }
  const digest = await sha256Text(rawToken);
  const row = await env.DB.prepare(
    "SELECT id, revoked_at FROM ordax_devices WHERE id = ?1 AND token_sha256 = ?2"
  ).bind(deviceId, digest).first();
  if (!row) return { ok: false, error: "invalid_device_token" };
  if (row.revoked_at) return { ok: false, error: "device_revoked" };
  return { ok: true };
}
__name(authenticateDevice, "authenticateDevice");
async function wakeDeviceSession(env, deviceId, targetAgentInstanceId, targetBootId) {
  const id = env.DEVICE_SESSIONS.idFromName(deviceId);
  const headers = new Headers({ "X-Ordax-Device-Id": deviceId });
  if (targetAgentInstanceId && targetBootId) {
    headers.set("X-Ordax-Target-Agent-Instance", targetAgentInstanceId);
    headers.set("X-Ordax-Target-Boot-Id", targetBootId);
  }
  await env.DEVICE_SESSIONS.get(id).fetch("https://device.internal/wake", {
    method: "POST",
    headers
  });
}
__name(wakeDeviceSession, "wakeDeviceSession");
async function parseSmallJson4(request, maxBytes = 128 * 1024) {
  const raw = await request.text();
  if (raw.length === 0 || raw.length > maxBytes) return null;
  try {
    const value = JSON.parse(raw);
    return isRecord5(value) ? value : null;
  } catch {
    return null;
  }
}
__name(parseSmallJson4, "parseSmallJson");
async function deviceSetup(request, env) {
  const body = await parseSmallJson4(request, 16 * 1024);
  if (!body) return json4({ ok: false, error: "request_invalid" }, 400);
  const operation = typeof body.operation === "string" ? body.operation : "";
  const binding = typeof body.machine_binding_sha256 === "string" ? body.machine_binding_sha256.toLowerCase() : "";
  if (!HEX64_RE.test(binding)) {
    return json4({ ok: false, error: "request_invalid" }, 400);
  }
  if (operation === "identify") {
    const rawToken = request.headers.get("X-Ordax-Device-Token") ?? "";
    if (rawToken.length < 32 || rawToken.length > 512) {
      return json4({ ok: false, error: "device_auth_required" }, 401);
    }
    const digest = await sha256Text(rawToken);
    const row = await env.DB.prepare(
      `SELECT id, machine_binding_sha256, revoked_at
       FROM ordax_devices WHERE token_sha256 = ?1`
    ).bind(digest).first();
    if (!row || row.revoked_at) {
      return json4({ ok: false, error: "device_token_invalid" }, 401);
    }
    if (row.machine_binding_sha256 !== binding) {
      return json4({ ok: false, error: "machine_binding_mismatch" }, 403);
    }
    return json4({
      ok: true,
      protocol: "cloudflare-v3",
      device_id: row.id
    });
  }
  if (operation !== "enroll") {
    return json4({ ok: false, error: "operation_not_allowed" }, 400);
  }
  const tokenSha256 = typeof body.token_sha256 === "string" ? body.token_sha256.toLowerCase() : "";
  const deviceName = typeof body.device_name === "string" ? body.device_name.trim() : "";
  if (!HEX64_RE.test(tokenSha256) || deviceName.length < 1 || deviceName.length > 120 || /[\x00-\x1f\x7f]/.test(deviceName)) {
    return json4({ ok: false, error: "request_invalid" }, 400);
  }
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) {
    return json4({ ok: false, error: identity.error }, identity.status);
  }
  const id = env.ENROLLMENT_SESSIONS.idFromName(binding);
  return env.ENROLLMENT_SESSIONS.get(id).fetch("https://enrollment.internal/enroll", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Ordax-Product-Subject": identity.subjectId
    },
    body: JSON.stringify({
      machine_binding_sha256: binding,
      device_name: deviceName,
      token_sha256: tokenSha256
    })
  });
}
__name(deviceSetup, "deviceSetup");
function normalizedStringArray(value, options) {
  const { maxItems, validator, allowed } = options;
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const result = /* @__PURE__ */ new Set();
  for (const item of value) {
    if (typeof item !== "string" || !validator(item) || allowed && !allowed.has(item)) {
      return null;
    }
    result.add(item);
  }
  return [...result].sort();
}
__name(normalizedStringArray, "normalizedStringArray");
function publicProductGrant(row) {
  let actions = [];
  let projects = [];
  try {
    actions = JSON.parse(row.actions_json);
  } catch {
    actions = [];
  }
  try {
    projects = JSON.parse(row.projects_json);
  } catch {
    projects = [];
  }
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    actions: Array.isArray(actions) ? actions : [],
    projects: Array.isArray(projects) ? projects : [],
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at
  };
}
__name(publicProductGrant, "publicProductGrant");
function parseProductGrantInput(body) {
  const actions = normalizedStringArray(body.actions, {
    maxItems: 128,
    validator: /* @__PURE__ */ __name((item) => PRODUCT_ID_RE.test(item), "validator"),
    allowed: PRODUCT_ACTIONS
  });
  const projects = normalizedStringArray(body.projects ?? [], {
    maxItems: 100,
    validator: /* @__PURE__ */ __name((item) => PROJECT_SLUG_RE2.test(item), "validator")
  });
  if (!actions || actions.length === 0 || !projects || actions.some((item) => PRODUCT_PROJECT_ACTIONS.has(item)) && projects.length === 0) {
    return null;
  }
  let expiresAt = null;
  if (body.expires_at != null) {
    if (typeof body.expires_at !== "string") return null;
    const parsed = new Date(body.expires_at);
    if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
      return null;
    }
    expiresAt = parsed.toISOString();
  }
  return { actions, projects, expiresAt };
}
__name(parseProductGrantInput, "parseProductGrantInput");
async function persistProductGrant(env, input) {
  const grantId = crypto.randomUUID();
  const createdAt = nowIso();
  await env.DB.prepare(
    `INSERT INTO ordax_product_grants
      (id, subject_id, space_id, device_id, actions_json, projects_json,
       expires_at, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)`
  ).bind(
    grantId,
    input.subjectId,
    input.spaceId,
    input.deviceId,
    stableJson(input.grant.actions),
    stableJson(input.grant.projects),
    input.grant.expiresAt,
    createdAt
  ).run();
  return {
    id: grantId,
    subject_id: input.subjectId,
    space_id: input.spaceId,
    device_id: input.deviceId,
    actions: input.grant.actions,
    projects: input.grant.projects,
    expires_at: input.grant.expiresAt,
    created_at: createdAt,
    revoked_at: null
  };
}
__name(persistProductGrant, "persistProductGrant");
async function createProductGrant(request, env) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const body = await parseSmallJson4(request, 32 * 1024);
  if (!body) return json4({ ok: false, error: "invalid_json" }, 400);
  const subjectId = typeof body.subject_id === "string" ? body.subject_id : "";
  const spaceId = body.space_id == null ? null : typeof body.space_id === "string" ? body.space_id : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const grantInput = parseProductGrantInput(body);
  if (!PRODUCT_ID_RE.test(subjectId) || spaceId !== null && !PRODUCT_ID_RE.test(spaceId) || !UUID_RE4.test(deviceId) || !grantInput) {
    return json4({ ok: false, error: "product_grant_invalid" }, 400);
  }
  const device = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL"
  ).bind(deviceId).first();
  if (!device) return json4({ ok: false, error: "device_not_found" }, 404);
  const grant = await persistProductGrant(env, {
    subjectId,
    spaceId,
    deviceId,
    grant: grantInput
  });
  return json4({ ok: true, grant }, 201);
}
__name(createProductGrant, "createProductGrant");
async function createProductGrantFromLink(request, env) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const body = await parseSmallJson4(request, 32 * 1024);
  if (!body) return json4({ ok: false, error: "invalid_json" }, 400);
  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const grantInput = parseProductGrantInput(body);
  if (!UUID_RE4.test(linkId) || !grantInput || body.subject_id != null || body.device_id != null || body.space_id != null) {
    return json4({ ok: false, error: "product_grant_invalid" }, 400);
  }
  const link = await env.DB.prepare(
    `SELECT l.subject_id, l.space_id, l.device_id
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.id = ?1
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL`
  ).bind(linkId).first();
  if (!link) {
    return json4({ ok: false, error: "product_device_link_not_found" }, 404);
  }
  const grant = await persistProductGrant(env, {
    subjectId: link.subject_id,
    spaceId: link.space_id || null,
    deviceId: link.device_id,
    grant: grantInput
  });
  return json4({
    ok: true,
    grant,
    provenance: {
      link_id: linkId,
      subject_id: link.subject_id,
      space_id: link.space_id || null,
      device_id: link.device_id
    }
  }, 201);
}
__name(createProductGrantFromLink, "createProductGrantFromLink");
async function listProductGrants(request, env) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const url = new URL(request.url);
  const subjectId = url.searchParams.get("subject_id");
  const deviceId = url.searchParams.get("device_id");
  if (subjectId !== null && !PRODUCT_ID_RE.test(subjectId)) {
    return json4({ ok: false, error: "subject_id_invalid" }, 400);
  }
  if (deviceId !== null && !UUID_RE4.test(deviceId)) {
    return json4({ ok: false, error: "device_id_invalid" }, 400);
  }
  const where = [];
  const values = [];
  if (subjectId !== null) {
    values.push(subjectId);
    where.push(`subject_id = ?${values.length}`);
  }
  if (deviceId !== null) {
    values.push(deviceId);
    where.push(`device_id = ?${values.length}`);
  }
  const condition = where.length ? " WHERE " + where.join(" AND ") : "";
  const query = `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants${condition}
     ORDER BY created_at DESC LIMIT 200`;
  const rows = await env.DB.prepare(query).bind(...values).all();
  return json4({
    ok: true,
    grants: (rows.results ?? []).map((row) => publicProductGrant(row))
  });
}
__name(listProductGrants, "listProductGrants");
async function resolveProductGrantForContext(env, context) {
  if (!projectBindingMatchesScope(
    context.action,
    context.project,
    PRODUCT_PROJECT_ACTIONS
  )) {
    return null;
  }
  const now = nowIso();
  const rows = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants
     WHERE subject_id = ?1
       AND revoked_at IS NULL
       AND (expires_at IS NULL OR expires_at > ?2)
       AND device_id = ?3
       AND (space_id IS NULL OR space_id = ?4)
     ORDER BY
       CASE WHEN space_id IS NULL THEN 0 ELSE 1 END DESC,
       created_at DESC
     LIMIT 100`
  ).bind(
    context.subjectId,
    now,
    context.deviceId,
    context.spaceId
  ).all();
  for (const row of rows.results ?? []) {
    let actions = [];
    let projects = [];
    try {
      actions = JSON.parse(row.actions_json);
    } catch {
      continue;
    }
    try {
      projects = JSON.parse(row.projects_json);
    } catch {
      continue;
    }
    if (!Array.isArray(actions) || !actions.every((item) => typeof item === "string") || !actions.includes(context.action) || !Array.isArray(projects) || !projects.every((item) => typeof item === "string")) {
      continue;
    }
    if (DEVICE_SCOPED_ACTIONS.has(context.action)) {
      if (projects.length !== 0 || context.project !== null) continue;
    } else if (PRODUCT_PROJECT_ACTIONS.has(context.action)) {
      if (context.project === null || !projects.includes(context.project)) continue;
    }
    return row;
  }
  return null;
}
__name(resolveProductGrantForContext, "resolveProductGrantForContext");
async function resolveProductGrantAdmin(request, env) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const body = await parseSmallJson4(request, 16 * 1024);
  if (!body) return json4({ ok: false, error: "invalid_json" }, 400);
  const subjectId = typeof body.subject_id === "string" ? body.subject_id : "";
  const spaceId = body.space_id == null ? null : typeof body.space_id === "string" ? body.space_id : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  if (!PRODUCT_ID_RE.test(subjectId) || spaceId !== null && !PRODUCT_ID_RE.test(spaceId) || !UUID_RE4.test(deviceId) || !PRODUCT_ACTIONS.has(action) || project !== null && !PROJECT_SLUG_RE2.test(project) || !projectBindingMatchesScope(action, project, PRODUCT_PROJECT_ACTIONS)) {
    return json4({ ok: false, error: "product_grant_resolution_invalid" }, 400);
  }
  const device = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL"
  ).bind(deviceId).first();
  if (!device) return json4({ ok: false, error: "device_not_found" }, 404);
  const grant = await resolveProductGrantForContext(env, {
    subjectId,
    spaceId,
    deviceId,
    action,
    project
  });
  if (!grant) {
    return json4({ ok: false, error: "product_grant_not_resolved" }, 404);
  }
  return json4({
    ok: true,
    grant: publicProductGrant(grant),
    resolved_for: {
      subject_id: subjectId,
      space_id: spaceId,
      device_id: deviceId,
      action,
      project
    }
  });
}
__name(resolveProductGrantAdmin, "resolveProductGrantAdmin");
async function revokeProductGrant(request, env, grantId) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  if (!UUID_RE4.test(grantId)) {
    return json4({ ok: false, error: "product_grant_id_invalid" }, 400);
  }
  const existing = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants WHERE id = ?1`
  ).bind(grantId).first();
  if (!existing) return json4({ ok: false, error: "product_grant_not_found" }, 404);
  if (existing.revoked_at) {
    return json4({
      ok: true,
      revoked: false,
      already_revoked: true,
      grant: publicProductGrant(existing)
    });
  }
  const revokedAt = nowIso();
  await env.DB.prepare(
    "UPDATE ordax_product_grants SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL"
  ).bind(revokedAt, grantId).run();
  return json4({
    ok: true,
    revoked: true,
    grant: publicProductGrant({ ...existing, revoked_at: revokedAt })
  });
}
__name(revokeProductGrant, "revokeProductGrant");
async function listProductTargets(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json4({ ok: false, error: identity.error }, identity.status);
  const url = new URL(request.url);
  const spaceId = url.searchParams.get("space_id");
  if (spaceId !== null && !PRODUCT_ID_RE.test(spaceId)) {
    return json4({ ok: false, error: "space_id_invalid" }, 400);
  }
  const now = nowIso();
  const rows = await env.DB.prepare(
    `SELECT
       g.id AS grant_id, g.space_id, g.device_id, g.actions_json, g.projects_json,
       g.expires_at, g.created_at,
       d.name AS device_name, d.last_seen_at,
       (
         SELECT l.id
         FROM ordax_product_device_links l
         WHERE l.subject_id = g.subject_id
           AND l.device_id = g.device_id
           AND l.revoked_at IS NULL
           AND COALESCE(l.space_id, '') = COALESCE(g.space_id, '')
         ORDER BY l.created_at DESC
         LIMIT 1
       ) AS link_id
     FROM ordax_product_grants g
     JOIN ordax_devices d ON d.id = g.device_id
     WHERE g.subject_id = ?1
       AND g.device_id IS NOT NULL
       AND g.revoked_at IS NULL
       AND d.revoked_at IS NULL
       AND (g.expires_at IS NULL OR g.expires_at > ?2)
       AND (?3 IS NULL OR g.space_id IS NULL OR g.space_id = ?3)
     ORDER BY d.name ASC, g.created_at DESC
     LIMIT 200`
  ).bind(identity.subjectId, now, spaceId).all();
  const devices = /* @__PURE__ */ new Map();
  for (const row of rows.results ?? []) {
    let actions = [];
    let projects = [];
    try {
      actions = JSON.parse(row.actions_json);
    } catch {
      continue;
    }
    try {
      projects = JSON.parse(row.projects_json);
    } catch {
      continue;
    }
    if (!Array.isArray(actions) || !actions.every((item) => typeof item === "string") || !Array.isArray(projects) || !projects.every((item) => typeof item === "string")) {
      continue;
    }
    let entry = devices.get(row.device_id);
    if (!entry) {
      entry = {
        device_id: row.device_id,
        name: row.device_name,
        last_seen_at: row.last_seen_at,
        link_id: row.link_id,
        grants: []
      };
      devices.set(row.device_id, entry);
    }
    entry.grants.push({
      grant_id: row.grant_id,
      space_id: row.space_id,
      actions,
      projects,
      expires_at: row.expires_at,
      created_at: row.created_at
    });
  }
  return json4({ ok: true, targets: [...devices.values()] });
}
__name(listProductTargets, "listProductTargets");
async function createProductDevicePairing(request, env) {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) return json4({ ok: false, error: auth.error }, 401);
  const now = /* @__PURE__ */ new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1e3).toISOString();
  const pairingId = crypto.randomUUID();
  const secret = randomHex(32);
  const secretSha256 = await sha256Text(secret);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE ordax_product_device_pairings
       SET expires_at = ?1
       WHERE device_id = ?2 AND claimed_at IS NULL AND expires_at > ?1`
    ).bind(createdAt, deviceId),
    env.DB.prepare(
      `INSERT INTO ordax_product_device_pairings
        (id, device_id, secret_sha256, created_at, expires_at,
         claimed_at, claimed_subject_id, claimed_space_id)
       VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL)`
    ).bind(pairingId, deviceId, secretSha256, createdAt, expiresAt)
  ]);
  return json4({
    ok: true,
    pairing: {
      pairing_id: pairingId,
      pairing_secret: secret,
      expires_at: expiresAt
    }
  }, 201);
}
__name(createProductDevicePairing, "createProductDevicePairing");
async function claimProductDevicePairing(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json4({ ok: false, error: identity.error }, identity.status);
  const body = await parseSmallJson4(request, 16 * 1024);
  if (!body) return json4({ ok: false, error: "product_pairing_invalid" }, 400);
  const pairingId = typeof body.pairing_id === "string" ? body.pairing_id : "";
  const pairingSecret = typeof body.pairing_secret === "string" ? body.pairing_secret.toLowerCase() : "";
  const spaceId = body.space_id == null ? "" : typeof body.space_id === "string" ? body.space_id : "";
  if (!UUID_RE4.test(pairingId) || !HEX64_RE.test(pairingSecret) || spaceId !== "" && !PRODUCT_ID_RE.test(spaceId)) {
    return json4({ ok: false, error: "product_pairing_invalid" }, 400);
  }
  const secretSha256 = await sha256Text(pairingSecret);
  const now = nowIso();
  const row = await env.DB.prepare(
    `SELECT p.device_id, p.secret_sha256, p.expires_at, p.claimed_at,
            p.claimed_subject_id, p.claimed_space_id
     FROM ordax_product_device_pairings p
     JOIN ordax_devices d ON d.id = p.device_id
     WHERE p.id = ?1 AND d.revoked_at IS NULL`
  ).bind(pairingId).first();
  if (!row || row.secret_sha256 !== secretSha256) {
    return json4({ ok: false, error: "product_pairing_not_found" }, 404);
  }
  if (row.expires_at <= now) {
    return json4({ ok: false, error: "product_pairing_expired" }, 410);
  }
  if (row.claimed_at) {
    if (row.claimed_subject_id !== identity.subjectId || (row.claimed_space_id ?? "") !== spaceId) {
      return json4({ ok: false, error: "product_pairing_already_claimed" }, 409);
    }
    const existingLink = await env.DB.prepare(
      `SELECT l.id, l.space_id, l.device_id, l.created_at,
              d.name AS device_name, d.last_seen_at
       FROM ordax_product_device_links l
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE l.subject_id = ?1 AND l.device_id = ?2 AND l.space_id = ?3
         AND l.revoked_at IS NULL AND d.revoked_at IS NULL`
    ).bind(identity.subjectId, row.device_id, spaceId).first();
    if (!existingLink) {
      return json4({ ok: false, error: "product_pairing_already_claimed" }, 409);
    }
    return json4({
      ok: true,
      link: {
        link_id: existingLink.id,
        space_id: existingLink.space_id || null,
        device_id: existingLink.device_id,
        device_name: existingLink.device_name,
        last_seen_at: existingLink.last_seen_at,
        created_at: existingLink.created_at
      },
      replayed: true
    });
  }
  if (!row.claimed_at) {
    const claim = await env.DB.prepare(
      `UPDATE ordax_product_device_pairings
       SET claimed_at = ?1, claimed_subject_id = ?2, claimed_space_id = ?3
       WHERE id = ?4
         AND secret_sha256 = ?5
         AND claimed_at IS NULL
         AND expires_at > ?1`
    ).bind(
      now,
      identity.subjectId,
      spaceId,
      pairingId,
      secretSha256
    ).run();
    if ((claim.meta.changes ?? 0) !== 1) {
      return json4({ ok: false, error: "product_pairing_claim_conflict" }, 409);
    }
  }
  const proposedLinkId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO ordax_product_device_links
      (id, subject_id, space_id, device_id, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, NULL)
     ON CONFLICT(subject_id, device_id, space_id)
     DO UPDATE SET revoked_at = NULL`
  ).bind(
    proposedLinkId,
    identity.subjectId,
    spaceId,
    row.device_id,
    now
  ).run();
  const link = await env.DB.prepare(
    `SELECT l.id, l.space_id, l.device_id, l.created_at,
            d.name AS device_name, d.last_seen_at
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.subject_id = ?1 AND l.device_id = ?2 AND l.space_id = ?3
       AND l.revoked_at IS NULL`
  ).bind(identity.subjectId, row.device_id, spaceId).first();
  if (!link) return json4({ ok: false, error: "product_device_link_failed" }, 500);
  return json4({
    ok: true,
    link: {
      link_id: link.id,
      space_id: link.space_id || null,
      device_id: link.device_id,
      device_name: link.device_name,
      last_seen_at: link.last_seen_at,
      created_at: link.created_at
    }
  }, 201);
}
__name(claimProductDevicePairing, "claimProductDevicePairing");
async function listProductDeviceLinks(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json4({ ok: false, error: identity.error }, identity.status);
  const url = new URL(request.url);
  const spaceId = url.searchParams.get("space_id");
  if (spaceId !== null && !PRODUCT_ID_RE.test(spaceId)) {
    return json4({ ok: false, error: "space_id_invalid" }, 400);
  }
  const rows = await env.DB.prepare(
    `SELECT l.id, l.space_id, l.device_id, l.created_at,
            d.name AS device_name, d.last_seen_at
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.subject_id = ?1
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL
       AND (?2 IS NULL OR l.space_id = ?2)
     ORDER BY d.name ASC, l.created_at DESC
     LIMIT 200`
  ).bind(identity.subjectId, spaceId).all();
  return json4({
    ok: true,
    links: (rows.results ?? []).map((row) => ({
      link_id: row.id,
      space_id: row.space_id || null,
      device_id: row.device_id,
      device_name: row.device_name,
      last_seen_at: row.last_seen_at,
      created_at: row.created_at
    }))
  });
}
__name(listProductDeviceLinks, "listProductDeviceLinks");
async function revokeProductDeviceLink(request, env, linkId) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json4({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE4.test(linkId)) {
    return json4({ ok: false, error: "product_device_link_id_invalid" }, 400);
  }
  const revokedAt = nowIso();
  const update = await env.DB.prepare(
    `UPDATE ordax_product_device_links
     SET revoked_at = ?1
     WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL`
  ).bind(revokedAt, linkId, identity.subjectId).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json4({ ok: false, error: "product_device_link_not_found" }, 404);
  }
  return json4({ ok: true, link_id: linkId, revoked_at: revokedAt });
}
__name(revokeProductDeviceLink, "revokeProductDeviceLink");
async function productSession(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) {
    return json4({ ok: false, error: identity.error }, identity.status);
  }
  return json4({
    ok: true,
    session: {
      subject_id: identity.subjectId,
      issuer: identity.issuer,
      audience: identity.audience,
      expires_at_unix: identity.expiresAt
    }
  });
}
__name(productSession, "productSession");
async function createProductAction(request, env) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json4({ ok: false, error: identity.error }, identity.status);
  const body = await parseSmallJson4(request, 64 * 1024);
  if (!body) return json4({ ok: false, error: "invalid_json" }, 400);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const spaceId = body.space_id == null ? null : typeof body.space_id === "string" ? body.space_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  const argumentsValue = isRecord5(body.arguments) ? { ...body.arguments } : {};
  if (!UUID_RE4.test(deviceId) || spaceId !== null && !PRODUCT_ID_RE.test(spaceId) || !PRODUCT_ACTIONS.has(action) || project !== null && !PROJECT_SLUG_RE2.test(project) || !projectBindingMatchesScope(action, project, PRODUCT_PROJECT_ACTIONS)) {
    return json4({ ok: false, error: "product_action_invalid" }, 400);
  }
  if (project !== null) {
    if (argumentsValue.project != null && argumentsValue.project !== project) return json4({ ok: false, error: "product_project_conflict" }, 400);
    argumentsValue.project = project;
  } else if ("project" in argumentsValue) {
    return json4({ ok: false, error: "product_action_invalid" }, 400);
  }
  const device = await env.DB.prepare("SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL").bind(deviceId).first();
  if (!device) return json4({ ok: false, error: "device_not_found" }, 404);
  const grant = await resolveProductGrantForContext(env, { subjectId: identity.subjectId, spaceId, deviceId, action, project });
  if (!grant) return json4({ ok: false, error: "product_grant_not_resolved" }, 403);
  let actions = [];
  let projects = [];
  try {
    const rawActions = JSON.parse(grant.actions_json);
    const rawProjects = JSON.parse(grant.projects_json);
    if (!Array.isArray(rawActions) || !rawActions.every((item) => typeof item === "string") || !Array.isArray(rawProjects) || !rawProjects.every((item) => typeof item === "string")) throw new Error("invalid grant");
    actions = rawActions;
    projects = rawProjects;
  } catch {
    return json4({ ok: false, error: "product_grant_corrupt" }, 500);
  }
  const requestId = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const effectId = crypto.randomUUID();
  const createdAt = nowIso();
  const expiresAtUnix = grant.expires_at == null ? null : Math.floor(new Date(grant.expires_at).getTime() / 1e3);
  const invocation = {
    action,
    arguments: argumentsValue,
    context: { request_id: requestId, subject_id: identity.subjectId, device_id: deviceId, space_id: spaceId },
    grant: { grant_id: grant.id, subject_id: grant.subject_id, actions, projects, space_id: grant.space_id, device_id: grant.device_id, expires_at_unix: Number.isFinite(expiresAtUnix) ? expiresAtUnix : null }
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(invocation));
  if (payloadBytes.byteLength > 64 * 1024) return json4({ ok: false, error: "product_payload_too_large" }, 413);
  const payloadText = new TextDecoder().decode(payloadBytes);
  const payloadB64 = bytesToBase64(payloadBytes);
  const payloadSha256 = await sha256Text(payloadText);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO ordax_jobs (id, device_id, capability, payload_canonical_b64, payload_sha256, status, effect_id, execution_epoch, created_at) VALUES (?1, ?2, 'ordax.product.invoke', ?3, ?4, 'queued', ?5, 0, ?6)`).bind(jobId, deviceId, payloadB64, payloadSha256, effectId, createdAt),
    env.DB.prepare(`INSERT INTO ordax_product_action_requests (request_id, job_id, subject_id, space_id, device_id, grant_id, action, project, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`).bind(requestId, jobId, identity.subjectId, spaceId, deviceId, grant.id, action, project, createdAt)
  ]);
  await wakeDeviceSession(env, deviceId);
  return json4({ ok: true, request_id: requestId, status: "queued" }, 202);
}
__name(createProductAction, "createProductAction");
async function getProductAction(request, env, requestId) {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json4({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE4.test(requestId)) return json4({ ok: false, error: "product_request_id_invalid" }, 400);
  const row = await env.DB.prepare(`SELECT r.request_id, r.action, r.project, r.created_at, j.status, j.result_json, j.error_code, j.started_at, j.finished_at, g.projects_json FROM ordax_product_action_requests r JOIN ordax_jobs j ON j.id = r.job_id LEFT JOIN ordax_product_grants g ON g.id = r.grant_id WHERE r.request_id = ?1 AND r.subject_id = ?2`).bind(requestId, identity.subjectId).first();
  if (!row) return json4({ ok: false, error: "product_action_not_found" }, 404);
  let result = null;
  if (typeof row.result_json === "string" && row.result_json) {
    try {
      result = JSON.parse(row.result_json);
    } catch {
      result = null;
    }
  }
  result = scopeProductResult(row.action, result, row.projects_json);
  return json4({ ok: true, action: { request_id: row.request_id, action: row.action, project: row.project, status: row.status, result, error_code: row.error_code, created_at: row.created_at, started_at: row.started_at, finished_at: row.finished_at } });
}
__name(getProductAction, "getProductAction");
async function recordProductAudit(request, env) {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) return json4({ ok: false, error: auth.error }, 401);
  const body = await parseSmallJson4(request, 32 * 1024);
  if (!body) return json4({ ok: false, error: "product_audit_invalid" }, 400);
  const requestId = typeof body.request_id === "string" ? body.request_id : "";
  const subjectId = typeof body.subject_id === "string" ? body.subject_id : "";
  const grantId = body.grant_id == null ? null : typeof body.grant_id === "string" ? body.grant_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  const phase = typeof body.phase === "string" ? body.phase : "";
  const decision = typeof body.decision === "string" ? body.decision : "";
  const reason = typeof body.reason === "string" ? body.reason : "";
  const fields = normalizedStringArray(body.payload_fields ?? [], { maxItems: 32, validator: /* @__PURE__ */ __name((item) => PRODUCT_ID_RE.test(item), "validator") });
  const resultOk = body.result_ok == null ? null : typeof body.result_ok === "boolean" ? body.result_ok : void 0;
  if (!UUID_RE4.test(requestId) || !PRODUCT_ID_RE.test(subjectId) || grantId !== null && !UUID_RE4.test(grantId) || !PRODUCT_ACTIONS.has(action) || project !== null && !PROJECT_SLUG_RE2.test(project) || !["decision", "result"].includes(phase) || !["allow", "deny"].includes(decision) || !reason || reason.length > 200 || !fields || resultOk === void 0) return json4({ ok: false, error: "product_audit_invalid" }, 400);
  const owner = await env.DB.prepare(`SELECT subject_id, space_id, device_id, grant_id, action, project FROM ordax_product_action_requests WHERE request_id = ?1`).bind(requestId).first();
  if (!owner || owner.device_id !== deviceId || owner.subject_id !== subjectId || owner.grant_id !== grantId || owner.action !== action || owner.project !== project) return json4({ ok: false, error: "product_audit_context_mismatch" }, 403);
  await env.DB.prepare(`INSERT INTO ordax_product_audit (request_id, subject_id, grant_id, device_id, space_id, action, project, phase, decision, reason, payload_fields_json, result_ok, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`).bind(requestId, subjectId, grantId, deviceId, owner.space_id, action, project, phase, decision, reason, stableJson(fields), resultOk === null ? null : resultOk ? 1 : 0, nowIso()).run();
  return json4({ ok: true });
}
__name(recordProductAudit, "recordProductAudit");
async function provisionDevice(request, env) {
  if (!await operatorAuthorized(request, env)) return json4({ ok: false, error: "operator_unauthorized" }, 401);
  const body = await parseSmallJson4(request, 16 * 1024);
  if (!body) return json4({ ok: false, error: "invalid_json" }, 400);
  const deviceId = typeof body.device_id === "string" && UUID_RE4.test(body.device_id) ? body.device_id : crypto.randomUUID();
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 120) : "OrdaX Device";
  if (!name) return json4({ ok: false, error: "device_name_required" }, 400);
  const token = randomHex(32);
  const tokenSha256 = await sha256Text(token);
  const createdAt = nowIso();
  await env.DB.prepare(
    `INSERT INTO ordax_devices (id, name, token_sha256, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, NULL)
     ON CONFLICT(id) DO UPDATE SET
       name = excluded.name,
       token_sha256 = excluded.token_sha256,
       revoked_at = NULL`
  ).bind(deviceId, name, tokenSha256, createdAt).run();
  return json4({
    ok: true,
    device_id: deviceId,
    device_token: token,
    protocol: "cloudflare-v3"
  }, 201);
}
__name(provisionDevice, "provisionDevice");
async function deleteDevice(request, env, deviceId) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  if (!UUID_RE4.test(deviceId)) {
    return json4({ ok: false, error: "device_id_invalid" }, 400);
  }
  const existing = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1"
  ).bind(deviceId).first();
  if (!existing) return json4({ ok: false, error: "device_not_found" }, 404);
  const artifactRows = await env.DB.prepare(
    "SELECT storage_path FROM ordax_artifacts WHERE device_id = ?1"
  ).bind(deviceId).all();
  for (const row of artifactRows.results ?? []) {
    if (row.storage_path) await env.ARTIFACTS.delete(row.storage_path);
  }
  const uploadRows = await env.DB.prepare(
    "SELECT storage_path, upload_id FROM ordax_artifact_uploads WHERE device_id = ?1"
  ).bind(deviceId).all();
  for (const row of uploadRows.results ?? []) {
    try {
      await env.ARTIFACTS.resumeMultipartUpload(row.storage_path, row.upload_id).abort();
    } catch {
    }
  }
  const statements = [
    env.DB.prepare(
      "DELETE FROM ordax_job_events WHERE job_id IN (SELECT id FROM ordax_jobs WHERE device_id = ?1)"
    ).bind(deviceId),
    env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE device_id = ?1"
    ).bind(deviceId),
    env.DB.prepare(
      "DELETE FROM ordax_artifacts WHERE device_id = ?1"
    ).bind(deviceId),
    env.DB.prepare(
      "DELETE FROM ordax_jobs WHERE device_id = ?1"
    ).bind(deviceId),
    env.DB.prepare(
      "DELETE FROM ordax_devices WHERE id = ?1"
    ).bind(deviceId)
  ];
  const results = await env.DB.batch(statements);
  const deleteResult = results[results.length - 1];
  const remaining = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1"
  ).bind(deviceId).first();
  return json4({
    ok: true,
    device_id: deviceId,
    deleted: !remaining,
    device_delete_changes: deleteResult?.meta.changes ?? 0,
    artifacts_deleted: artifactRows.results?.length ?? 0,
    multipart_uploads_aborted: uploadRows.results?.length ?? 0
  });
}
__name(deleteDevice, "deleteDevice");
async function enqueueJob(request, env) {
  if (!await operatorAuthorized(request, env)) return json4({ ok: false, error: "operator_unauthorized" }, 401);
  const body = await parseSmallJson4(request);
  if (!body) return json4({ ok: false, error: "invalid_json" }, 400);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  if (!UUID_RE4.test(deviceId) || !actionAllowed(action) || project === "") {
    return json4({ ok: false, error: "job_invalid" }, 400);
  }
  const device = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL"
  ).bind(deviceId).first();
  if (!device) return json4({ ok: false, error: "device_not_found" }, 404);
  const payload = isRecord5(body.payload) ? { ...body.payload } : {};
  if (project) {
    if (payload.project != null && payload.project !== project) {
      return json4({ ok: false, error: "project_conflict" }, 400);
    }
    payload.project = project;
  }
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  if (payloadBytes.byteLength > 64 * 1024) {
    return json4({ ok: false, error: "payload_too_large" }, 413);
  }
  const payloadB64 = bytesToBase64(payloadBytes);
  const payloadSha256 = await sha256Text(new TextDecoder().decode(payloadBytes));
  const jobId = crypto.randomUUID();
  const effectId = crypto.randomUUID();
  const createdAt = nowIso();
  await env.DB.prepare(
    `INSERT INTO ordax_jobs
      (id, device_id, capability, payload_canonical_b64, payload_sha256, status,
       effect_id, execution_epoch, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, 0, ?7)`
  ).bind(jobId, deviceId, action, payloadB64, payloadSha256, effectId, createdAt).run();
  await wakeDeviceSession(env, deviceId);
  return json4({ ok: true, job_id: jobId, effect_id: effectId, status: "queued" }, 201);
}
__name(enqueueJob, "enqueueJob");
async function getJob(request, env, jobId) {
  if (!await operatorAuthorized(request, env)) {
    return json4({ ok: false, error: "operator_unauthorized" }, 401);
  }
  if (!UUID_RE4.test(jobId)) return json4({ ok: false, error: "job_id_invalid" }, 400);
  const row = await env.DB.prepare(
    `SELECT id, device_id, capability, status, effect_id, attempt_id, lease_id,
            execution_epoch, agent_instance_id, boot_id, lease_expires_at,
            report_id, result_json, result_sha256, error_code,
            created_at, started_at, finished_at
     FROM ordax_jobs WHERE id = ?1`
  ).bind(jobId).first();
  if (!row) return json4({ ok: false, error: "job_not_found" }, 404);
  const events = await env.DB.prepare(
    `SELECT stage, message, progress_percent, created_at
     FROM ordax_job_events WHERE job_id = ?1 ORDER BY id ASC LIMIT 200`
  ).bind(jobId).all();
  const artifacts = await env.DB.prepare(
    `SELECT id, file_name, kind, content_type, sha256, size_bytes, created_at
     FROM ordax_artifacts WHERE job_id = ?1 ORDER BY created_at ASC`
  ).bind(jobId).all();
  let result = null;
  if (typeof row.result_json === "string" && row.result_json) {
    try {
      result = JSON.parse(row.result_json);
    } catch {
      result = null;
    }
  }
  const { result_json: _ignored, ...publicRow } = row;
  return json4({
    ok: true,
    job: { ...publicRow, result },
    events: events.results ?? [],
    artifacts: artifacts.results ?? []
  });
}
__name(getJob, "getJob");
async function recoverTerminalReport(request, env) {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) return json4({ ok: false, error: auth.error }, 401);
  const body = await parseSmallJson4(request, 640 * 1024);
  if (!body) return json4({ ok: false, error: "report_invalid" }, 400);
  const recoveryAgentInstanceId = request.headers.get(
    "X-Ordax-Recovery-Agent-Instance"
  ) ?? "";
  const recoveryBootId = request.headers.get("X-Ordax-Recovery-Boot-Id") ?? "";
  if (!UUID_RE4.test(recoveryAgentInstanceId) || !UUID_RE4.test(recoveryBootId)) {
    return json4({ ok: false, error: "recovery_runtime_identity_required" }, 400);
  }
  const jobId = typeof body.job_id === "string" ? body.job_id : "";
  const effectId = typeof body.effect_id === "string" ? body.effect_id : "";
  const attemptId = typeof body.attempt_id === "string" ? body.attempt_id : "";
  const leaseId = typeof body.lease_id === "string" ? body.lease_id : "";
  const agentInstanceId = typeof body.agent_instance_id === "string" ? body.agent_instance_id : "";
  const bootId = typeof body.boot_id === "string" ? body.boot_id : "";
  const reportId = typeof body.report_id === "string" ? body.report_id : "";
  const executionEpoch = Number.isSafeInteger(body.execution_epoch) ? Number(body.execution_epoch) : 0;
  const status = typeof body.status === "string" ? body.status : "";
  const resultSha256 = typeof body.result_sha256 === "string" ? body.result_sha256.toLowerCase() : "";
  const errorCode = typeof body.error_code === "string" ? body.error_code : null;
  const resultValue = isRecord5(body.result) ? body.result : {};
  const resultJson = stableJson(resultValue);
  if (!UUID_RE4.test(jobId) || !UUID_RE4.test(effectId) || !UUID_RE4.test(attemptId) || !UUID_RE4.test(leaseId) || !UUID_RE4.test(agentInstanceId) || !UUID_RE4.test(bootId) || !UUID_RE4.test(reportId) || executionEpoch < 1 || !["succeeded", "failed", "cancelled"].includes(status) || !HEX64_RE.test(resultSha256) || new TextEncoder().encode(resultJson).byteLength > 512 * 1024) {
    return json4({ ok: false, error: "report_invalid" }, 400);
  }
  const row = await env.DB.prepare(
    `SELECT status, effect_id, attempt_id, lease_id, execution_epoch,
            agent_instance_id, boot_id, report_id, result_json,
            result_sha256, error_code
     FROM ordax_jobs WHERE id = ?1 AND device_id = ?2`
  ).bind(jobId, deviceId).first();
  if (!row) return json4({ ok: false, error: "job_not_found" }, 404);
  const contextMatches = row.effect_id === effectId && row.attempt_id === attemptId && row.lease_id === leaseId && Number(row.execution_epoch) === executionEpoch && row.agent_instance_id === agentInstanceId && row.boot_id === bootId;
  if (["succeeded", "failed", "cancelled"].includes(row.status)) {
    const replayMatches = contextMatches && row.report_id === reportId && row.status === status && canonicalStoredJson(row.result_json) === resultJson && (row.result_sha256 ?? "").toLowerCase() === resultSha256 && row.error_code === errorCode;
    if (!replayMatches) {
      return json4({ ok: false, error: "terminal_report_conflict" }, 409);
    }
    await wakeDeviceSession(
      env,
      deviceId,
      recoveryAgentInstanceId,
      recoveryBootId
    );
    return json4({ ok: true, status, replayed: true });
  }
  if (!contextMatches) {
    return json4({ ok: false, error: "execution_context_superseded" }, 409);
  }
  if (!["leased", "running"].includes(row.status)) {
    return json4({ ok: false, error: "job_not_recoverable" }, 409);
  }
  const finishedAt = nowIso();
  const update = await env.DB.prepare(
    `UPDATE ordax_jobs SET
       status = ?1, report_id = ?2, result_json = ?3, result_sha256 = ?4,
       error_code = ?5, finished_at = ?6, lease_expires_at = NULL
     WHERE id = ?7 AND device_id = ?8
       AND effect_id = ?9 AND attempt_id = ?10 AND lease_id = ?11
       AND execution_epoch = ?12 AND agent_instance_id = ?13 AND boot_id = ?14
       AND status IN ('leased','running') AND report_id IS NULL`
  ).bind(
    status,
    reportId,
    resultJson,
    resultSha256,
    errorCode,
    finishedAt,
    jobId,
    deviceId,
    effectId,
    attemptId,
    leaseId,
    executionEpoch,
    agentInstanceId,
    bootId
  ).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json4({ ok: false, error: "terminal_recovery_race" }, 409);
  }
  await wakeDeviceSession(
    env,
    deviceId,
    recoveryAgentInstanceId,
    recoveryBootId
  );
  return json4({ ok: true, status, recovered: true, replayed: false });
}
__name(recoverTerminalReport, "recoverTerminalReport");
function parseArtifactDescriptor(request, deviceId, jobId, artifactId, maxBytes) {
  const fileName = (request.headers.get("X-Ordax-Artifact-Name") ?? "artifact.bin").replace(/[^a-zA-Z0-9._-]+/g, "-").slice(0, 180) || "artifact.bin";
  const kind = (request.headers.get("X-Ordax-Artifact-Kind") ?? "artifact").slice(0, 80);
  const sha256 = (request.headers.get("X-Ordax-Artifact-Sha256") ?? "").toLowerCase();
  const sizeBytes = Number(
    request.headers.get("X-Ordax-Artifact-Size") ?? request.headers.get("content-length") ?? "0"
  );
  const metadataRaw = request.headers.get("X-Ordax-Artifact-Metadata") ?? "{}";
  const contentType = (request.headers.get("content-type") ?? "application/octet-stream").slice(0, 255);
  if (!HEX64_RE.test(sha256) || !Number.isSafeInteger(sizeBytes) || sizeBytes < 0 || sizeBytes > maxBytes || metadataRaw.length > 4e3) {
    return null;
  }
  try {
    const parsed = JSON.parse(metadataRaw);
    if (!isRecord5(parsed)) return null;
  } catch {
    return null;
  }
  return {
    artifactId,
    jobId,
    deviceId,
    storagePath: deviceId + "/" + jobId + "/" + artifactId + "-" + fileName,
    fileName,
    kind,
    contentType,
    sha256,
    sizeBytes,
    metadataRaw
  };
}
__name(parseArtifactDescriptor, "parseArtifactDescriptor");
async function existingArtifactGrant(request, env, artifactId, jobId, deviceId, expected) {
  const row = await env.DB.prepare(
    `SELECT job_id, device_id, storage_path, file_name, kind, content_type,
            sha256, size_bytes, metadata_json
     FROM ordax_artifacts WHERE id = ?1`
  ).bind(artifactId).first();
  if (!row) return null;
  const matches = row.job_id === jobId && row.device_id === deviceId && (!expected || row.storage_path === expected.storagePath && row.file_name === expected.fileName && row.kind === expected.kind && row.content_type === expected.contentType && row.sha256.toLowerCase() === expected.sha256 && Number(row.size_bytes) === expected.sizeBytes && row.metadata_json === expected.metadataRaw);
  if (!matches) {
    return json4({ ok: false, error: "artifact_replay_conflict" }, 409);
  }
  const readToken = randomHex(32);
  const readTokenSha256 = await sha256Text(readToken);
  const readExpiresAt = new Date(Date.now() + 60 * 60 * 1e3).toISOString();
  await env.DB.prepare(
    `UPDATE ordax_artifacts
     SET read_token_sha256 = ?1, read_expires_at = ?2
     WHERE id = ?3 AND job_id = ?4 AND device_id = ?5`
  ).bind(
    readTokenSha256,
    readExpiresAt,
    artifactId,
    jobId,
    deviceId
  ).run();
  const origin = new URL(request.url).origin;
  return json4({
    ok: true,
    complete: true,
    replayed: true,
    artifact_id: artifactId,
    storage_path: row.storage_path,
    signed_url: origin + "/v3/artifacts/" + artifactId + "?token=" + encodeURIComponent(readToken),
    expires_at: readExpiresAt
  });
}
__name(existingArtifactGrant, "existingArtifactGrant");
async function artifactJobAuthorized(request, env, parts) {
  const jobId = parts[2] ?? "";
  const artifactId = parts[3] ?? "";
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  if (!UUID_RE4.test(jobId) || !UUID_RE4.test(artifactId)) {
    return { ok: false, response: json4({ ok: false, error: "artifact_path_invalid" }, 400) };
  }
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) {
    return { ok: false, response: json4({ ok: false, error: auth.error }, 401) };
  }
  const job = await env.DB.prepare(
    "SELECT id FROM ordax_jobs WHERE id = ?1 AND device_id = ?2"
  ).bind(jobId, deviceId).first();
  if (!job) {
    return { ok: false, response: json4({ ok: false, error: "job_not_found" }, 404) };
  }
  return { ok: true, deviceId, jobId, artifactId };
}
__name(artifactJobAuthorized, "artifactJobAuthorized");
async function uploadArtifact(request, env, parts) {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const descriptor = parseArtifactDescriptor(
    request,
    access.deviceId,
    access.jobId,
    access.artifactId,
    DIRECT_ARTIFACT_MAX_BYTES
  );
  if (!descriptor) {
    return json4({ ok: false, error: "artifact_metadata_invalid" }, 400);
  }
  const replay = await existingArtifactGrant(
    request,
    env,
    access.artifactId,
    access.jobId,
    access.deviceId,
    descriptor
  );
  if (replay) return replay;
  let stored;
  try {
    stored = await env.ARTIFACTS.put(descriptor.storagePath, request.body, {
      sha256: hexToArrayBuffer(descriptor.sha256),
      httpMetadata: { contentType: descriptor.contentType }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/\((10014|10037)\)\s*$/.test(message)) {
      return json4({ ok: false, error: "artifact_checksum_rejected" }, 422);
    }
    throw error;
  }
  if (!stored) {
    return json4({ ok: false, error: "artifact_storage_write_failed" }, 503);
  }
  const storedSha256 = stored.checksums.sha256;
  if (stored.size !== descriptor.sizeBytes || !storedSha256 || arrayBufferToHex(storedSha256).toLowerCase() !== descriptor.sha256) {
    await env.ARTIFACTS.delete(descriptor.storagePath);
    return json4({ ok: false, error: "artifact_integrity_mismatch" }, 422);
  }
  const readToken = randomHex(32);
  const readTokenSha256 = await sha256Text(readToken);
  const createdAt = nowIso();
  const readExpiresAt = new Date(Date.now() + 60 * 60 * 1e3).toISOString();
  await env.DB.prepare(
    `INSERT INTO ordax_artifacts
      (id, job_id, device_id, storage_path, file_name, kind, content_type, sha256,
       size_bytes, metadata_json, read_token_sha256, read_expires_at, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`
  ).bind(
    descriptor.artifactId,
    descriptor.jobId,
    descriptor.deviceId,
    descriptor.storagePath,
    descriptor.fileName,
    descriptor.kind,
    descriptor.contentType,
    descriptor.sha256,
    descriptor.sizeBytes,
    descriptor.metadataRaw,
    readTokenSha256,
    readExpiresAt,
    createdAt
  ).run();
  const origin = new URL(request.url).origin;
  return json4({
    ok: true,
    artifact_id: descriptor.artifactId,
    storage_path: descriptor.storagePath,
    signed_url: origin + "/v3/artifacts/" + descriptor.artifactId + "?token=" + encodeURIComponent(readToken),
    expires_at: readExpiresAt
  }, 201);
}
__name(uploadArtifact, "uploadArtifact");
async function loadMultipartUpload(env, artifactId, jobId, deviceId) {
  return env.DB.prepare(
    `SELECT artifact_id, job_id, device_id, upload_id, storage_path, file_name,
            kind, content_type, sha256, size_bytes, metadata_json, created_at
     FROM ordax_artifact_uploads
     WHERE artifact_id = ?1 AND job_id = ?2 AND device_id = ?3`
  ).bind(artifactId, jobId, deviceId).first();
}
__name(loadMultipartUpload, "loadMultipartUpload");
async function createMultipartArtifact(request, env, parts) {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const descriptor = parseArtifactDescriptor(
    request,
    access.deviceId,
    access.jobId,
    access.artifactId,
    MULTIPART_ARTIFACT_MAX_BYTES
  );
  if (!descriptor || descriptor.sizeBytes < 1) {
    return json4({ ok: false, error: "artifact_metadata_invalid" }, 400);
  }
  const replay = await existingArtifactGrant(
    request,
    env,
    access.artifactId,
    access.jobId,
    access.deviceId,
    descriptor
  );
  if (replay) return replay;
  const staleBefore = new Date(Date.now() - 8 * 24 * 60 * 60 * 1e3).toISOString();
  await env.DB.prepare(
    "DELETE FROM ordax_artifact_uploads WHERE device_id = ?1 AND created_at < ?2"
  ).bind(access.deviceId, staleBefore).run();
  const existing = await loadMultipartUpload(
    env,
    access.artifactId,
    access.jobId,
    access.deviceId
  );
  if (existing) {
    const matches = existing.storage_path === descriptor.storagePath && existing.file_name === descriptor.fileName && existing.kind === descriptor.kind && existing.content_type === descriptor.contentType && existing.sha256.toLowerCase() === descriptor.sha256 && Number(existing.size_bytes) === descriptor.sizeBytes && existing.metadata_json === descriptor.metadataRaw;
    if (!matches) {
      return json4({ ok: false, error: "multipart_upload_conflict" }, 409);
    }
    return json4({
      ok: true,
      upload_id: existing.upload_id,
      storage_path: existing.storage_path,
      resumed: true
    });
  }
  const multipart = await env.ARTIFACTS.createMultipartUpload(
    descriptor.storagePath,
    { httpMetadata: { contentType: descriptor.contentType } }
  );
  try {
    await env.DB.prepare(
      `INSERT INTO ordax_artifact_uploads
        (artifact_id, job_id, device_id, upload_id, storage_path, file_name, kind,
         content_type, sha256, size_bytes, metadata_json, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`
    ).bind(
      descriptor.artifactId,
      descriptor.jobId,
      descriptor.deviceId,
      multipart.uploadId,
      descriptor.storagePath,
      descriptor.fileName,
      descriptor.kind,
      descriptor.contentType,
      descriptor.sha256,
      descriptor.sizeBytes,
      descriptor.metadataRaw,
      nowIso()
    ).run();
  } catch (error) {
    try {
      await multipart.abort();
    } catch {
    }
    throw error;
  }
  return json4({
    ok: true,
    upload_id: multipart.uploadId,
    storage_path: descriptor.storagePath,
    resumed: false
  }, 201);
}
__name(createMultipartArtifact, "createMultipartArtifact");
async function uploadMultipartPart(request, env, parts) {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const url = new URL(request.url);
  const uploadId = url.searchParams.get("uploadId") ?? "";
  const partNumber = Number(url.searchParams.get("partNumber") ?? "0");
  const partSha256 = (request.headers.get("X-Ordax-Part-Sha256") ?? "").toLowerCase();
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!uploadId || uploadId.length > 512 || !Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > MULTIPART_MAX_PARTS || !HEX64_RE.test(partSha256) || !Number.isSafeInteger(contentLength) || contentLength < 1 || contentLength > DIRECT_ARTIFACT_MAX_BYTES || !request.body) {
    return json4({ ok: false, error: "multipart_part_invalid" }, 400);
  }
  const session = await loadMultipartUpload(
    env,
    access.artifactId,
    access.jobId,
    access.deviceId
  );
  if (!session) return json4({ ok: false, error: "multipart_upload_not_found" }, 404);
  if (session.upload_id !== uploadId) {
    return json4({ ok: false, error: "multipart_upload_conflict" }, 409);
  }
  const [r2Body, digestBody] = request.body.tee();
  const digestStream = new crypto.DigestStream("SHA-256");
  const digestPromise = (async () => {
    await digestBody.pipeTo(digestStream);
    return arrayBufferToHex(await digestStream.digest).toLowerCase();
  })();
  const uploadPromise = env.ARTIFACTS.resumeMultipartUpload(session.storage_path, uploadId).uploadPart(partNumber, r2Body);
  const [uploaded, observedSha256] = await Promise.all([uploadPromise, digestPromise]);
  if (observedSha256 !== partSha256) {
    return json4({ ok: false, error: "multipart_part_checksum_mismatch" }, 422);
  }
  return json4({
    ok: true,
    part_number: uploaded.partNumber,
    etag: uploaded.etag,
    sha256: observedSha256
  }, 201);
}
__name(uploadMultipartPart, "uploadMultipartPart");
async function completeMultipartArtifact(request, env, parts) {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const alreadyComplete = await existingArtifactGrant(
    request,
    env,
    access.artifactId,
    access.jobId,
    access.deviceId
  );
  if (alreadyComplete) return alreadyComplete;
  const session = await loadMultipartUpload(
    env,
    access.artifactId,
    access.jobId,
    access.deviceId
  );
  if (!session) return json4({ ok: false, error: "multipart_upload_not_found" }, 404);
  const body = await parseSmallJson4(request, 1024 * 1024);
  const uploadId = body && typeof body.upload_id === "string" ? body.upload_id : "";
  const rawParts = body && Array.isArray(body.parts) ? body.parts : [];
  if (uploadId !== session.upload_id || rawParts.length < 1 || rawParts.length > MULTIPART_MAX_PARTS) {
    return json4({ ok: false, error: "multipart_complete_invalid" }, 400);
  }
  const uploadedParts = [];
  for (const value of rawParts) {
    if (!isRecord5(value)) {
      return json4({ ok: false, error: "multipart_complete_invalid" }, 400);
    }
    const partNumber = Number(value.part_number);
    const etag = typeof value.etag === "string" ? value.etag : "";
    if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > MULTIPART_MAX_PARTS || etag.length < 1 || etag.length > 256) {
      return json4({ ok: false, error: "multipart_complete_invalid" }, 400);
    }
    uploadedParts.push({ partNumber, etag });
  }
  uploadedParts.sort((a, b) => a.partNumber - b.partNumber);
  if (uploadedParts.some((item, index) => item.partNumber !== index + 1)) {
    return json4({ ok: false, error: "multipart_parts_not_contiguous" }, 400);
  }
  let stored = await env.ARTIFACTS.head(session.storage_path);
  if (!stored) {
    stored = await env.ARTIFACTS.resumeMultipartUpload(session.storage_path, session.upload_id).complete(uploadedParts);
  }
  if (!stored || stored.size !== Number(session.size_bytes)) {
    await env.ARTIFACTS.delete(session.storage_path);
    await env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1"
    ).bind(access.artifactId).run();
    return json4({ ok: false, error: "artifact_integrity_mismatch" }, 422);
  }
  const object2 = await env.ARTIFACTS.get(session.storage_path);
  if (!object2 || !object2.body) {
    return json4({ ok: false, error: "artifact_storage_read_failed" }, 503);
  }
  const digestStream = new crypto.DigestStream("SHA-256");
  await object2.body.pipeTo(digestStream);
  const observedSha256 = arrayBufferToHex(await digestStream.digest).toLowerCase();
  if (observedSha256 !== session.sha256.toLowerCase()) {
    await env.ARTIFACTS.delete(session.storage_path);
    await env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1"
    ).bind(access.artifactId).run();
    return json4({ ok: false, error: "artifact_integrity_mismatch" }, 422);
  }
  const readToken = randomHex(32);
  const readTokenSha256 = await sha256Text(readToken);
  const createdAt = nowIso();
  const readExpiresAt = new Date(Date.now() + 60 * 60 * 1e3).toISOString();
  await env.DB.prepare(
    `INSERT INTO ordax_artifacts
      (id, job_id, device_id, storage_path, file_name, kind, content_type, sha256,
       size_bytes, metadata_json, read_token_sha256, read_expires_at, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
     ON CONFLICT(id) DO NOTHING`
  ).bind(
    session.artifact_id,
    session.job_id,
    session.device_id,
    session.storage_path,
    session.file_name,
    session.kind,
    session.content_type,
    session.sha256,
    session.size_bytes,
    session.metadata_json,
    readTokenSha256,
    readExpiresAt,
    createdAt
  ).run();
  const persisted = await env.DB.prepare(
    `SELECT job_id, device_id, storage_path, sha256, size_bytes
     FROM ordax_artifacts WHERE id = ?1`
  ).bind(access.artifactId).first();
  if (!persisted || persisted.job_id !== session.job_id || persisted.device_id !== session.device_id || persisted.storage_path !== session.storage_path || persisted.sha256.toLowerCase() !== session.sha256.toLowerCase() || Number(persisted.size_bytes) !== Number(session.size_bytes)) {
    return json4({ ok: false, error: "artifact_publish_conflict" }, 409);
  }
  await env.DB.prepare(
    "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1"
  ).bind(access.artifactId).run();
  const origin = new URL(request.url).origin;
  return json4({
    ok: true,
    complete: true,
    multipart: true,
    artifact_id: session.artifact_id,
    storage_path: session.storage_path,
    sha256: observedSha256,
    size_bytes: Number(session.size_bytes),
    signed_url: origin + "/v3/artifacts/" + session.artifact_id + "?token=" + encodeURIComponent(readToken),
    expires_at: readExpiresAt
  }, 201);
}
__name(completeMultipartArtifact, "completeMultipartArtifact");
async function abortMultipartArtifact(request, env, parts) {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const url = new URL(request.url);
  const uploadId = url.searchParams.get("uploadId") ?? "";
  const session = await loadMultipartUpload(
    env,
    access.artifactId,
    access.jobId,
    access.deviceId
  );
  if (!session) return json4({ ok: true, aborted: false, missing: true });
  if (uploadId !== session.upload_id) {
    return json4({ ok: false, error: "multipart_upload_conflict" }, 409);
  }
  try {
    await env.ARTIFACTS.resumeMultipartUpload(session.storage_path, session.upload_id).abort();
  } catch {
  }
  await env.DB.prepare(
    "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1"
  ).bind(access.artifactId).run();
  return json4({ ok: true, aborted: true });
}
__name(abortMultipartArtifact, "abortMultipartArtifact");
async function downloadArtifact(request, env, artifactId) {
  if (!UUID_RE4.test(artifactId)) return json4({ ok: false, error: "artifact_id_invalid" }, 400);
  const token = new URL(request.url).searchParams.get("token") ?? "";
  if (token.length < 32 || token.length > 512) return json4({ ok: false, error: "artifact_token_required" }, 401);
  const digest = await sha256Text(token);
  const row = await env.DB.prepare(
    `SELECT storage_path, file_name, content_type, read_expires_at
     FROM ordax_artifacts WHERE id = ?1 AND read_token_sha256 = ?2`
  ).bind(artifactId, digest).first();
  if (!row || new Date(row.read_expires_at).getTime() <= Date.now()) {
    return json4({ ok: false, error: "artifact_token_invalid_or_expired" }, 403);
  }
  const object2 = await env.ARTIFACTS.get(row.storage_path);
  if (!object2) return json4({ ok: false, error: "artifact_not_found" }, 404);
  const headers = new Headers();
  object2.writeHttpMetadata(headers);
  headers.set("content-type", row.content_type ?? headers.get("content-type") ?? "application/octet-stream");
  headers.set("content-disposition", `inline; filename="${row.file_name.replace(/"/g, "")}"`);
  headers.set("cache-control", "private, no-store");
  return new Response(object2.body, { headers });
}
__name(downloadArtifact, "downloadArtifact");
var index_default = {
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(
      runProductRetention(env).then((stats) => {
        console.log(JSON.stringify({ event: "product_retention", ...stats }));
      })
    );
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (request.method === "GET" && url.pathname === "/health") {
      return json4({
        ok: true,
        service: "ordax-control-plane-v3",
        capabilities: CONTROL_PLANE_CAPABILITIES,
        product_auth_configured: productAuthConfigured(env)
      });
    }
    if (request.method === "GET" && url.pathname === "/.well-known/openai-apps-challenge") {
      return openAiAppsChallenge(env);
    }
    if (request.method === "GET") {
      const publicPage = publicProductPage(url.pathname);
      if (publicPage) return publicPage;
    }
    if (request.method === "GET" && url.pathname === "/v3/device/ws") {
      if ((request.headers.get("Upgrade") ?? "").toLowerCase() !== "websocket") {
        return json4({ ok: false, error: "websocket_required" }, 426);
      }
      const deviceId = url.searchParams.get("device_id") ?? "";
      const token = request.headers.get("X-Ordax-Device-Token") ?? "";
      const auth = await authenticateDevice(env, deviceId, token);
      if (!auth.ok) return json4({ ok: false, error: auth.error }, 401);
      const id = env.DEVICE_SESSIONS.idFromName(deviceId);
      const headers = new Headers(request.headers);
      headers.set("X-Ordax-Device-Id", deviceId);
      headers.delete("X-Ordax-Device-Token");
      return env.DEVICE_SESSIONS.get(id).fetch("https://device.internal/ws", {
        method: "GET",
        headers
      });
    }
    if (request.method === "POST" && url.pathname === "/v3/device/setup") {
      return deviceSetup(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/device/recover-report") {
      return recoverTerminalReport(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/device/product-pairings") {
      return createProductDevicePairing(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/devices") {
      return provisionDevice(request, env);
    }
    if (request.method === "DELETE" && parts[0] === "v3" && parts[1] === "devices" && parts.length === 3) {
      return deleteDevice(request, env, parts[2]);
    }
    if (request.method === "GET" && url.pathname === "/oauth/consent") {
      return oauthConsentResponse(request);
    }
    if (request.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
      const authorizationServers = env.PRODUCT_AUTH_ISSUER ? [env.PRODUCT_AUTH_ISSUER] : [];
      return json4({
        resource: `${url.origin}/mcp`,
        authorization_servers: authorizationServers,
        bearer_methods_supported: ["header"],
        scopes_supported: ["openid", "email", "offline_access"]
      });
    }
    if (url.pathname === "/mcp") {
      return handleOrdaxMcp(request, {
        session: /* @__PURE__ */ __name((inner) => productSession(inner, env), "session"),
        targets: /* @__PURE__ */ __name((inner) => listProductTargets(inner, env), "targets"),
        createAction: /* @__PURE__ */ __name((inner) => createProductAction(inner, env), "createAction"),
        getAction: /* @__PURE__ */ __name((inner, requestId) => getProductAction(inner, env, requestId), "getAction")
      });
    }
    if (request.method === "GET" && url.pathname === "/v3/product/session") {
      return productSession(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/device-intelligence-grants") {
      return createOwnerDeviceIntelligenceGrant(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/device-intelligence-grants") {
      return listOwnerDeviceIntelligenceGrants(request, env);
    }
    if (request.method === "DELETE" && parts[0] === "v3" && parts[1] === "product" && parts[2] === "device-intelligence-grants" && parts.length === 4) {
      return revokeOwnerDeviceIntelligenceGrant(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/device-computer-grants") {
      return createOwnerDeviceComputerGrant(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/device-computer-grants") {
      return listOwnerDeviceComputerGrants(request, env);
    }
    if (request.method === "DELETE" && parts[0] === "v3" && parts[1] === "product" && parts[2] === "device-computer-grants" && parts.length === 4) {
      return revokeOwnerDeviceComputerGrant(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/project-capability-grants") {
      return createOwnerProjectGrant(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/project-capability-grants") {
      return listOwnerProjectGrants(request, env);
    }
    if (request.method === "DELETE" && parts[0] === "v3" && parts[1] === "product" && parts[2] === "project-capability-grants" && parts.length === 4) {
      return revokeOwnerProjectGrant(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/device-links") {
      return claimProductDevicePairing(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/device-links") {
      return listProductDeviceLinks(request, env);
    }
    if (request.method === "DELETE" && parts[0] === "v3" && parts[1] === "product" && parts[2] === "device-links" && parts.length === 4) {
      return revokeProductDeviceLink(request, env, parts[3]);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/targets") {
      return listProductTargets(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/actions") {
      return createProductAction(request, env);
    }
    if (request.method === "GET" && parts[0] === "v3" && parts[1] === "product" && parts[2] === "actions" && parts.length === 4) {
      return getProductAction(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/audit") {
      return recordProductAudit(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product-grants") {
      return createProductGrant(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product-grants/from-link") {
      return createProductGrantFromLink(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product-grants") {
      return listProductGrants(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product-grants/resolve") {
      return resolveProductGrantAdmin(request, env);
    }
    if (request.method === "DELETE" && parts[0] === "v3" && parts[1] === "product-grants" && parts.length === 3) {
      return revokeProductGrant(request, env, parts[2]);
    }
    if (request.method === "POST" && url.pathname === "/v3/jobs") {
      return enqueueJob(request, env);
    }
    if (request.method === "GET" && parts[0] === "v3" && parts[1] === "jobs" && parts.length === 3) {
      return getJob(request, env, parts[2]);
    }
    if (parts[0] === "v3" && parts[1] === "artifacts" && parts.length === 4) {
      const action = url.searchParams.get("action") ?? "";
      if (request.method === "POST" && action === "mpu-create") {
        return createMultipartArtifact(request, env, parts);
      }
      if (request.method === "PUT" && action === "mpu-uploadpart") {
        return uploadMultipartPart(request, env, parts);
      }
      if (request.method === "POST" && action === "mpu-complete") {
        return completeMultipartArtifact(request, env, parts);
      }
      if (request.method === "DELETE" && action === "mpu-abort") {
        return abortMultipartArtifact(request, env, parts);
      }
      if (request.method === "PUT" && action === "") {
        return uploadArtifact(request, env, parts);
      }
    }
    if (request.method === "GET" && parts[0] === "v3" && parts[1] === "artifacts" && parts.length === 3) {
      return downloadArtifact(request, env, parts[2]);
    }
    return json4({ ok: false, error: "not_found" }, 404);
  }
};
var EnrollmentSession = class extends DurableObject {
  static {
    __name(this, "EnrollmentSession");
  }
  constructor(ctx, env) {
    super(ctx, env);
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/enroll") {
      return json4({ ok: false, error: "not_found" }, 404);
    }
    const productSubjectId = request.headers.get("X-Ordax-Product-Subject") ?? "";
    if (!PRODUCT_ID_RE.test(productSubjectId)) {
      return json4({ ok: false, error: "user_identity_invalid" }, 401);
    }
    const body = await parseSmallJson4(request, 8 * 1024);
    if (!body) return json4({ ok: false, error: "request_invalid" }, 400);
    const binding = typeof body.machine_binding_sha256 === "string" ? body.machine_binding_sha256.toLowerCase() : "";
    const tokenSha256 = typeof body.token_sha256 === "string" ? body.token_sha256.toLowerCase() : "";
    const name = typeof body.device_name === "string" ? body.device_name.trim() : "";
    if (!HEX64_RE.test(binding) || !HEX64_RE.test(tokenSha256) || !name) {
      return json4({ ok: false, error: "request_invalid" }, 400);
    }
    const existing = await this.env.DB.prepare(
      `SELECT id, owner_product_subject_id, enrollment_window_started_at, enrollment_count
       FROM ordax_devices WHERE machine_binding_sha256 = ?1`
    ).bind(binding).first();
    if (existing?.owner_product_subject_id && existing.owner_product_subject_id !== productSubjectId) {
      return json4({ ok: false, error: "device_owner_mismatch" }, 403);
    }
    const now = /* @__PURE__ */ new Date();
    const previousWindow = existing?.enrollment_window_started_at ? new Date(existing.enrollment_window_started_at) : null;
    const sameWindow = Boolean(
      previousWindow && Number.isFinite(previousWindow.getTime()) && now.getTime() - previousWindow.getTime() < 60 * 60 * 1e3
    );
    const previousCount = sameWindow ? Number(existing?.enrollment_count ?? 0) : 0;
    if (previousCount >= 10) {
      return json4({ ok: false, error: "enrollment_rate_limited" }, 429);
    }
    const deviceId = existing?.id ?? crypto.randomUUID();
    const windowStartedAt = sameWindow && previousWindow ? previousWindow.toISOString() : now.toISOString();
    const enrolledAt = now.toISOString();
    const nextCount = previousCount + 1;
    if (existing) {
      const updated = await this.env.DB.prepare(
        `UPDATE ordax_devices SET
           name = ?1,
           token_sha256 = ?2,
           owner_product_subject_id = ?3,
           revoked_at = NULL,
           last_enrolled_at = ?4,
           enrollment_window_started_at = ?5,
           enrollment_count = ?6
         WHERE id = ?7
           AND machine_binding_sha256 = ?8
           AND (owner_product_subject_id IS NULL OR owner_product_subject_id = ?3)`
      ).bind(
        name,
        tokenSha256,
        productSubjectId,
        enrolledAt,
        windowStartedAt,
        nextCount,
        deviceId,
        binding
      ).run();
      if ((updated.meta.changes ?? 0) !== 1) {
        return json4({ ok: false, error: "enrollment_conflict" }, 409);
      }
    } else {
      try {
        await this.env.DB.prepare(
          `INSERT INTO ordax_devices
            (id, name, token_sha256, created_at, revoked_at,
             machine_binding_sha256, owner_product_subject_id, last_enrolled_at,
             enrollment_window_started_at, enrollment_count)
           VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9)`
        ).bind(
          deviceId,
          name,
          tokenSha256,
          enrolledAt,
          binding,
          productSubjectId,
          enrolledAt,
          windowStartedAt,
          nextCount
        ).run();
      } catch {
        return json4({ ok: false, error: "enrollment_conflict" }, 409);
      }
    }
    return json4({
      ok: true,
      protocol: "cloudflare-v3",
      device_id: deviceId
    });
  }
};
var DeviceSession = class extends DurableObject {
  static {
    __name(this, "DeviceSession");
  }
  constructor(ctx, env) {
    super(ctx, env);
  }
  ack(ws, requestId, ok, extra = {}) {
    ws.send(JSON.stringify({
      type: "ack",
      request_id: typeof requestId === "string" ? requestId : null,
      ok,
      ...extra
    }));
  }
  attachment(ws) {
    const value = ws.deserializeAttachment();
    return isRecord5(value) && typeof value.deviceId === "string" && typeof value.agentInstanceId === "string" && typeof value.bootId === "string" ? value : null;
  }
  async fenceExpiredForeignRunningJobs(deviceId, agentInstanceId, bootId) {
    const now = nowIso();
    await this.env.DB.prepare(
      `UPDATE ordax_jobs SET
         status = 'failed',
         error_code = 'execution_context_lost',
         finished_at = COALESCE(finished_at, ?1)
       WHERE device_id = ?2
         AND status = 'running'
         AND report_id IS NULL
         AND lease_expires_at < ?1
         AND (
           agent_instance_id IS NULL OR boot_id IS NULL
           OR agent_instance_id != ?3 OR boot_id != ?4
         )`
    ).bind(now, deviceId, agentInstanceId, bootId).run();
  }
  async deliverNextJob(ws, deviceId) {
    const now = nowIso();
    const activeExecution = await this.env.DB.prepare(
      `SELECT id FROM ordax_jobs
       WHERE device_id = ?1
         AND (status = 'running' OR (status = 'leased' AND lease_expires_at >= ?2))
       LIMIT 1`
    ).bind(deviceId, now).first();
    if (activeExecution) return;
    const candidate = await this.env.DB.prepare(
      `SELECT id, capability, payload_canonical_b64, payload_sha256, effect_id, execution_epoch
       FROM ordax_jobs
       WHERE device_id = ?1
         AND (status = 'queued' OR (status = 'leased' AND lease_expires_at < ?2))
       ORDER BY created_at ASC
       LIMIT 1`
    ).bind(deviceId, now).first();
    if (!candidate) return;
    const attachment = this.attachment(ws);
    if (!attachment) return;
    const attemptId = crypto.randomUUID();
    const leaseId = crypto.randomUUID();
    const nextEpoch = Number(candidate.execution_epoch ?? 0) + 1;
    const leaseExpiresAt = new Date(Date.now() + 12e4).toISOString();
    const update = await this.env.DB.prepare(
      `UPDATE ordax_jobs SET
         status = 'leased',
         attempt_id = ?1,
         lease_id = ?2,
         execution_epoch = ?3,
         agent_instance_id = ?4,
         boot_id = ?5,
         lease_expires_at = ?6
       WHERE id = ?7 AND device_id = ?8
         AND (status = 'queued' OR (status = 'leased' AND lease_expires_at < ?9))`
    ).bind(
      attemptId,
      leaseId,
      nextEpoch,
      attachment.agentInstanceId,
      attachment.bootId,
      leaseExpiresAt,
      candidate.id,
      deviceId,
      now
    ).run();
    if ((update.meta.changes ?? 0) !== 1) return;
    ws.send(JSON.stringify({
      type: "job",
      job: {
        job_id: candidate.id,
        capability: candidate.capability,
        payload_canonical_b64: candidate.payload_canonical_b64,
        payload_sha256: candidate.payload_sha256,
        effect_id: candidate.effect_id,
        attempt_id: attemptId,
        lease_id: leaseId,
        execution_epoch: nextEpoch,
        agent_instance_id: attachment.agentInstanceId,
        boot_id: attachment.bootId,
        expires_at: leaseExpiresAt
      }
    }));
  }
  async fetch(request) {
    const url = new URL(request.url);
    const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
    if (!UUID_RE4.test(deviceId)) return json4({ ok: false, error: "device_id_invalid" }, 400);
    if (url.pathname === "/ws") {
      if ((request.headers.get("Upgrade") ?? "").toLowerCase() !== "websocket") {
        return json4({ ok: false, error: "websocket_required" }, 426);
      }
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      this.ctx.acceptWebSocket(server);
      const agentInstanceId = request.headers.get("X-Ordax-Agent-Instance") ?? "";
      const bootId = request.headers.get("X-Ordax-Boot-Id") ?? "";
      if (!UUID_RE4.test(agentInstanceId) || !UUID_RE4.test(bootId)) {
        server.close(1008, "invalid runtime identity");
        return new Response(null, { status: 101, webSocket: client });
      }
      server.serializeAttachment({ deviceId, agentInstanceId, bootId });
      await this.env.DB.prepare(
        "UPDATE ordax_devices SET last_seen_at = ?1 WHERE id = ?2"
      ).bind(nowIso(), deviceId).run();
      server.send(JSON.stringify({
        type: "hello",
        device_id: deviceId,
        protocol: "cloudflare-v3"
      }));
      await this.fenceExpiredForeignRunningJobs(deviceId, agentInstanceId, bootId);
      await this.deliverNextJob(server, deviceId);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/wake" && request.method === "POST") {
      const targetAgentInstanceId = request.headers.get("X-Ordax-Target-Agent-Instance") ?? "";
      const targetBootId = request.headers.get("X-Ordax-Target-Boot-Id") ?? "";
      const targeted = Boolean(targetAgentInstanceId || targetBootId);
      if (targeted && (!UUID_RE4.test(targetAgentInstanceId) || !UUID_RE4.test(targetBootId))) {
        return json4({ ok: false, error: "wake_target_invalid" }, 400);
      }
      for (const ws of this.ctx.getWebSockets()) {
        const attachment = this.attachment(ws);
        if (!attachment || attachment.deviceId !== deviceId) continue;
        if (targeted && (attachment.agentInstanceId !== targetAgentInstanceId || attachment.bootId !== targetBootId)) {
          continue;
        }
        await this.deliverNextJob(ws, deviceId);
      }
      return json4({ ok: true });
    }
    return json4({ ok: false, error: "not_found" }, 404);
  }
  async webSocketMessage(ws, raw) {
    let message;
    try {
      const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
      const parsed = JSON.parse(text);
      if (!isRecord5(parsed)) throw new Error("not object");
      message = parsed;
    } catch {
      this.ack(ws, null, false, { error: "invalid_json" });
      return;
    }
    const attachment = this.attachment(ws);
    if (!attachment) {
      ws.close(1008, "missing identity");
      return;
    }
    const requestId = message.request_id;
    const type = typeof message.type === "string" ? message.type : "";
    const deviceId = attachment.deviceId;
    if (type === "heartbeat") {
      await this.env.DB.prepare(
        "UPDATE ordax_devices SET last_seen_at = ?1 WHERE id = ?2 AND revoked_at IS NULL"
      ).bind(nowIso(), deviceId).run();
      this.ack(ws, requestId, true, { server_time: nowIso() });
      return;
    }
    const jobId = typeof message.job_id === "string" ? message.job_id : "";
    const effectId = typeof message.effect_id === "string" ? message.effect_id : "";
    const attemptId = typeof message.attempt_id === "string" ? message.attempt_id : "";
    const leaseId = typeof message.lease_id === "string" ? message.lease_id : "";
    const executionEpoch = Number.isSafeInteger(message.execution_epoch) ? Number(message.execution_epoch) : 0;
    if (!UUID_RE4.test(jobId) || !UUID_RE4.test(effectId) || !UUID_RE4.test(attemptId) || !UUID_RE4.test(leaseId) || executionEpoch < 1) {
      this.ack(ws, requestId, false, { error: "execution_context_invalid" });
      return;
    }
    if (type === "report") {
      const reportId = typeof message.report_id === "string" ? message.report_id : "";
      const status = typeof message.status === "string" ? message.status : "";
      const resultSha256 = typeof message.result_sha256 === "string" ? message.result_sha256.toLowerCase() : "";
      const resultValue = isRecord5(message.result) ? message.result : {};
      const resultJson = stableJson(resultValue);
      const errorCode = typeof message.error_code === "string" ? message.error_code : null;
      if (!UUID_RE4.test(reportId) || !["succeeded", "failed", "cancelled"].includes(status) || !HEX64_RE.test(resultSha256)) {
        this.ack(ws, requestId, false, { error: "report_invalid" });
        return;
      }
      if (new TextEncoder().encode(resultJson).byteLength > 512 * 1024) {
        this.ack(ws, requestId, false, { error: "result_too_large" });
        return;
      }
      const terminal = await this.env.DB.prepare(
        `SELECT status, effect_id, attempt_id, report_id, result_json,
                result_sha256, error_code, lease_id, execution_epoch,
                agent_instance_id, boot_id
         FROM ordax_jobs
         WHERE id = ?1 AND device_id = ?2
           AND status IN ('succeeded','failed','cancelled')`
      ).bind(jobId, deviceId).first();
      if (terminal) {
        const replayMatches = terminal.effect_id === effectId && terminal.attempt_id === attemptId && terminal.report_id === reportId && terminal.status === status && canonicalStoredJson(terminal.result_json) === resultJson && (terminal.result_sha256 ?? "").toLowerCase() === resultSha256 && terminal.error_code === errorCode && terminal.lease_id === leaseId && Number(terminal.execution_epoch) === executionEpoch && terminal.agent_instance_id === attachment.agentInstanceId && terminal.boot_id === attachment.bootId;
        this.ack(
          ws,
          requestId,
          replayMatches,
          replayMatches ? { status, replayed: true } : { error: "terminal_report_conflict" }
        );
        return;
      }
    }
    const active = await this.env.DB.prepare(
      `SELECT id FROM ordax_jobs
       WHERE id = ?1 AND device_id = ?2 AND effect_id = ?3 AND attempt_id = ?4
         AND lease_id = ?5 AND execution_epoch = ?6
         AND agent_instance_id = ?7 AND boot_id = ?8
         AND status IN ('leased','running')`
    ).bind(
      jobId,
      deviceId,
      effectId,
      attemptId,
      leaseId,
      executionEpoch,
      attachment.agentInstanceId,
      attachment.bootId
    ).first();
    if (!active) {
      this.ack(ws, requestId, false, { error: "lease_not_active" });
      return;
    }
    if (type === "start") {
      const startedAt = nowIso();
      const result = await this.env.DB.prepare(
        `UPDATE ordax_jobs SET status = 'running', started_at = COALESCE(started_at, ?1)
         WHERE id = ?2 AND device_id = ?3 AND effect_id = ?4 AND attempt_id = ?5
           AND lease_id = ?6 AND execution_epoch = ?7
           AND agent_instance_id = ?8 AND boot_id = ?9
           AND status IN ('leased','running') AND report_id IS NULL`
      ).bind(
        startedAt,
        jobId,
        deviceId,
        effectId,
        attemptId,
        leaseId,
        executionEpoch,
        attachment.agentInstanceId,
        attachment.bootId
      ).run();
      const ok = (result.meta.changes ?? 0) === 1;
      this.ack(ws, requestId, ok, ok ? { started: true } : { error: "start_rejected" });
      return;
    }
    if (type === "lease_heartbeat") {
      const leasedUntil = new Date(Date.now() + 12e4).toISOString();
      const result = await this.env.DB.prepare(
        `UPDATE ordax_jobs SET lease_expires_at = ?1
         WHERE id = ?2 AND device_id = ?3 AND effect_id = ?4 AND attempt_id = ?5
           AND lease_id = ?6 AND execution_epoch = ?7
           AND agent_instance_id = ?8 AND boot_id = ?9
           AND status IN ('leased','running') AND report_id IS NULL`
      ).bind(
        leasedUntil,
        jobId,
        deviceId,
        effectId,
        attemptId,
        leaseId,
        executionEpoch,
        attachment.agentInstanceId,
        attachment.bootId
      ).run();
      const ok = (result.meta.changes ?? 0) === 1;
      this.ack(
        ws,
        requestId,
        ok,
        ok ? { leased_until: leasedUntil } : { error: "lease_not_active" }
      );
      return;
    }
    if (type === "progress") {
      const percent = message.progress_percent == null ? null : Number.isInteger(message.progress_percent) ? Math.max(0, Math.min(100, Number(message.progress_percent))) : null;
      const stage = typeof message.stage === "string" ? message.stage.slice(0, 96) : "info";
      const text = typeof message.message === "string" ? message.message.slice(0, 512) : null;
      await this.env.DB.prepare(
        `INSERT INTO ordax_job_events (job_id, stage, message, progress_percent, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)`
      ).bind(jobId, stage, text, percent, nowIso()).run();
      this.ack(ws, requestId, true);
      return;
    }
    if (type === "report") {
      const reportId = String(message.report_id);
      const status = String(message.status);
      const resultSha256 = String(message.result_sha256).toLowerCase();
      const resultValue = isRecord5(message.result) ? message.result : {};
      const resultJson = stableJson(resultValue);
      const errorCode = typeof message.error_code === "string" ? message.error_code : null;
      const finishedAt = nowIso();
      const update = await this.env.DB.prepare(
        `UPDATE ordax_jobs SET
           status = ?1, report_id = ?2, result_json = ?3, result_sha256 = ?4,
           error_code = ?5, finished_at = ?6, lease_expires_at = NULL
         WHERE id = ?7 AND device_id = ?8 AND effect_id = ?9 AND attempt_id = ?10
           AND lease_id = ?11 AND execution_epoch = ?12
           AND agent_instance_id = ?13 AND boot_id = ?14
           AND status IN ('leased','running') AND report_id IS NULL`
      ).bind(
        status,
        reportId,
        resultJson,
        resultSha256,
        errorCode,
        finishedAt,
        jobId,
        deviceId,
        effectId,
        attemptId,
        leaseId,
        executionEpoch,
        attachment.agentInstanceId,
        attachment.bootId
      ).run();
      const ok = (update.meta.changes ?? 0) === 1;
      this.ack(ws, requestId, ok, ok ? { status, replayed: false } : { error: "report_rejected" });
      if (ok) await this.deliverNextJob(ws, deviceId);
      return;
    }
    this.ack(ws, requestId, false, { error: "operation_not_allowed" });
  }
  async webSocketClose(_ws, _code, _reason, _wasClean) {
  }
  async webSocketError(_ws, _error) {
  }
};
export {
  DeviceSession,
  EnrollmentSession,
  index_default as default
};
//# sourceMappingURL=index.js.map
