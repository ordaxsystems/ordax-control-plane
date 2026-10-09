import { readBoundedJsonObject } from "./request_json.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import {
  authenticateProductDevice,
  recordProductPresence,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";

export const PRODUCT_DEVICE_PRESENCE_PATH = "/v3/product/device/presence";

type Presence = Pick<Parameters<typeof recordProductPresence>[1],
  "online" | "runtimeKind" | "agentVersion" | "capabilityDigest">;
type Dependencies = {
  authenticate?: typeof authenticateProductDevice;
  record?: typeof recordProductPresence;
};
const FIELDS = new Set(["online", "runtime_kind", "agent_version", "capability_digest"]);
const RUNTIME_KINDS = new Set(["ordax-os", "desktop-agent", "mobile-client", "other"]);

function json(value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(value, {
    status, headers: { "cache-control": "no-store", ...headers },
  });
}

function presence(body: Record<string, unknown> | null): Presence | null {
  if (!body || Object.keys(body).length !== FIELDS.size
    || Object.keys(body).some(key => !FIELDS.has(key))
    || typeof body.online !== "boolean"
    || !(body.runtime_kind === null || RUNTIME_KINDS.has(body.runtime_kind as string))
    || !(body.agent_version === null || (typeof body.agent_version === "string"
      && body.agent_version.length >= 1 && body.agent_version.length <= 80
      && body.agent_version.trim() === body.agent_version
      && !/[\x00-\x1f\x7f]/.test(body.agent_version)))
    || !(body.capability_digest === null || (typeof body.capability_digest === "string"
      && /^[0-9a-f]{64}$/.test(body.capability_digest)))) return null;
  return {
    online: body.online,
    runtimeKind: body.runtime_kind as Presence["runtimeKind"],
    agentVersion: body.agent_version as string | null,
    capabilityDigest: body.capability_digest as string | null,
  };
}

/**
 * Device-only transport for the existing canonical presence RPC. The device
 * credential, never account/provider metadata, selects the writer. Reporting
 * presence grants no actions and does not establish a working command channel.
 * Dependencies are test seams; production uses only the PostgreSQL adapters.
 */
export async function handleProductDevicePresence(
  request: Request,
  env: ProductPostgresEnv,
  dependencies: Dependencies = {},
): Promise<Response> {
  if (request.method !== "POST") {
    return json({ ok: false, error: "method_not_allowed" }, 405, { allow: "POST" });
  }
  const deviceId = request.headers.get("X-Ordax-Device-Id");
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  if (!isCanonicalUuid(deviceId) || token.length < 32 || token.length > 512
    || !/^[\x21-\x7e]+$/.test(token)) {
    return json({ ok: false, error: "product_device_unauthorized" }, 401);
  }
  const mime = (request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
  if (mime !== "application/json") {
    return json({ ok: false, error: "content_type_invalid" }, 415);
  }
  // A complete metadata snapshot, not arbitrary client/owner/capability claims.
  const snapshot = presence(await readBoundedJsonObject(request, 16 * 1024));
  if (!snapshot) return json({ ok: false, error: "product_presence_invalid" }, 400);
  try {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const tokenSha256 = Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
    const authenticated = await (dependencies.authenticate ?? authenticateProductDevice)(env, {
      deviceId, tokenSha256,
    });
    if (authenticated === false) return json({ ok: false, error: "product_device_unauthorized" }, 401);
    if (authenticated !== true) return json({ ok: false, error: "product_postgres_invalid_response" }, 502);
    const changed = await (dependencies.record ?? recordProductPresence)(env, {
      deviceId, ...snapshot, force: false,
    });
    // The authority coalesces unchanged heartbeats. false is a valid receipt,
    // not a failed write or proof that last_seen_at changed on this request.
    if (typeof changed !== "boolean") {
      return json({ ok: false, error: "product_postgres_invalid_response" }, 502);
    }
    return json({ ok: true, device_id: deviceId, changed });
  } catch (error) {
    const unconfigured = error instanceof ProductPostgresError
      && error.code === "product_postgres_unconfigured";
    return json({ ok: false, error: unconfigured
      ? "product_postgres_unconfigured" : "product_presence_unavailable" }, 503);
  }
}
