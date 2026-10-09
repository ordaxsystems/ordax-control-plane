import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { sanitizeTargets, type OrdaxMcpHandlers } from "./mcp_http.ts";
import {
  listCanonicalProductTargets,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type DiscoveryEnv = ProductAuthEnv & ProductPostgresEnv;
type TargetReader = typeof listCanonicalProductTargets;
type DiscoveryHandlers = Pick<OrdaxMcpHandlers, "session" | "targets">;

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "cache-control": "no-store" } });
}

function validCatalog(value: unknown): value is { ok: true; targets: Record<string, unknown>[] } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const result = value as Record<string, unknown>;
  if (result.ok !== true || !Array.isArray(result.targets)) return false;
  const ids = new Set<string>();
  return result.targets.every((target) => {
    if (!target || typeof target !== "object" || Array.isArray(target)) return false;
    const id = (target as Record<string, unknown>).device_id;
    if (!isCanonicalUuid(id) || ids.has(id.toLowerCase())) return false;
    ids.add(id.toLowerCase());
    return true;
  });
}

/**
 * Read handlers for the coordinated Product MCP cutover (#42).
 * Not wired into index.ts while action/grant/status routes still use D1.
 * The signed OAuth identity selects the existing canonical RPC; no caller
 * header/body, registry scan, legacy fallback or local grant decision is used.
 * readTargets is a dependency seam for transport tests, never request input.
 */
export function createCanonicalProductMcpDiscoveryHandlers(
  env: DiscoveryEnv,
  readTargets: TargetReader = listCanonicalProductTargets,
): DiscoveryHandlers {
  return {
    async session(request) {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
      return json({
        ok: true,
        session: {
          subject_id: identity.ownerUserId,
          client_kind: identity.clientKind,
          client_id: identity.clientId,
          expires_at_unix: identity.expiresAt,
        },
      });
    },
    async targets(request) {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
      try {
        const result = await readTargets(env, {
          ownerUserId: identity.ownerUserId,
          clientKind: identity.clientKind,
          clientId: identity.clientId,
        });
        // Eligibility and exact-client grant resolution remain in PostgreSQL.
        if (result?.ok === false && result.error === "product_owner_auth_ineligible") {
          return json({ ok: false, error: "product_owner_auth_ineligible" }, 403);
        }
        if (!validCatalog(result)) {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 502);
        }
        return json(sanitizeTargets(result));
      } catch (error) {
        // Do not publish database messages, connection strings or SQL details.
        const unconfigured = error instanceof ProductPostgresError
          && error.code === "product_postgres_unconfigured";
        return json({
          ok: false,
          error: unconfigured ? "product_postgres_unconfigured" : "product_targets_unavailable",
        }, 503);
      }
    },
  };
}
