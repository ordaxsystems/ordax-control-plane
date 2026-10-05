export interface ProductAuthEnv {
  PRODUCT_AUTH_ISSUER?: string;
  PRODUCT_AUTH_AUDIENCE?: string;
  PRODUCT_AUTH_JWKS_URL?: string;
}

export type ProductIdentity =
  | {
      ok: true;
      subjectId: string;
      issuer: string;
      audience: string | string[];
      expiresAt: number;
    }
  | {
      ok: false;
      error: string;
      status: number;
    };

type JsonRecord = Record<string, unknown>;

const PRODUCT_SUBJECT_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const JWT_ALGORITHMS = new Set(["RS256", "ES256"]);
const CLOCK_SKEW_SECONDS = 60;

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
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

function decodeJsonPart(value: string): JsonRecord | null {
  const bytes = decodeBase64Url(value);
  if (!bytes) return null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function audienceMatches(value: unknown, expected: string): value is string | string[] {
  return value === expected
    || (Array.isArray(value) && value.every((item) => typeof item === "string") && value.includes(expected));
}

async function importVerificationKey(jwk: JsonWebKey, alg: string): Promise<CryptoKey> {
  if (alg === "RS256") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  }
  if (alg === "ES256") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  }
  throw new Error("unsupported_jwt_algorithm");
}

async function verifySignature(
  alg: string,
  key: CryptoKey,
  signingInput: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (alg === "RS256") {
    return crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      signature,
      signingInput,
    );
  }
  if (alg === "ES256") {
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      signingInput,
    );
  }
  return false;
}

async function loadJwk(env: ProductAuthEnv, kid: string, alg: string): Promise<JsonWebKey | null> {
  const jwksUrl = env.PRODUCT_AUTH_JWKS_URL ?? "";
  let parsed: URL;
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
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) return null;

  const body = await response.json() as unknown;
  if (!isRecord(body) || !Array.isArray(body.keys)) return null;
  for (const raw of body.keys) {
    if (
      isRecord(raw)
      && raw.kid === kid
      && (raw.alg == null || raw.alg === alg)
      && typeof raw.kty === "string"
    ) {
      return raw as JsonWebKey;
    }
  }
  return null;
}

export function productAuthConfigured(env: ProductAuthEnv): boolean {
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

export async function authenticateProductRequest(
  request: Request,
  env: ProductAuthEnv,
): Promise<ProductIdentity> {
  if (!productAuthConfigured(env)) {
    return { ok: false, error: "product_auth_unconfigured", status: 503 };
  }

  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ") || authorization.length > 16_384) {
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

  const issuer = env.PRODUCT_AUTH_ISSUER as string;
  const audience = env.PRODUCT_AUTH_AUDIENCE as string;
  const subjectId = typeof payload.sub === "string" ? payload.sub : "";
  const exp = typeof payload.exp === "number" && Number.isFinite(payload.exp) ? payload.exp : 0;
  const nbf = typeof payload.nbf === "number" && Number.isFinite(payload.nbf) ? payload.nbf : null;
  const now = Math.floor(Date.now() / 1000);

  if (
    payload.iss !== issuer
    || !audienceMatches(payload.aud, audience)
    || !PRODUCT_SUBJECT_RE.test(subjectId)
    || exp <= now - CLOCK_SKEW_SECONDS
    || (nbf !== null && nbf > now + CLOCK_SKEW_SECONDS)
  ) {
    return { ok: false, error: "product_token_claims_invalid", status: 401 };
  }

  let jwk: JsonWebKey | null = null;
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
    audience: payload.aud as string | string[],
    expiresAt: exp,
  };
}
