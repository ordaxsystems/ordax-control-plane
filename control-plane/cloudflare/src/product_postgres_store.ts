type JsonObject = Record<string, unknown>;

export interface ProductPostgresEnv {
  SUPABASE_URL?: string;
  SUPABASE_SERVER_KEY?: string;
}

export type ProductRemoteJob = {
  request_id: string;
  device_id: string;
  project_id: string | null;
  capability: string;
  payload: JsonObject;
  payload_sha256: string;
  effect_id: string;
  attempt_id: string;
  lease_id: string;
  execution_epoch: number;
  agent_instance_id: string;
  boot_id: string;
  lease_expires_at: string;
};

export type ProductActionEnqueueResult = {
  ok: boolean;
  replayed?: boolean;
  request_id?: string;
  effect_id?: string;
  status?: string;
  error?: string;
};

export type ProductActionClaimResult = {
  ok: boolean;
  job: ProductRemoteJob | null;
  error?: string;
};

export class ProductPostgresError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
  ) {
    super(code);
    this.name = "ProductPostgresError";
  }
}

const RPC_TIMEOUT_MS = 10_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function configuredOrigin(env: ProductPostgresEnv): URL | null {
  const raw = (env.SUPABASE_URL ?? "").trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
      return null;
    }
    url.pathname = "/";
    return url;
  } catch {
    return null;
  }
}

function configuredServerKey(env: ProductPostgresEnv): string | null {
  const key = (env.SUPABASE_SERVER_KEY ?? "").trim();
  return key.startsWith("sb_secret_") && key.length >= 32 ? key : null;
}

export function productPostgresConfigured(env: ProductPostgresEnv): boolean {
  return configuredOrigin(env) !== null && configuredServerKey(env) !== null;
}

async function callRpc<T>(
  env: ProductPostgresEnv,
  rpc: string,
  payload: JsonObject,
): Promise<T> {
  const origin = configuredOrigin(env);
  const serverKey = configuredServerKey(env);
  if (!origin || !serverKey) {
    throw new ProductPostgresError("product_postgres_unconfigured", 503);
  }

  const endpoint = new URL(`/rest/v1/rpc/${rpc}`, origin);
  let response: Response;
  try {
    response = await fetch(endpoint.toString(), {
      method: "POST",
      headers: {
        apikey: serverKey,
        accept: "application/json",
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(payload),
      redirect: "manual",
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
  } catch {
    throw new ProductPostgresError("product_postgres_unavailable", 503);
  }

  if (!response.ok) {
    // Never surface database/server details or the backend secret to Product clients.
    throw new ProductPostgresError(
      response.status >= 500 ? "product_postgres_unavailable" : "product_postgres_rejected",
      response.status >= 500 ? 503 : 502,
    );
  }

  try {
    return await response.json() as T;
  } catch {
    throw new ProductPostgresError("product_postgres_invalid_response", 502);
  }
}

export async function enqueueProductAction(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string;
    spaceId: string;
    projectId: string | null;
    deviceId: string;
    clientKind: "ordax-web" | "ordax-mobile" | "product-mcp";
    capability: string;
    accessMode: "read" | "write";
    payload: JsonObject;
    idempotencyKey: string;
    expiresAt: string;
  },
): Promise<ProductActionEnqueueResult> {
  return callRpc<ProductActionEnqueueResult>(
    env,
    "ordax_enqueue_product_action_v1",
    {
      p_owner_user_id: input.ownerUserId,
      p_space_id: input.spaceId,
      p_project_id: input.projectId,
      p_device_id: input.deviceId,
      p_client_kind: input.clientKind,
      p_capability: input.capability,
      p_access_mode: input.accessMode,
      p_payload: input.payload,
      p_idempotency_key: input.idempotencyKey,
      p_expires_at: input.expiresAt,
    },
  );
}

export async function claimProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    agentInstanceId: string;
    bootId: string;
    leaseSeconds?: number;
  },
): Promise<ProductActionClaimResult> {
  return callRpc<ProductActionClaimResult>(
    env,
    "ordax_claim_product_action_v1",
    {
      p_device_id: input.deviceId,
      p_agent_instance_id: input.agentInstanceId,
      p_boot_id: input.bootId,
      p_lease_seconds: input.leaseSeconds ?? 120,
    },
  );
}

export async function startProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_start_product_action_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
  });
}

export async function renewProductActionLease(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    leaseSeconds?: number;
  },
): Promise<string | null> {
  return callRpc<string | null>(env, "ordax_renew_product_action_lease_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_lease_seconds: input.leaseSeconds ?? 120,
  });
}

export async function progressProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    stage: string;
    message: string | null;
    progressPercent: number | null;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_progress_product_action_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_stage: input.stage,
    p_message: input.message,
    p_progress_percent: input.progressPercent,
  });
}

export async function reportProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    reportId: string;
    status: "succeeded" | "failed" | "cancelled";
    result: JsonObject;
    resultSha256: string;
    errorCode: string | null;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_report_product_action_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_report_id: input.reportId,
    p_status: input.status,
    p_result: input.result,
    p_result_sha256: input.resultSha256,
    p_error_code: input.errorCode,
  });
}

export async function getProductAction(
  env: ProductPostgresEnv,
  ownerUserId: string,
  requestId: string,
): Promise<JsonObject | null> {
  if (!UUID_RE.test(ownerUserId) || !UUID_RE.test(requestId)) {
    throw new ProductPostgresError("product_action_identity_invalid", 400);
  }
  return callRpc<JsonObject | null>(env, "ordax_get_product_action_v1", {
    p_owner_user_id: ownerUserId,
    p_request_id: requestId,
  });
}

export async function recordProductPresence(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    online: boolean;
    runtimeKind: "ordax-os" | "desktop-agent" | "mobile-client" | "other" | null;
    agentVersion: string | null;
    capabilityDigest: string | null;
    force?: boolean;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_record_product_presence_v1", {
    p_device_id: input.deviceId,
    p_online: input.online,
    p_runtime_kind: input.runtimeKind,
    p_agent_version: input.agentVersion,
    p_capability_digest: input.capabilityDigest,
    p_force: input.force ?? false,
  });
}

export async function enrollProductDevice(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string;
    deviceName: string;
    deviceKind: "desktop" | "laptop" | "mobile" | "server" | "other";
    channel: "stable" | "development";
    tokenSha256: string;
    machineBindingSha256: string;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_enroll_product_device_v1", {
    p_owner_user_id: input.ownerUserId,
    p_device_name: input.deviceName,
    p_device_kind: input.deviceKind,
    p_channel: input.channel,
    p_token_sha256: input.tokenSha256,
    p_machine_binding_sha256: input.machineBindingSha256,
  });
}

export async function identifyProductDevice(
  env: ProductPostgresEnv,
  input: {
    tokenSha256: string;
    machineBindingSha256: string;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_identify_product_device_v1", {
    p_token_sha256: input.tokenSha256,
    p_machine_binding_sha256: input.machineBindingSha256,
  });
}

export async function authenticateProductDevice(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    tokenSha256: string;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_authenticate_product_device_v1", {
    p_device_id: input.deviceId,
    p_token_sha256: input.tokenSha256,
  });
}

export async function importLegacyProductDevice(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    ownerUserId: string;
    displayName: string;
    deviceKind: "desktop" | "laptop" | "mobile" | "server" | "other";
    channel: "stable" | "development";
    tokenSha256: string;
    machineBindingSha256: string;
    lastSeenAt: string | null;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_import_legacy_product_device_v1", {
    p_device_id: input.deviceId,
    p_owner_user_id: input.ownerUserId,
    p_display_name: input.displayName,
    p_device_kind: input.deviceKind,
    p_channel: input.channel,
    p_token_sha256: input.tokenSha256,
    p_machine_binding_sha256: input.machineBindingSha256,
    p_last_seen_at: input.lastSeenAt,
  });
}
