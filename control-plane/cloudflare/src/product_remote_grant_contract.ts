/**
 * Shape-only validation for the canonical PostgreSQL Product grant RPCs.
 *
 * Authorization lives exclusively in the PostgreSQL SECURITY DEFINER RPCs.
 * This module does not resolve owners, memberships, devices or capabilities,
 * and must not translate legacy D1 subject IDs or project slugs.
 */
export type RemoteClientKind = "ordax-web" | "ordax-mobile" | "product-mcp";
export type RemoteGrantCapability = {
  capability: string;
  accessMode: "read" | "write";
};

export type RemoteGrantGroupInput = {
  ownerUserId: string;
  spaceId: string | null;
  projectId: string | null;
  deviceId: string;
  clientKind: RemoteClientKind;
  clientId: string | null;
  profileKey: string;
  capabilities: RemoteGrantCapability[];
  validUntil: string | null;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CAPABILITY_RE = /^[a-z][a-z0-9._-]+$/;
const PROFILE_RE = /^[a-z][a-z0-9._-]+$/;
const CLIENT_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]+$/;
const CLIENT_KINDS = new Set(["ordax-web", "ordax-mobile", "product-mcp"]);

export function isCanonicalUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export function canonicalRemoteClient(
  ownerUserId: string,
  clientKind: RemoteClientKind,
  clientId: string | null,
): { p_owner_user_id: string; p_client_kind: string; p_client_id: string | null } | null {
  if (
    !isCanonicalUuid(ownerUserId)
    || !CLIENT_KINDS.has(clientKind)
    || (clientId !== null && (
      typeof clientId !== "string"
      || clientId.length < 8
      || clientId.length > 160
      || !CLIENT_RE.test(clientId)
    ))
  ) return null;
  return {
    p_owner_user_id: ownerUserId,
    p_client_kind: clientKind,
    p_client_id: clientId,
  };
}

export function canonicalRemoteGrantGroup(input: RemoteGrantGroupInput): Record<string, unknown> | null {
  if (!input || typeof input !== "object") return null;
  const client = canonicalRemoteClient(input.ownerUserId, input.clientKind, input.clientId);
  if (
    !client
    || !isCanonicalUuid(input.deviceId)
    || (input.spaceId !== null && !isCanonicalUuid(input.spaceId))
    || (input.projectId !== null && !isCanonicalUuid(input.projectId))
    || (input.projectId === null && input.spaceId !== null)
    || (input.projectId !== null && input.spaceId === null)
    || typeof input.profileKey !== "string"
    || input.profileKey.length < 2
    || input.profileKey.length > 80
    || !PROFILE_RE.test(input.profileKey)
    || !Array.isArray(input.capabilities)
    || input.capabilities.length < 1
    || input.capabilities.length > 128
  ) return null;

  const capabilities = new Set<string>();
  const names: string[] = [];
  const modes: string[] = [];
  for (const item of input.capabilities) {
    if (
      !item
      || typeof item !== "object"
      || typeof item.capability !== "string"
      || item.capability.length < 2
      || item.capability.length > 120
      || !CAPABILITY_RE.test(item.capability)
      || (item.accessMode !== "read" && item.accessMode !== "write")
      || capabilities.has(item.capability)
    ) return null;
    capabilities.add(item.capability);
    names.push(item.capability);
    modes.push(item.accessMode);
  }

  let validUntil: string | null = null;
  if (input.validUntil !== null) {
    if (typeof input.validUntil !== "string") return null;
    const date = new Date(input.validUntil);
    if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) return null;
    validUntil = date.toISOString();
  }
  return {
    ...client,
    p_space_id: input.spaceId,
    p_project_id: input.projectId,
    p_device_id: input.deviceId,
    p_profile_key: input.profileKey,
    p_capabilities: names,
    p_access_modes: modes,
    p_valid_until: validUntil,
  };
}
