export interface ProductRetentionEnv {
  DB: D1Database;
  ARTIFACTS: R2Bucket;
}

export interface ProductRetentionStats {
  artifacts: number;
  multipart_uploads: number;
  audits: number;
  jobs: number;
  pairings: number;
  device_links: number;
  grants: number;
}

export const PRODUCT_ARTIFACT_RETENTION_DAYS = 7;
export const PRODUCT_HISTORY_RETENTION_DAYS = 30;
export const PRODUCT_INACTIVE_AUTHZ_RETENTION_DAYS = 30;
export const PRODUCT_MULTIPART_RETENTION_DAYS = 8;

const DAY_MS = 24 * 60 * 60 * 1000;
const BATCH_SIZE = 100;

function isoBefore(nowMs: number, days: number): string {
  return new Date(nowMs - days * DAY_MS).toISOString();
}

async function purgeProductArtifacts(
  env: ProductRetentionEnv,
  cutoff: string,
): Promise<number> {
  let deleted = 0;
  while (true) {
    const page = await env.DB.prepare(
      `SELECT a.id, a.storage_path
       FROM ordax_artifacts a
       JOIN ordax_jobs j ON j.id = a.job_id
       WHERE j.capability = 'ordax.product.invoke'
         AND a.created_at < ?1
       ORDER BY a.created_at
       LIMIT ?2`,
    ).bind(cutoff, BATCH_SIZE).all<{ id: string; storage_path: string }>();

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
        "DELETE FROM ordax_artifacts WHERE id = ?1 AND storage_path = ?2",
      ).bind(row.id, row.storage_path).run();
      const changes = Number(result.meta?.changes ?? 0);
      deleted += changes;
      progress += changes;
    }
    if (rows.length < BATCH_SIZE || progress === 0) break;
  }
  return deleted;
}

async function purgeStaleProductMultipartUploads(
  env: ProductRetentionEnv,
  cutoff: string,
): Promise<number> {
  const page = await env.DB.prepare(
    `SELECT u.artifact_id, u.storage_path, u.upload_id
     FROM ordax_artifact_uploads u
     JOIN ordax_jobs j ON j.id = u.job_id
     WHERE j.capability = 'ordax.product.invoke'
       AND u.created_at < ?1
     ORDER BY u.created_at
     LIMIT ?2`,
  ).bind(cutoff, BATCH_SIZE).all<{
    artifact_id: string;
    storage_path: string;
    upload_id: string;
  }>();

  let deleted = 0;
  for (const row of page.results ?? []) {
    try {
      await env.ARTIFACTS
        .resumeMultipartUpload(row.storage_path, row.upload_id)
        .abort();
    } catch {
      // R2 expires abandoned multipart sessions independently. The database row
      // can still be dropped after our retention window so it cannot retain
      // product metadata indefinitely.
    }
    const result = await env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1 AND upload_id = ?2",
    ).bind(row.artifact_id, row.upload_id).run();
    deleted += Number(result.meta?.changes ?? 0);
  }
  return deleted;
}

async function deleteCount(
  env: ProductRetentionEnv,
  sql: string,
  ...bindings: unknown[]
): Promise<number> {
  const result = await env.DB.prepare(sql).bind(...bindings).run();
  return Number(result.meta?.changes ?? 0);
}

export async function runProductRetention(
  env: ProductRetentionEnv,
  nowMs = Date.now(),
): Promise<ProductRetentionStats> {
  const artifactCutoff = isoBefore(nowMs, PRODUCT_ARTIFACT_RETENTION_DAYS);
  const multipartCutoff = isoBefore(nowMs, PRODUCT_MULTIPART_RETENTION_DAYS);
  const historyCutoff = isoBefore(nowMs, PRODUCT_HISTORY_RETENTION_DAYS);
  const inactiveAuthzCutoff = isoBefore(
    nowMs,
    PRODUCT_INACTIVE_AUTHZ_RETENTION_DAYS,
  );
  const nowIso = new Date(nowMs).toISOString();

  const artifacts = await purgeProductArtifacts(env, artifactCutoff);
  const multipartUploads = await purgeStaleProductMultipartUploads(
    env,
    multipartCutoff,
  );

  const audits = await deleteCount(
    env,
    "DELETE FROM ordax_product_audit WHERE created_at < ?1",
    historyCutoff,
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
    historyCutoff,
  );

  const pairings = await deleteCount(
    env,
    "DELETE FROM ordax_product_device_pairings WHERE expires_at < ?1",
    nowIso,
  );

  const deviceLinks = await deleteCount(
    env,
    `DELETE FROM ordax_product_device_links
     WHERE revoked_at IS NOT NULL AND revoked_at < ?1`,
    inactiveAuthzCutoff,
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
    inactiveAuthzCutoff,
  );

  return {
    artifacts,
    multipart_uploads: multipartUploads,
    audits,
    jobs,
    pairings,
    device_links: deviceLinks,
    grants,
  };
}
