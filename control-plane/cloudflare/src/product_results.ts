type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
}

// Enforce discovery scope in the server too: older agents may return every project.
export function scopeProductResult(action: unknown, result: unknown, projectsJson: unknown): unknown {
  if (action !== "projects.list" && action !== "workspace.repository_catalog") return result;
  const envelope = object(result);
  const data = object(envelope?.data);
  if (!envelope || !data) return null;
  let projects: unknown = null;
  try { projects = typeof projectsJson === "string" ? JSON.parse(projectsJson) : null; } catch { /* deny discovery */ }
  const allowed = new Set<string>(Array.isArray(projects) && projects.every((item) => typeof item === "string") ? projects : []);
  const entries = Array.isArray(data.projects) ? data.projects : [];
  const safeProjects = entries.flatMap((entry) => {
    const item = object(entry);
    if (!item || typeof item.slug !== "string" || !allowed.has(item.slug)) return [];
    const safe: JsonObject = {};
    for (const key of ["slug", "apps", "available", "allowed_branches", "preview_mode"]) {
      if (key in item) safe[key] = item[key];
    }
    const repository = object(item.repository);
    if (action === "workspace.repository_catalog" && repository) {
      const publicRepository: JsonObject = {};
      for (const key of ["is_repository", "branch", "remote", "has_origin", "dirty", "changed_entries", "status_available"]) {
        if (key in repository) publicRepository[key] = repository[key];
      }
      safe.repository = publicRepository;
    }
    return [safe];
  });
  const safeData: JsonObject = { projects: safeProjects };
  const selectedKey = action === "projects.list" ? "default_project" : "active_project";
  if (typeof data[selectedKey] === "string" && allowed.has(data[selectedKey] as string)) safeData[selectedKey] = data[selectedKey];
  if (object(data.agent_timings)) safeData.agent_timings = data.agent_timings;
  return { ok: envelope.ok, summary: envelope.summary, data: safeData };
}
