PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS ordax_devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_sha256 TEXT NOT NULL UNIQUE,
  scopes_json TEXT NOT NULL DEFAULT '["develop_heartbeat","develop_poll","develop_report","artifact_write"]',
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS ordax_jobs (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES ordax_devices(id) ON DELETE CASCADE,
  capability TEXT NOT NULL,
  payload_canonical_b64 TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','leased','running','succeeded','failed','cancelled')),
  effect_id TEXT NOT NULL,
  attempt_id TEXT,
  lease_id TEXT,
  execution_epoch INTEGER NOT NULL DEFAULT 0,
  agent_instance_id TEXT,
  boot_id TEXT,
  lease_expires_at TEXT,
  result_json TEXT,
  result_sha256 TEXT,
  error_code TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE INDEX IF NOT EXISTS ordax_jobs_device_status_created
  ON ordax_jobs(device_id, status, created_at);

CREATE TABLE IF NOT EXISTS ordax_job_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES ordax_jobs(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  message TEXT,
  progress_percent INTEGER,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ordax_job_events_job_id
  ON ordax_job_events(job_id, id);

CREATE TABLE IF NOT EXISTS ordax_artifacts (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES ordax_jobs(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES ordax_devices(id) ON DELETE CASCADE,
  storage_path TEXT NOT NULL UNIQUE,
  file_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  content_type TEXT,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  read_token_sha256 TEXT NOT NULL,
  read_expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ordax_artifacts_job_id
  ON ordax_artifacts(job_id);
