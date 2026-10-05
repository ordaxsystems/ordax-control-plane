CREATE TABLE IF NOT EXISTS ordax_product_grants (
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  space_id TEXT,
  device_id TEXT REFERENCES ordax_devices(id) ON DELETE CASCADE,
  actions_json TEXT NOT NULL,
  projects_json TEXT NOT NULL DEFAULT '[]',
  expires_at TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS ordax_product_grants_subject_created
  ON ordax_product_grants(subject_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ordax_product_grants_device_created
  ON ordax_product_grants(device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ordax_product_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  grant_id TEXT,
  device_id TEXT NOT NULL,
  space_id TEXT,
  action TEXT NOT NULL,
  project TEXT,
  phase TEXT NOT NULL CHECK (phase IN ('decision','result')),
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny')),
  reason TEXT NOT NULL,
  payload_fields_json TEXT NOT NULL DEFAULT '[]',
  result_ok INTEGER CHECK (result_ok IS NULL OR result_ok IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ordax_product_audit_subject_created
  ON ordax_product_audit(subject_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ordax_product_audit_grant_created
  ON ordax_product_audit(grant_id, created_at DESC);
