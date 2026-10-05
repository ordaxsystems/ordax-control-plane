CREATE TABLE IF NOT EXISTS ordax_product_action_requests (
  request_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL UNIQUE REFERENCES ordax_jobs(id) ON DELETE CASCADE,
  subject_id TEXT NOT NULL,
  space_id TEXT,
  device_id TEXT NOT NULL REFERENCES ordax_devices(id) ON DELETE CASCADE,
  grant_id TEXT NOT NULL REFERENCES ordax_product_grants(id),
  action TEXT NOT NULL,
  project TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ordax_product_action_requests_subject_created
  ON ordax_product_action_requests(subject_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ordax_product_action_requests_job
  ON ordax_product_action_requests(job_id);
