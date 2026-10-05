CREATE TABLE IF NOT EXISTS ordax_artifact_uploads (
  artifact_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  upload_id TEXT NOT NULL,
  storage_path TEXT NOT NULL UNIQUE,
  file_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  content_type TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(job_id) REFERENCES ordax_jobs(id) ON DELETE CASCADE,
  FOREIGN KEY(device_id) REFERENCES ordax_devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ordax_artifact_uploads_device_created_idx
  ON ordax_artifact_uploads(device_id, created_at);
