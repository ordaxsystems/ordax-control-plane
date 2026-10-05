ALTER TABLE ordax_devices ADD COLUMN machine_binding_sha256 TEXT;
ALTER TABLE ordax_devices ADD COLUMN owner_github_user_id TEXT;
ALTER TABLE ordax_devices ADD COLUMN last_enrolled_at TEXT;
ALTER TABLE ordax_devices ADD COLUMN enrollment_window_started_at TEXT;
ALTER TABLE ordax_devices ADD COLUMN enrollment_count INTEGER NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS ordax_devices_machine_binding
  ON ordax_devices(machine_binding_sha256)
  WHERE machine_binding_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS ordax_devices_owner_github_user
  ON ordax_devices(owner_github_user_id)
  WHERE owner_github_user_id IS NOT NULL;
