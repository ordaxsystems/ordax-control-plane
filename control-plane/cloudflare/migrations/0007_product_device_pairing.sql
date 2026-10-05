CREATE TABLE IF NOT EXISTS ordax_product_device_pairings (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES ordax_devices(id) ON DELETE CASCADE,
  secret_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  claimed_at TEXT,
  claimed_subject_id TEXT,
  claimed_space_id TEXT
);

CREATE INDEX IF NOT EXISTS ordax_product_device_pairings_device_created
  ON ordax_product_device_pairings(device_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ordax_product_device_pairings_expiry
  ON ordax_product_device_pairings(expires_at);

CREATE TABLE IF NOT EXISTS ordax_product_device_links (
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  space_id TEXT NOT NULL DEFAULT '',
  device_id TEXT NOT NULL REFERENCES ordax_devices(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS ordax_product_device_links_subject_device_space
  ON ordax_product_device_links(subject_id, device_id, space_id);

CREATE INDEX IF NOT EXISTS ordax_product_device_links_subject_created
  ON ordax_product_device_links(subject_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ordax_product_device_links_device_created
  ON ordax_product_device_links(device_id, created_at DESC);
