ALTER TABLE ordax_devices ADD COLUMN owner_product_subject_id TEXT;

CREATE INDEX IF NOT EXISTS idx_ordax_devices_owner_product_subject
  ON ordax_devices(owner_product_subject_id);
