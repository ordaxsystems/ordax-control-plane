ALTER TABLE ordax_jobs ADD COLUMN report_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ordax_jobs_report_id_unique
  ON ordax_jobs(report_id)
  WHERE report_id IS NOT NULL;
