-- 031: Scan windows — time-of-day restrictions for scheduled scanning.
-- Enterprise customers can restrict scans to specific time windows to
-- avoid scanning during business hours or peak traffic.
--
-- Idempotent: safe to re-run.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'monitored_targets' AND column_name = 'scan_window_start'
  ) THEN
    ALTER TABLE monitored_targets
      ADD COLUMN scan_window_start time DEFAULT NULL,
      ADD COLUMN scan_window_end   time DEFAULT NULL,
      ADD COLUMN scan_window_tz    text DEFAULT 'UTC';
  END IF;
END $$;

COMMENT ON COLUMN monitored_targets.scan_window_start IS 'Earliest time of day (in scan_window_tz) when scheduled scans may run. NULL = no restriction.';
COMMENT ON COLUMN monitored_targets.scan_window_end   IS 'Latest time of day (in scan_window_tz) when scheduled scans may run. NULL = no restriction.';
COMMENT ON COLUMN monitored_targets.scan_window_tz    IS 'IANA timezone for the scan window, e.g. Europe/London. Defaults to UTC.';
