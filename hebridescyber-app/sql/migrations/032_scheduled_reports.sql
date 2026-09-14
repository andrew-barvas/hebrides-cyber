-- 032: Scheduled report delivery — periodic email/webhook delivery of
-- scan summaries. Customers can schedule daily/weekly/monthly reports
-- for individual targets or all targets.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS scheduled_reports (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner       uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url  text,  -- NULL = all targets
  frequency   text NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
  format      text NOT NULL DEFAULT 'pdf' CHECK (format IN ('pdf', 'csv', 'json')),
  recipients  text[] NOT NULL DEFAULT '{}',
  enabled     boolean NOT NULL DEFAULT true,
  last_sent   timestamptz,
  next_due    timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'scheduled_reports' AND policyname = 'owner_select'
  ) THEN
    ALTER TABLE scheduled_reports ENABLE ROW LEVEL SECURITY;
    CREATE POLICY owner_select ON scheduled_reports FOR SELECT USING (auth.uid() = owner);
    CREATE POLICY owner_insert ON scheduled_reports FOR INSERT WITH CHECK (auth.uid() = owner);
    CREATE POLICY owner_update ON scheduled_reports FOR UPDATE USING (auth.uid() = owner);
    CREATE POLICY owner_delete ON scheduled_reports FOR DELETE USING (auth.uid() = owner);
  END IF;
END $$;
