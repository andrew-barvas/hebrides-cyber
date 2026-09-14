-- 033: SIEM integration — forward audit events and scan findings to
-- external SIEM/log aggregation systems via syslog or webhook.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS siem_integrations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner           uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name            text NOT NULL DEFAULT 'Default SIEM',
  type            text NOT NULL CHECK (type IN ('webhook', 'syslog')),
  endpoint        text NOT NULL,  -- URL for webhook, host:port for syslog
  auth_header     text,           -- e.g. "Bearer <token>" for webhook auth
  format          text NOT NULL DEFAULT 'json' CHECK (format IN ('json', 'cef', 'leef')),
  event_types     text[] NOT NULL DEFAULT '{scan.completed,finding.new,finding.fixed}',
  enabled         boolean NOT NULL DEFAULT true,
  last_sent       timestamptz,
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, name)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'siem_integrations' AND policyname = 'owner_select'
  ) THEN
    ALTER TABLE siem_integrations ENABLE ROW LEVEL SECURITY;
    CREATE POLICY owner_select ON siem_integrations FOR SELECT USING (auth.uid() = owner);
    CREATE POLICY owner_insert ON siem_integrations FOR INSERT WITH CHECK (auth.uid() = owner);
    CREATE POLICY owner_update ON siem_integrations FOR UPDATE USING (auth.uid() = owner);
    CREATE POLICY owner_delete ON siem_integrations FOR DELETE USING (auth.uid() = owner);
  END IF;
END $$;
