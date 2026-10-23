-- Migration 062: bring-your-own uptime monitoring (UptimeRobot).
--
-- A customer connects their OWN UptimeRobot account (UptimeRobot's terms bar
-- reselling or white-labelling its monitoring), and we create and read
-- monitors there for their verified domains. Two tables:
--
--   uptime_integrations  one row per (owner, provider): the customer's API key,
--                        stored encrypted (credentialEncryption.ts; listed in
--                        secretMigration.ts's STRING_SECRET_TARGETS). Service
--                        role only: NO client policy at all, so even the owner's
--                        browser can never select the (encrypted) key. The UI
--                        learns "connected or not" from the API route.
--   uptime_monitors      one row per (owner, target_url, provider): which
--                        provider monitor covers which monitored target, plus
--                        the last status the sync saw. Owner can read their own
--                        rows; all writes are service role.
--
-- Both cascade from auth.users, so account erasure removes them.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.uptime_integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('uptimerobot')),
  api_key text NOT NULL,
  last_sync_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, provider)
);

ALTER TABLE public.uptime_integrations ENABLE ROW LEVEL SECURITY;
-- Deliberately no policies: service role only (it bypasses RLS).

CREATE TABLE IF NOT EXISTS public.uptime_monitors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_url text NOT NULL,
  provider text NOT NULL CHECK (provider IN ('uptimerobot')),
  external_id text NOT NULL,
  last_status text CHECK (last_status IN ('up', 'down', 'seems_down', 'paused', 'unknown')),
  last_status_at timestamptz,
  state_duration_seconds integer CHECK (state_duration_seconds IS NULL OR state_duration_seconds >= 0),
  last_checked_at timestamptz,
  -- Set when a "down" alert has been sent for the current outage, cleared on recovery,
  -- so one outage produces exactly one down message and one recovered message.
  down_alerted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, target_url, provider)
);

CREATE INDEX IF NOT EXISTS uptime_monitors_owner_idx ON public.uptime_monitors (owner);

ALTER TABLE public.uptime_monitors ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own uptime monitors" ON public.uptime_monitors;
CREATE POLICY "Users can view their own uptime monitors"
  ON public.uptime_monitors FOR SELECT
  USING (auth.uid() = owner);
