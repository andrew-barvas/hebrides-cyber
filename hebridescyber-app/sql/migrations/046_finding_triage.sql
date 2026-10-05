-- Migration 046: finding triage (accept risk / false positive / snooze).
--
-- One row per (owner, target host, checkId) — the same identity
-- finding_lifecycle and findingsDiff use. Written only through
-- /api/findings/triage with the service role (audited); owners can read
-- their own rows. A separate table rather than columns on finding_lifecycle,
-- whose scan-time upserts write complete rows and would overwrite them.
--
-- state:
--   accepted_risk  — known and accepted (or, for third-party scripts,
--                    authorised); still counts towards the score.
--   false_positive — not a real issue; excluded from future scores.
--   snoozed        — hidden until expires_at; still counts towards the score.
-- A row whose expires_at has passed has no effect (checked at read time).
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.finding_triage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_host text NOT NULL,
  check_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('accepted_risk', 'false_positive', 'snoozed')),
  reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 3 AND 2000),
  expires_at timestamptz,
  created_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, target_host, check_id),
  CONSTRAINT finding_triage_snooze_needs_expiry CHECK (state <> 'snoozed' OR expires_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS finding_triage_owner_host_idx
  ON public.finding_triage (owner, target_host);

ALTER TABLE public.finding_triage ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own finding triage" ON public.finding_triage;
CREATE POLICY "Users can view their own finding triage"
  ON public.finding_triage FOR SELECT
  USING (auth.uid() = owner);
