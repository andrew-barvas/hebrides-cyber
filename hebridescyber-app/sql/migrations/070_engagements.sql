-- Migration 070: authorised engagements and signed scope
-- (docs/EXPLOITABILITY-ENGINE.md §6.1). An engagement is a booked, contracted,
-- time-boxed authorised test. Scope hosts are its signed, enumerated in/out list.
-- Written only by the service role; owners read their own. No FK to auth.users:
-- the record of what was authorised survives erasure (as 048 and 051). Idempotent.
--
-- Schema only. Nothing grants or runs anything because of these rows: the worker
-- gate in run-queued-scan-jobs.ts is unchanged, and an authorisation with no
-- engagement_id keeps working exactly as today.

CREATE TABLE IF NOT EXISTS public.engagements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL,
  reference text NOT NULL,                       -- human engagement ref on the contract
  state text NOT NULL DEFAULT 'booked',
  scan_profile text NOT NULL DEFAULT 'exposure',
  window_start timestamptz,
  window_end timestamptz,
  contract_signed_at timestamptz,
  contract_signed_by_name text,
  contract_signed_by_role text,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  closed_at timestamptz,
  aborted_at timestamptz,
  abort_reason text
);

ALTER TABLE public.engagements DROP CONSTRAINT IF EXISTS engagements_state_check;
ALTER TABLE public.engagements ADD CONSTRAINT engagements_state_check
  CHECK (state IN ('booked', 'scoped', 'authorised', 'in_window', 'reported', 'closed', 'aborted'));
ALTER TABLE public.engagements DROP CONSTRAINT IF EXISTS engagements_profile_check;
ALTER TABLE public.engagements ADD CONSTRAINT engagements_profile_check
  CHECK (scan_profile IN ('safe', 'exposure', 'offensive'));
ALTER TABLE public.engagements DROP CONSTRAINT IF EXISTS engagements_window_check;
ALTER TABLE public.engagements ADD CONSTRAINT engagements_window_check
  CHECK (window_start IS NULL OR window_end IS NULL OR window_end > window_start);

CREATE UNIQUE INDEX IF NOT EXISTS engagements_owner_reference ON public.engagements (owner, reference);

CREATE TABLE IF NOT EXISTS public.engagement_scope_hosts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  engagement_id uuid NOT NULL REFERENCES public.engagements(id) ON DELETE CASCADE,
  owner uuid NOT NULL,                           -- denormalised for a non-recursive RLS policy
  host text NOT NULL,                            -- normalised like authHostFromUrl
  included boolean NOT NULL,                     -- false = explicit out-of-scope entry
  trust_group text,                              -- chain mapper grouping; null = registrable domain
  added_by uuid NOT NULL,
  added_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS engagement_scope_one_active_host
  ON public.engagement_scope_hosts (engagement_id, host) WHERE removed_at IS NULL;

-- Link an authorisation to the engagement it was signed for (nullable: legacy
-- Tier A rows have none and keep working exactly as today).
ALTER TABLE public.offensive_scan_authorizations ADD COLUMN IF NOT EXISTS engagement_id uuid
  REFERENCES public.engagements(id);

ALTER TABLE public.engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.engagement_scope_hosts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Owners read their own engagements" ON public.engagements;
CREATE POLICY "Owners read their own engagements"
  ON public.engagements FOR SELECT USING (auth.uid() = owner);

DROP POLICY IF EXISTS "Owners read their own engagement scope" ON public.engagement_scope_hosts;
CREATE POLICY "Owners read their own engagement scope"
  ON public.engagement_scope_hosts FOR SELECT USING (auth.uid() = owner);
-- No INSERT/UPDATE/DELETE policies: service role only.
