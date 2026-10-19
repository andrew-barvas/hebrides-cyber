-- Migration 061: Cyber Essentials self-assessment answers.
--
-- The scan-derived half of CE readiness (cyberEssentialsReadiness.ts's
-- assessCeReadiness) already derives per-control pass/partial/fail evidence
-- from scan findings. This table captures the other half: the answers only the
-- customer can give (e.g. "are host-based firewalls enabled on all devices?")
-- that external scanning can't observe. ceSelfAssessment.ts's combineReadiness
-- merges the two into one readiness report.
--
-- One row per (owner, question_key). Written only server-side (service role via
-- /api/account/ce-assessment, after authenticateApiRequest); owners read their
-- own rows. The questionnaire holds no secrets, but it is the customer's own
-- compliance posture, so it is owner-scoped like every other per-account table.
--
-- UNIQUE(owner, question_key) makes the PUT an idempotent upsert — the client
-- re-sends the full answer set and each answer lands on its own row.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.ce_self_assessment (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  control text NOT NULL,
  question_key text NOT NULL,
  answer text NOT NULL CHECK (answer IN ('yes', 'no', 'partial', 'na')),
  note text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, question_key)
);

CREATE INDEX IF NOT EXISTS ce_self_assessment_owner_idx
  ON public.ce_self_assessment (owner);

ALTER TABLE public.ce_self_assessment ENABLE ROW LEVEL SECURITY;

-- Owner-read only; all writes are service-role (the ce-assessment route), same
-- as sla_policies / finding_lifecycle. Deliberately no insert/update/delete
-- policy for the client — the route authenticates the caller and writes with
-- supabaseAdmin, scoped to caller.ownerId.
DROP POLICY IF EXISTS "Users can view their own ce self assessment" ON public.ce_self_assessment;
CREATE POLICY "Users can view their own ce self assessment"
  ON public.ce_self_assessment FOR SELECT
  USING (auth.uid() = owner);
