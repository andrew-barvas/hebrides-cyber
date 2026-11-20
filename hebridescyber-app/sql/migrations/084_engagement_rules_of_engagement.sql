-- Migration 084: the rest of the engagement record (docs/EXPLOIT-PRODUCT-PLAN.md,
-- "Governance and authorisation workflow"). 070 holds the engagement, its window,
-- the signed contract and the scope list. This adds what an authorised test also
-- needs on record before it may start:
--   - the customer's organisation name as it appears on the contract,
--   - references to the signed contract and rules-of-engagement documents, and
--     who signed the rules of engagement and when,
--   - an expiry after which nothing active may run, whatever the state,
--   - the authorised contacts (who approved it, who to call, who can stop it),
--   - optional testing windows: slots inside the overall window, when set the
--     only times active work may run.
--
-- Same rules as 070: written only by the service role (admin routes), owners read
-- their own, no FK to auth.users so the record survives erasure. Idempotent.

ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS customer_name text;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS contract_document_ref text;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS roe_document_ref text;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS roe_document_sha256 text;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS roe_signed_at timestamptz;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS roe_signed_by_name text;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS roe_signed_by_role text;
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS expires_at timestamptz;

ALTER TABLE public.engagements DROP CONSTRAINT IF EXISTS engagements_roe_sha256_check;
ALTER TABLE public.engagements ADD CONSTRAINT engagements_roe_sha256_check
  CHECK (roe_document_sha256 IS NULL OR roe_document_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE public.engagements DROP CONSTRAINT IF EXISTS engagements_expiry_check;
ALTER TABLE public.engagements ADD CONSTRAINT engagements_expiry_check
  CHECK (expires_at IS NULL OR window_end IS NULL OR expires_at >= window_end);

CREATE TABLE IF NOT EXISTS public.engagement_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  engagement_id uuid NOT NULL REFERENCES public.engagements(id) ON DELETE CASCADE,
  owner uuid NOT NULL,                           -- denormalised for a non-recursive RLS policy
  kind text NOT NULL,
  name text NOT NULL,
  role text,
  email text,
  phone text,
  added_by uuid NOT NULL,
  added_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz
);
ALTER TABLE public.engagement_contacts DROP CONSTRAINT IF EXISTS engagement_contacts_kind_check;
ALTER TABLE public.engagement_contacts ADD CONSTRAINT engagement_contacts_kind_check
  CHECK (kind IN ('authoriser', 'technical', 'emergency'));
ALTER TABLE public.engagement_contacts DROP CONSTRAINT IF EXISTS engagement_contacts_reachable_check;
ALTER TABLE public.engagement_contacts ADD CONSTRAINT engagement_contacts_reachable_check
  CHECK (email IS NOT NULL OR phone IS NOT NULL);
CREATE INDEX IF NOT EXISTS engagement_contacts_engagement
  ON public.engagement_contacts (engagement_id) WHERE removed_at IS NULL;

CREATE TABLE IF NOT EXISTS public.engagement_testing_windows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  engagement_id uuid NOT NULL REFERENCES public.engagements(id) ON DELETE CASCADE,
  owner uuid NOT NULL,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  added_by uuid NOT NULL,
  added_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz
);
ALTER TABLE public.engagement_testing_windows DROP CONSTRAINT IF EXISTS engagement_testing_windows_order_check;
ALTER TABLE public.engagement_testing_windows ADD CONSTRAINT engagement_testing_windows_order_check
  CHECK (ends_at > starts_at);
CREATE INDEX IF NOT EXISTS engagement_testing_windows_engagement
  ON public.engagement_testing_windows (engagement_id, starts_at) WHERE removed_at IS NULL;

ALTER TABLE public.engagement_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.engagement_testing_windows ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Owners read their own engagement contacts" ON public.engagement_contacts;
CREATE POLICY "Owners read their own engagement contacts"
  ON public.engagement_contacts FOR SELECT USING (auth.uid() = owner);

DROP POLICY IF EXISTS "Owners read their own engagement testing windows" ON public.engagement_testing_windows;
CREATE POLICY "Owners read their own engagement testing windows"
  ON public.engagement_testing_windows FOR SELECT USING (auth.uid() = owner);
-- No INSERT/UPDATE/DELETE policies: service role only.
