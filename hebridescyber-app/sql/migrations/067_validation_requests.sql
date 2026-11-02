-- Migration 067: "request validation" on a finding (the Scanner -> Lookout ->
-- Exploit ladder).
--
-- A customer asks for a human-run, authorised test of one finding they can see
-- in a scan report. This table records the request with a snapshot of the
-- finding as it was when asked, so the engagement conversation starts from the
-- same evidence the customer saw. It sends no traffic: any testing happens only
-- under a signed engagement (docs/EXPLOIT-PRODUCT-PLAN.md, OT-13).
--
-- Owner can read their own requests; ALL writes are service role, so a request
-- always comes from the validated API route and carries a real finding snapshot.
--
-- Cascades from auth.users, so account erasure removes them.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS public.validation_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  requested_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  scan_id uuid,
  target_host text NOT NULL CHECK (char_length(target_host) BETWEEN 1 AND 253),
  check_id text NOT NULL CHECK (char_length(check_id) BETWEEN 1 AND 500),
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 500),
  confirmed_exploitable boolean NOT NULL DEFAULT false,
  snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  note text CHECK (note IS NULL OR char_length(note) <= 1000),
  status text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'scoping', 'completed', 'declined', 'withdrawn')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS validation_requests_owner_idx ON public.validation_requests (owner, created_at DESC);

-- One open request per finding per site, so a double click or a repeat
-- request does not create a queue of duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS validation_requests_open_uniq
  ON public.validation_requests (owner, target_host, check_id)
  WHERE status IN ('requested', 'scoping');

ALTER TABLE public.validation_requests ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own validation requests" ON public.validation_requests;
CREATE POLICY "Users can view their own validation requests"
  ON public.validation_requests FOR SELECT
  USING (auth.uid() = owner);
