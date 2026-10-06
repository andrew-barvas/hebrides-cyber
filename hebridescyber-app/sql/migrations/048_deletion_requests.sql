-- Migration 048: account deletion requests.
--
-- /privacy promises an erasure request is actioned within 30 days. Before
-- this, a request only wrote an audit_logs row and emailed the operator, so
-- nothing tracked the deadline. One row per request:
--   - written by POST /api/account/request-deletion (service role), at most
--     one pending row per owner, so a repeated click doesn't restart the clock;
--   - read by the daily check (src/scripts/check-deletion-requests.ts), which
--     emails the operator about requests due within 7 days or overdue
--     (reminded_at stops it repeating within a day);
--   - marked completed by the erasure itself (src/lib/accountErasure.ts).
--
-- No foreign key to auth.users on purpose: erasing the account must not
-- erase the record that the request was fulfilled. The row keeps only the
-- (now dangling) user id and the dates, no email or name.
--
-- Owners can read their own rows (the account page shows the due date);
-- only the service role writes.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.deletion_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'withdrawn')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  due_at timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
  reminded_at timestamptz,
  completed_at timestamptz,
  CHECK ((status = 'completed') = (completed_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS deletion_requests_one_pending_per_owner
  ON public.deletion_requests (owner)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS deletion_requests_pending_due_idx
  ON public.deletion_requests (due_at)
  WHERE status = 'pending';

ALTER TABLE public.deletion_requests ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own deletion requests" ON public.deletion_requests;
CREATE POLICY "Users can view their own deletion requests"
  ON public.deletion_requests FOR SELECT
  USING (auth.uid() = owner);
