-- Migration 051: Tier A opt-in offensive scanning.
--
-- Two things:
--
-- 1. Allow the `offensive` scan profile (and, finally, `ai-pentest`) as a
--    stored value. Migrations 020/021 constrained scan_profile/base_profile to
--    safe/full/api/cms/osint, so the Tier A profile could not be stored on a
--    monitored target, a scan job, or a bundle. We widen the three CHECK
--    constraints. The claim_scan_job() RPC row type is unchanged, so no RPC
--    redefinition is needed (unlike 020).
--
--    Being storable is NOT being runnable: run-queued-scan-jobs.ts refuses an
--    `offensive` profile unless the owner is on Tier A AND has a current row in
--    offensive_scan_authorizations for the target AND the domain is verified.
--
-- 2. offensive_scan_authorizations — the per-(owner, target) record that the
--    owner explicitly authorised offensive scanning of a host they control,
--    with the acknowledged scope. One ACTIVE authorization per (owner, host);
--    re-authorising replaces it. Written only by the service role (the consent
--    API route); owners can read their own. No foreign key to auth.users, so
--    the record of what was authorised survives account erasure (same reasoning
--    as deletion_requests in 048).
--
-- Idempotent — safe to re-run.

-- 1. Widen the profile CHECK constraints (drop the auto-named inline constraint
--    from 020/021, add a fixed-named one). Re-runnable: drop-if-exists then add.
alter table public.monitored_targets drop constraint if exists monitored_targets_scan_profile_check;
alter table public.monitored_targets add constraint monitored_targets_scan_profile_check
  check (scan_profile in ('safe', 'full', 'api', 'cms', 'osint', 'offensive', 'ai-pentest'));

alter table public.scan_jobs drop constraint if exists scan_jobs_scan_profile_check;
alter table public.scan_jobs add constraint scan_jobs_scan_profile_check
  check (scan_profile is null or scan_profile in ('safe', 'full', 'api', 'cms', 'osint', 'offensive', 'ai-pentest'));

alter table public.scan_bundles drop constraint if exists scan_bundles_base_profile_check;
alter table public.scan_bundles add constraint scan_bundles_base_profile_check
  check (base_profile in ('safe', 'full', 'api', 'cms', 'osint', 'offensive', 'ai-pentest'));

-- 2. Per-scan offensive authorization ledger.
CREATE TABLE IF NOT EXISTS public.offensive_scan_authorizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL,
  target_host text NOT NULL,
  authorized_by uuid NOT NULL,
  authorized_at timestamptz NOT NULL DEFAULT now(),
  -- The scope text the owner acknowledged (which attacks, which host). Kept so
  -- the audit record shows exactly what was consented to.
  scope text NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz
);

-- At most one active (not revoked) authorization per (owner, host); a repeat
-- authorisation must revoke the old row first, so the worker's "latest active"
-- lookup is unambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS offensive_auth_one_active_per_target
  ON public.offensive_scan_authorizations (owner, target_host)
  WHERE revoked_at IS NULL;

ALTER TABLE public.offensive_scan_authorizations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Owners read their own offensive authorizations" ON public.offensive_scan_authorizations;
CREATE POLICY "Owners read their own offensive authorizations"
  ON public.offensive_scan_authorizations FOR SELECT
  USING (auth.uid() = owner);
