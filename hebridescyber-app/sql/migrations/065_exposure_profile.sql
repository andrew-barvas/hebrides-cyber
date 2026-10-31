-- Migration 064: the `exposure` scan profile (managed exposure review).
--
-- Allows 'exposure' as a stored scan_profile / base_profile, so a monitored
-- target, a scan job or a bundle can select it. The profile itself is defined
-- in src/lib/scanProfiles.ts: open ports, services and known
-- misconfigurations only, with no injection testers, active scan or
-- proof-of-exploit re-checks. Same pattern as 051: drop the fixed-named
-- constraint and add it back with the wider list. The claim_scan_job() RPC row
-- type is unchanged, so no RPC redefinition is needed.
--
-- Idempotent — safe to re-run.

alter table public.monitored_targets drop constraint if exists monitored_targets_scan_profile_check;
alter table public.monitored_targets add constraint monitored_targets_scan_profile_check
  check (scan_profile in ('safe', 'full', 'api', 'cms', 'osint', 'exposure', 'offensive', 'ai-pentest'));

alter table public.scan_jobs drop constraint if exists scan_jobs_scan_profile_check;
alter table public.scan_jobs add constraint scan_jobs_scan_profile_check
  check (scan_profile is null or scan_profile in ('safe', 'full', 'api', 'cms', 'osint', 'exposure', 'offensive', 'ai-pentest'));

alter table public.scan_bundles drop constraint if exists scan_bundles_base_profile_check;
alter table public.scan_bundles add constraint scan_bundles_base_profile_check
  check (base_profile in ('safe', 'full', 'api', 'cms', 'osint', 'exposure', 'offensive', 'ai-pentest'));
