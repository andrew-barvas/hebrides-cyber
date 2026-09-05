-- Scan profiles: which of the extended-tool suite's tools run for a given
-- scan (src/lib/scanProfiles.ts). Replaces the old binary
-- ExecuteScanOptions.runExtendedTools flag (all-or-nothing) with a named
-- profile ("safe" | "full" | "api" | "cms" | "osint") stored per target,
-- with an optional per-job override.
--
-- monitored_targets.scan_profile defaults to 'full', preserving today's
-- behaviour for every existing row with zero backfill needed — a scheduled
-- scan of an already-registered target keeps running every extended tool
-- exactly as it did before this migration.
--
-- scan_jobs.scan_profile is nullable: an explicit per-job override (not
-- written by any code path yet in this slice) wins outright when set; null
-- means "inherit from the target this job is for, or default to safe if
-- there's no monitored_targets row" — see run-queued-scan-jobs.ts's
-- resolveScanConfig().
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

alter table public.monitored_targets
  add column if not exists scan_profile text not null default 'full'
    check (scan_profile in ('safe', 'full', 'api', 'cms', 'osint'));

alter table public.scan_jobs
  add column if not exists scan_profile text
    check (scan_profile is null or scan_profile in ('safe', 'full', 'api', 'cms', 'osint'));

-- CREATE OR REPLACE cannot change a function's OUT-parameter row type
-- (Postgres error 42P13) — adding scan_profile to the RETURNS TABLE means
-- the old signature has to be dropped first, same as
-- 010_claim_scan_job_scan_id.sql did when it added scan_id.
drop function if exists public.claim_scan_job(text);

create or replace function public.claim_scan_job(worker_id text)
returns table (id uuid, owner uuid, target_url text, scan_id uuid, scan_profile text)
language plpgsql
as $$
declare
  next_id uuid;
begin
  select scan_jobs.id into next_id
  from public.scan_jobs
  where scan_jobs.status = 'pending'
  order by scan_jobs.created_at
  for update skip locked
  limit 1;

  if next_id is null then
    return;
  end if;

  return query
    update public.scan_jobs
    set status = 'running', claimed_at = now(), claimed_by = worker_id, attempts = attempts + 1
    where scan_jobs.id = next_id
    returning scan_jobs.id, scan_jobs.owner, scan_jobs.target_url, scan_jobs.scan_id, scan_jobs.scan_profile;
end;
$$;
