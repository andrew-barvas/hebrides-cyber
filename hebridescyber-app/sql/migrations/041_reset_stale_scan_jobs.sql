-- 041: reset_stale_scan_jobs() — recover jobs orphaned by a killed runner
--
-- A scan_jobs row stuck in 'running' with claimed_at older than 30 minutes
-- means the GitHub Actions runner that claimed it was killed (OOM, timeout,
-- or runner restart) without writing a failed/completed status. Reset such
-- rows to 'pending' so the next worker run re-claims them automatically.
-- Also resets the linked scans row from 'running' back to 'queued' so the
-- dashboard no longer shows the scan as "scanning" when no work is happening.
--
-- Called at the start of run-queued-scan-jobs.ts before the claim loop.
-- Safe to run repeatedly — only touches rows that are genuinely stale.
-- Using language sql with a multi-CTE query to keep this editor-paste-safe
-- (no internal semicolons that Supabase's editor would truncate on).

create or replace function public.reset_stale_scan_jobs()
returns integer
language sql
as '
  with stale as (
    update public.scan_jobs
    set status = ''pending'',
        claimed_at = null,
        claimed_by = null
    where status = ''running''
      and claimed_at < now() - interval ''30 minutes''
    returning id, scan_id
  ),
  reset_scans as (
    update public.scans
    set status = ''queued''
    where id in (
      select scan_id from stale where scan_id is not null
    )
    and status = ''running''
    returning id
  )
  select count(*)::integer from stale
';
