-- Extends claim_scan_job() to also return scan_id, so the worker
-- (src/scripts/run-queued-scan-jobs.ts) can tell an on-demand job (dashboard
-- "Run scan" button, scan_id pre-set by src/pages/api/run-scan.ts to an
-- already-existing scans row) apart from a scheduled job (enqueue-scheduled-
-- scans.ts inserts scan_jobs with scan_id left null; the worker creates the
-- scans row itself once it claims the job).
--
-- This exists because Azure Static Web Apps' Free-tier managed Functions
-- cannot run the scan pipeline synchronously inside the HTTP request without
-- risking the platform's own execution ceiling — confirmed via
-- `az staticwebapp functions show` refusing to run on Free SKU at all. The
-- fix moves on-demand scans onto the same scan_jobs queue the scheduled path
-- already uses, with .github/workflows/on-demand-scan.yml giving it a fast
-- trigger instead of waiting for the next daily cron.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

create or replace function public.claim_scan_job(worker_id text)
returns table (id uuid, owner uuid, target_url text, scan_id uuid)
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
    returning scan_jobs.id, scan_jobs.owner, scan_jobs.target_url, scan_jobs.scan_id;
end;
$$;
