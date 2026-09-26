-- Migration step 2 of 2: claim_scan_job function (migration 020).
-- Run this AFTER apply-019-026-step1.sql has succeeded.
-- Paste this entire block into a new Supabase SQL Editor tab and click Run.
--
-- DROP + CREATE required because CREATE OR REPLACE cannot change a
-- function's RETURNS TABLE signature (scan_profile column is new here).

drop function if exists public.claim_scan_job(text);

create or replace function public.claim_scan_job(worker_id text)
returns table (id uuid, owner uuid, target_url text, scan_id uuid, scan_profile text)
language plpgsql
as '
declare
  next_id uuid;
begin
  select scan_jobs.id into next_id
  from public.scan_jobs
  where scan_jobs.status = ''pending''
  order by scan_jobs.created_at
  for update skip locked
  limit 1;

  if next_id is null then
    return;
  end if;

  return query
    update public.scan_jobs
    set status = ''running'', claimed_at = now(), claimed_by = worker_id, attempts = attempts + 1
    where scan_jobs.id = next_id
    returning scan_jobs.id, scan_jobs.owner, scan_jobs.target_url, scan_jobs.scan_id, scan_jobs.scan_profile;
end;
';
