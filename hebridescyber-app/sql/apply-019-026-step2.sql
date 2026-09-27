-- Migration step 2 of 2: claim_scan_job function (migration 020).
-- Run this AFTER apply-019-026-step1.sql has succeeded.
-- Paste this entire block into a new Supabase SQL Editor tab and click Run.
--
-- Uses language sql + a CTE instead of PL/pgSQL so there are NO semicolons
-- inside the function body — the Supabase SQL editor injects metadata comments
-- after the last semicolon it finds, which would truncate a PL/pgSQL body.
-- The FOR UPDATE SKIP LOCKED semantics are identical: the CTE locks one
-- pending row, the UPDATE claims it and returns the same columns.

drop function if exists public.claim_scan_job(text);

create or replace function public.claim_scan_job(worker_id text)
returns table (id uuid, owner uuid, target_url text, scan_id uuid, scan_profile text)
language sql
as '
  with claimed as (
    select scan_jobs.id
    from public.scan_jobs
    where scan_jobs.status = ''pending''
    order by scan_jobs.created_at
    for update skip locked
    limit 1
  )
  update public.scan_jobs
  set    status     = ''running'',
         claimed_at = now(),
         claimed_by = worker_id,
         attempts   = attempts + 1
  where  scan_jobs.id = (select claimed.id from claimed)
  returning scan_jobs.id,
            scan_jobs.owner,
            scan_jobs.target_url,
            scan_jobs.scan_id,
            scan_jobs.scan_profile
';
