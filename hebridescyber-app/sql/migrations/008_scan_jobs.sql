-- Free-tier job queue for scheduled/bulk scanning: a Postgres table plus a
-- SKIP LOCKED claim function, worked by ephemeral GitHub Actions runners
-- instead of a long-lived container or Redis — see docs/PLATFORM-ROADMAP.md
-- §4 for why (Azure Static Web Apps + Consumption Functions can't run
-- either, and this repo is deliberately kept free-tier).
--
-- Scope: this queue only replaces the SCHEDULED monitoring path
-- (.github/workflows/scheduled-scans.yml). The dashboard's synchronous
-- "Run scan" button still calls src/functions/run-scan directly — that path
-- already works within the Function's timeout for every check that exists
-- today, and changing its UX (instant → "queued") is a separate product
-- decision this migration doesn't make.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

create table if not exists public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  target_url text not null,
  status text not null default 'pending' check (status in ('pending', 'running', 'completed', 'failed')),
  claimed_at timestamptz,
  -- Free-form identifier for whichever Actions run/shard claimed this job —
  -- debugging aid only, nothing parses it.
  claimed_by text,
  attempts int not null default 0,
  last_error text,
  -- Set once executeScan() has created the resulting scans row. Nullable:
  -- a failed job (e.g. SSRF check rejected the target) never gets one.
  scan_id uuid references public.scans (id) on delete set null,
  created_at timestamptz not null default now()
);

-- Only pending jobs are ever scanned by claim_scan_job — a plain index
-- (not partial) so it stays useful for the admin/debug queries too, but the
-- claim function's own ORDER BY + LIMIT keeps a claim cheap regardless.
create index if not exists scan_jobs_status_created_idx on public.scan_jobs (status, created_at);

alter table public.scan_jobs enable row level security;

drop policy if exists "Users can view their own scan jobs" on public.scan_jobs;
create policy "Users can view their own scan jobs"
  on public.scan_jobs for select
  using (owner = auth.uid());

-- Deliberately no insert/update/delete policy — enqueueing and claiming both
-- happen server-side only (service role), via
-- src/scripts/enqueue-scheduled-scans.ts and src/scripts/run-queued-scan-jobs.ts.

-- ---------------------------------------------------------------------------
-- claim_scan_job(): atomic "give me the next job, mark it running"
-- ---------------------------------------------------------------------------
-- Supabase's JS client can't express `FOR UPDATE SKIP LOCKED` through the
-- normal query builder (PostgREST doesn't support locking clauses), so the
-- select-and-claim has to happen inside a single plpgsql function called via
-- RPC — the standard way to get this from supabase-js. SKIP LOCKED is what
-- makes it safe for multiple worker shards to call this concurrently without
-- two of them ever claiming the same row.
create or replace function public.claim_scan_job(worker_id text)
returns table (id uuid, owner uuid, target_url text)
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
    returning scan_jobs.id, scan_jobs.owner, scan_jobs.target_url;
end;
$$;

-- Callable only via the service-role key (scripts run in CI, never the
-- browser) — no grant to `authenticated`/`anon` needed or wanted here,
-- unlike caller_team_ids()/is_caller_team_owner() in 007_teams.sql, which
-- exist specifically to be called *by* those roles.
