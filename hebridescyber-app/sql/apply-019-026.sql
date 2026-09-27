-- Combined migration script: 019 → 026 (no 023 — that number was never used).
-- Safe to run against a database that already has some of these applied —
-- every statement uses IF NOT EXISTS / OR REPLACE / DROP IF EXISTS.
--
-- Paste the entire file into the Supabase SQL Editor and click Run.
-- All seven migrations run as one transaction; if any statement errors,
-- the whole batch rolls back cleanly.

-- ============================================================
-- 019: contact lead-qualification fields
-- ============================================================
alter table public.contact_enquiries
  add column if not exists company text,
  add column if not exists team_size text
    check (team_size in ('solo', '2_10', '11_50', '51_200', '200_plus')),
  add column if not exists budget_range text
    check (budget_range in ('unsure', 'under_300', '300_800', '800_1800', '1800_plus'));

-- ============================================================
-- 020: scan profiles
-- ============================================================
alter table public.monitored_targets
  add column if not exists scan_profile text not null default 'full'
    check (scan_profile in ('safe', 'full', 'api', 'cms', 'osint'));

alter table public.scan_jobs
  add column if not exists scan_profile text
    check (scan_profile is null or scan_profile in ('safe', 'full', 'api', 'cms', 'osint'));

-- DROP required because CREATE OR REPLACE cannot change a function's RETURNS TABLE signature.
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

-- ============================================================
-- 021: scan bundles
-- ============================================================
create table if not exists public.scan_bundles (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text not null,
  base_profile text not null check (base_profile in ('safe', 'full', 'api', 'cms', 'osint')),
  -- Partial<Record<ExtendedToolName, boolean>> validated at point-of-use (src/lib/scanProfiles.ts)
  tool_overrides jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (owner, name)
);

alter table public.scan_bundles enable row level security;

drop policy if exists "Users can view their own scan bundles" on public.scan_bundles;
create policy "Users can view their own scan bundles"
  on public.scan_bundles for select
  using (owner = auth.uid());

alter table public.monitored_targets
  add column if not exists scan_bundle_id uuid references public.scan_bundles(id) on delete set null;

-- ============================================================
-- 022: asset inventory
-- ============================================================
create table if not exists public.asset_inventory (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  target_url text not null,
  hostname text not null,
  kind text not null check (kind in ('domain', 'subdomain')),
  cms_type text,
  cloud_hints jsonb not null default '[]'::jsonb,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (owner, hostname)
);

create index if not exists asset_inventory_owner_idx on public.asset_inventory (owner);

alter table public.asset_inventory enable row level security;

drop policy if exists "Users can view their own asset inventory" on public.asset_inventory;
create policy "Users can view their own asset inventory"
  on public.asset_inventory for select
  using (owner = auth.uid());

drop policy if exists "Team members can view their team owner's asset inventory" on public.asset_inventory;
create policy "Team members can view their team owner's asset inventory"
  on public.asset_inventory for select
  using (
    owner in (
      select teams.owner_id from public.teams
      join public.team_members on team_members.team_id = teams.id
      where team_members.user_id = auth.uid()
    )
  );

-- (023 was never assigned — sequence intentionally jumps 022 → 024)

-- ============================================================
-- 024: subscriptions lockdown — SECURITY CRITICAL
--
-- Without this, any signed-in user can run from their browser console:
--   supabase.from("subscriptions").update({ plan: "agency", status: "active" })
-- and grant themselves a paid plan for free, bypassing Stripe entirely.
-- This drops the client-writable UPDATE policy added in 002_improvements.sql.
-- ============================================================
drop policy if exists "Users can update their own subscription" on public.subscriptions;

-- ============================================================
-- 025: extended team roles (developer + auditor)
-- ============================================================
alter table public.team_members drop constraint if exists team_members_role_check;
alter table public.team_members
  add constraint team_members_role_check
    check (role in ('admin', 'developer', 'auditor', 'member'));

-- ============================================================
-- 026: monitored_targets UPDATE policy
-- Without this the scan-profile selector silently no-ops under RLS.
-- ============================================================
drop policy if exists "Users can update their own monitored targets" on public.monitored_targets;
create policy "Users can update their own monitored targets"
  on public.monitored_targets for update
  using (owner = auth.uid())
  with check (owner = auth.uid());

-- ============================================================
-- Verification queries — uncomment and run separately after the above
-- ============================================================
-- 1. Confirm 024 worked (should return 0 rows with cmd = 'UPDATE'):
--    select policyname, cmd from pg_policies
--    where tablename = 'subscriptions' order by policyname;
--
-- 2. Confirm 020 worked (should return 1 row):
--    select column_name from information_schema.columns
--    where table_name = 'monitored_targets' and column_name = 'scan_profile';
--
-- 3. Confirm 022 worked (should return 0, not an error):
--    select count(*) from public.asset_inventory;
--
-- 4. Confirm 026 worked (should include an UPDATE policy row):
--    select policyname, cmd from pg_policies
--    where tablename = 'monitored_targets' order by policyname;
