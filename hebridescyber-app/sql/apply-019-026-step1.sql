-- Migration step 1 of 2: DDL changes (019–026, excluding the PL/pgSQL function).
-- Paste this entire block into Supabase SQL Editor and click Run first.
-- Then run apply-019-026-step2.sql in a second tab.
--
-- Safe to re-run — every statement uses IF NOT EXISTS / DROP IF EXISTS.

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
-- 020: scan profiles (columns only — function is in step 2)
-- ============================================================
alter table public.monitored_targets
  add column if not exists scan_profile text not null default 'full'
    check (scan_profile in ('safe', 'full', 'api', 'cms', 'osint'));

alter table public.scan_jobs
  add column if not exists scan_profile text
    check (scan_profile is null or scan_profile in ('safe', 'full', 'api', 'cms', 'osint'));

-- ============================================================
-- 021: scan bundles
-- ============================================================
create table if not exists public.scan_bundles (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text not null,
  base_profile text not null check (base_profile in ('safe', 'full', 'api', 'cms', 'osint')),
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

-- (023 never existed — sequence jumps 022 → 024 by design)

-- ============================================================
-- 024: subscriptions lockdown — SECURITY CRITICAL
-- Removes the client-writable UPDATE policy. Without this, any signed-in
-- user can run: supabase.from("subscriptions").update({ plan: "agency" })
-- from the browser console and upgrade for free, bypassing Stripe entirely.
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
