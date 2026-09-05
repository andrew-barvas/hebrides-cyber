-- Scan bundles: a saved, named combination of a base scan profile plus
-- per-tool overrides (e.g. "Full, but skip sqlmap and add nmap"), for
-- customers who don't want to accept one of the five canned profiles
-- (020_scan_profiles.sql) as-is. src/lib/scanProfiles.ts's
-- resolveToolConfig(profile, bundleOverrides) already accepts overrides as
-- its second parameter — built that way from the start specifically so
-- this migration needs no change to that function.
--
-- No UI or CRUD API route ships in this slice — deliberately. A row is
-- added manually via the Supabase SQL editor for now, same bootstrap
-- pattern 009_repo_connections.sql documents for repo_connections:
--   insert into public.scan_bundles (owner, name, base_profile, tool_overrides)
--   values ('<user-uuid>', 'Full minus sqlmap', 'full', '{"sqlmap": false}');
-- monitored_targets.scan_bundle_id stays null for every row until a later
-- slice adds a CRUD route to set it.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

create table if not exists public.scan_bundles (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text not null,
  base_profile text not null check (base_profile in ('safe', 'full', 'api', 'cms', 'osint')),
  -- Partial<Record<ExtendedToolName, boolean>> (src/lib/scanProfiles.ts) —
  -- validated at the point of use, not here, same "one validation rule
  -- lives in one place" precedent as repo_connections.github_repo.
  tool_overrides jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (owner, name)
);

alter table public.scan_bundles enable row level security;

drop policy if exists "Users can view their own scan bundles" on public.scan_bundles;
create policy "Users can view their own scan bundles"
  on public.scan_bundles for select
  using (owner = auth.uid());

-- No insert/update/delete policy yet — deliberately service-role-only,
-- same reasoning as repo_connections, until a CRUD API route exists.

alter table public.monitored_targets
  add column if not exists scan_bundle_id uuid references public.scan_bundles(id) on delete set null;
