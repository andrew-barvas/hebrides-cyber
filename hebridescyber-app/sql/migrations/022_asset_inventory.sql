-- Asset inventory: every hostname (root domain + discovered subdomains)
-- seen across an owner's scans, with best-effort CMS type and cloud/CDN
-- hints attached to the root domain row. Populated as a side effect of
-- executeScan() (src/lib/assetInventory.ts's syncAssetInventory(), called
-- from src/lib/scanExecution.ts) — never blocks or fails a scan if the
-- sync itself errors.
--
-- unique(owner, hostname): a hostname is a hostname regardless of which of
-- an owner's targets a particular scan discovered it from — if two of an
-- owner's targets both surface the same subdomain, one row survives,
-- reflecting whichever scan synced it most recently. Acceptable for a
-- foundation-level inventory; not worth a composite key for that edge case.
--
-- first_seen_at is intentionally NOT included in the upsert payload
-- (src/lib/assetInventory.ts) so `on conflict ... do update` never touches
-- it — only an actual first INSERT sets it, via the column default.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

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

-- Same "shared security posture view" extension 007_teams.sql already
-- applied to scans/scan_results/monitored_targets.
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

-- No insert/update/delete policy — writes are service-role only, from
-- executeScan()'s post-scan sync step.
