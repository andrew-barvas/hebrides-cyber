-- Migration 086: device patch-audit agent (P1-5).
--
-- The Go agent in /agent reports a device's OS version, installed software
-- and pending updates to POST /api/agent/inventory with a per-device token.
-- The server checks the Cyber Essentials 14-day patch rule against it, with
-- CVE matching (OSV.dev and the CPE index) and end-of-life dates.
--
--   agent_devices      one enrolled device: its owner, a label, the SHA-256
--                      of its token (the plaintext is shown once, at issue),
--                      revocation, what it last reported about itself, and
--                      the latest patch-rule evaluation for the dashboard
--   agent_inventories  the reports themselves, newest few per device (the
--                      API trims older ones), as validated JSON
--
-- Only the token's hash is stored, as api_keys and fix_plans do, so a
-- database read never yields a working token.
--
-- Service-role only in both directions: owners manage devices through
-- /api/agent/devices, and agents write through /api/agent/inventory, which
-- validates every field first. RLS on, no policies.
--
-- Idempotent — safe to re-run.

create table if not exists public.agent_devices (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text not null check (length(name) between 1 and 80),
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  token_prefix text not null check (length(token_prefix) between 1 and 16),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  last_seen_at timestamptz,
  hostname text check (length(hostname) <= 200),
  os_family text check (os_family in ('windows', 'macos', 'linux')),
  os_name text check (length(os_name) <= 200),
  os_version text check (length(os_version) <= 100),
  agent_version text check (length(agent_version) <= 100),
  -- Pending update id -> the date this device first reported it, for updates
  -- whose source gives no release date (apt, dnf, softwareupdate).
  pending_first_seen jsonb not null default '{}'::jsonb,
  patch_status text not null default 'never_reported'
    check (patch_status in ('never_reported', 'passes', 'at_risk', 'fails', 'unknown')),
  evaluation jsonb,
  -- Latest CVE / end-of-life match (src/scripts/match-device-inventories.ts).
  last_match jsonb,
  matched_at timestamptz
);

create index if not exists agent_devices_owner_idx on public.agent_devices (owner, created_at desc);
-- The matching job's queue: active devices with a report newer than their match.
create index if not exists agent_devices_match_queue_idx on public.agent_devices (last_seen_at)
  where revoked_at is null and last_seen_at is not null;

create table if not exists public.agent_inventories (
  id bigint generated always as identity primary key,
  device_id uuid not null references public.agent_devices (id) on delete cascade,
  owner uuid not null references auth.users (id) on delete cascade,
  received_at timestamptz not null default now(),
  collected_at timestamptz,
  inventory jsonb not null check (octet_length(inventory::text) <= 3000000)
);

create index if not exists agent_inventories_device_idx on public.agent_inventories (device_id, received_at desc);

alter table public.agent_devices enable row level security;
alter table public.agent_inventories enable row level security;

-- No policies on purpose: service-role only.
