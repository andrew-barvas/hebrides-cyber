-- API keys for the public REST API (/api/v1/*).
--
-- Lets customers trigger scans from CI, scripts, and the GitHub Action without
-- handling a Supabase session JWT. Additive only — nothing here alters an
-- existing table.
--
-- All statements are safe to re-run (IF NOT EXISTS guards each one), matching
-- the convention established in 002_improvements.sql.

-- ---------------------------------------------------------------------------
-- api_keys
-- ---------------------------------------------------------------------------
-- Only a SHA-256 hash of the key is stored. The plaintext is returned exactly
-- once, at creation, and is unrecoverable afterwards — so a database leak
-- cannot be replayed against the API.
--
-- key_prefix keeps the first few characters in plaintext purely so the
-- dashboard can show "hc_live_a1b2…" and let a user tell their keys apart.
create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text not null,
  key_hash text not null unique,
  key_prefix text not null,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

-- Every authenticated API request looks a key up by hash, so this index is on
-- the hot path. Partial: revoked keys are never matched, so they're not worth
-- indexing.
create index if not exists api_keys_key_hash_idx
  on public.api_keys (key_hash)
  where revoked_at is null;

create index if not exists api_keys_owner_idx on public.api_keys (owner);

alter table public.api_keys enable row level security;

-- Users can see and manage their own keys from the dashboard. Note these
-- policies deliberately never expose a way to read key_hash back usefully —
-- the hash is not reversible, and the plaintext was never stored.
drop policy if exists "Users can view their own API keys" on public.api_keys;
create policy "Users can view their own API keys"
  on public.api_keys for select
  using (owner = auth.uid());

drop policy if exists "Users can revoke their own API keys" on public.api_keys;
create policy "Users can revoke their own API keys"
  on public.api_keys for update
  using (owner = auth.uid())
  with check (owner = auth.uid());

drop policy if exists "Users can delete their own API keys" on public.api_keys;
create policy "Users can delete their own API keys"
  on public.api_keys for delete
  using (owner = auth.uid());

-- Inserts happen server-side only (via the service role), so the plaintext key
-- is generated and hashed somewhere the browser can't influence. No insert
-- policy is defined, by design.
