-- Webhooks: POST a signed event to a customer's URL when their scan
-- completes, so they can react in their own systems (CI gate, Slack,
-- PagerDuty) without polling GET /api/v1/scans/{id}.
--
-- Additive only. All statements are safe to re-run, matching the convention
-- established in 002_improvements.sql / 004_api_keys.sql.

-- ---------------------------------------------------------------------------
-- webhooks
-- ---------------------------------------------------------------------------
-- Unlike api_keys, `secret` is stored in plaintext, not hashed. An API key
-- only ever needs a one-way equality check ("does this match?"), but a
-- webhook secret has to be read back out to sign every outgoing delivery —
-- there's no way to HMAC a payload against a hash. The trade-off is
-- accepted the same way Stripe's own webhook signing secrets work: it's
-- server-side-only (no select policy ever returns it — see below), and it
-- can't authenticate *as* the customer the way a leaked API key could; at
-- worst a leaked secret lets someone forge a fake completion event.
--
-- Only one event exists today (scan.completed), so there's no `events`
-- filter column — that's for when a second event type actually exists, not
-- before.
create table if not exists public.webhooks (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text,
  url text not null,
  secret text not null,
  failure_count integer not null default 0,
  last_success_at timestamptz,
  last_failure_at timestamptz,
  disabled_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists webhooks_owner_idx on public.webhooks (owner);

alter table public.webhooks enable row level security;

-- Users can see and manage their own webhooks from the dashboard. The secret
-- IS included in a raw `select *` here — see src/pages/api/webhooks.ts,
-- which never selects that column for the list endpoint. RLS controls row
-- access, not column visibility, so keeping the secret out of the response
-- is an application-layer responsibility, matching how api_keys keeps
-- key_hash out of its list response despite RLS technically allowing it.
drop policy if exists "Users can view their own webhooks" on public.webhooks;
create policy "Users can view their own webhooks"
  on public.webhooks for select
  using (owner = auth.uid());

drop policy if exists "Users can delete their own webhooks" on public.webhooks;
create policy "Users can delete their own webhooks"
  on public.webhooks for delete
  using (owner = auth.uid());

-- Inserts and disable/failure-count updates happen server-side only (via the
-- service role) — inserts so the secret is generated somewhere the browser
-- can't influence, updates so a user can't zero out their own failure_count
-- or forge last_success_at. No insert/update policy is defined, by design.
