-- Authenticated scanning, first slice: a customer-supplied session cookie or
-- Basic Auth credential for one monitored target, used to re-run the
-- passive header/cookie/CSP/CORS checks against an authenticated request —
-- not a full crawl-behind-login, not IDOR detection, not multi-step auth
-- (OAuth/MFA). See src/lib/scanners/authenticatedCheck.ts for what this
-- actually checks and why the scope stops there for now.
--
-- One row per monitored_targets row (not per owner, not a separate free-
-- text target_url) — authenticated scanning only makes sense for a target
-- already being scanned repeatedly, the same reasoning monitored_targets
-- itself exists for. Deleting the monitored target cascades away its
-- credential.
--
-- No client-writable RLS policy, same reasoning as repo_connections
-- (009_repo_connections.sql) and ticket_integrations
-- (013_ticket_integrations.sql): a session cookie or Basic Auth password is
-- a live credential, more sensitive than monitored_targets' own
-- client-writable target_url column, so only
-- src/pages/api/account/target-auth.ts (service role) may write a row.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
create table if not exists public.target_auth_credentials (
  id                   uuid primary key default gen_random_uuid(),
  owner                uuid not null references auth.users (id) on delete cascade,
  monitored_target_id  uuid not null references public.monitored_targets (id) on delete cascade,
  auth_type            text not null check (auth_type in ('cookie', 'basic')),
  cookie_value         text,
  basic_username       text,
  basic_password       text,
  created_at           timestamptz not null default now(),
  unique (monitored_target_id)
);

alter table public.target_auth_credentials enable row level security;

-- Read-only for the owner, and even then the UI only ever selects auth_type
-- + created_at to show connection status — never cookie_value/basic_username/
-- basic_password back to the browser once saved (Postgres RLS is row-level,
-- not column-level; this is an application-layer rule, same convention as
-- ticket_integrations).
drop policy if exists "Users can view their own target auth credentials" on public.target_auth_credentials;
create policy "Users can view their own target auth credentials"
  on public.target_auth_credentials for select
  using (owner = auth.uid());

-- No insert/update/delete policy — deliberately service-role-only.
