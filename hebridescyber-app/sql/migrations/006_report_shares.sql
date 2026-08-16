-- Shareable report links: a token-gated public URL for one scan report, so a
-- customer can share it with a client or auditor who has no login.
--
-- Additive only. All statements are safe to re-run, matching the convention
-- established in 002_improvements.sql / 004_api_keys.sql / 005_webhooks.sql.

-- ---------------------------------------------------------------------------
-- report_shares
-- ---------------------------------------------------------------------------
-- No owner column — ownership is derived by joining to scans, the same way
-- scan_results already does, since a share always belongs to exactly one scan.
create table if not exists public.report_shares (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  token text not null unique,
  expires_at timestamptz,
  revoked_at timestamptz,
  view_count integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists report_shares_token_idx
  on public.report_shares (token)
  where revoked_at is null;

alter table public.report_shares enable row level security;

-- Owner can see and revoke shares for their own scans (joined-ownership,
-- mirroring scan_results' policy exactly).
drop policy if exists "Users can view shares for their own scans" on public.report_shares;
create policy "Users can view shares for their own scans"
  on public.report_shares for select
  using (
    exists (
      select 1 from public.scans
      where scans.id = report_shares.scan_id
        and scans.owner = auth.uid()
    )
  );

drop policy if exists "Users can revoke shares for their own scans" on public.report_shares;
create policy "Users can revoke shares for their own scans"
  on public.report_shares for delete
  using (
    exists (
      select 1 from public.scans
      where scans.id = report_shares.scan_id
        and scans.owner = auth.uid()
    )
  );

-- Deliberately NO public select policy, and no insert policy for end users.
--
-- A public "not revoked and not expired" RLS policy here would be a real
-- vulnerability: `using()` filters every row for read access regardless of
-- the query's WHERE clause, so it would let anyone holding only the anon key
-- enumerate every customer's active share tokens via a plain `select *`, not
-- just look up the one token they already hold. Public viewing instead goes
-- through src/pages/api/reports/[token].ts, which uses the service-role
-- client and an explicit token match — the same trust model already used by
-- src/pages/api/badge/[scanId].ts. Inserts happen server-side only too, so
-- the token is generated somewhere the browser can't influence.
