-- Migration 085: shared fix plans (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md
-- idea 8).
--
-- An Agency user picks findings from one site's scan and shares them as a fix
-- plan with whoever does the work (the client, their IT supplier, a
-- developer), by link, with no account needed. Each item shows as fixed once
-- the owner's scans resolve it (finding_lifecycle.resolved_at, which already
-- follows the "a failed lookup is never fixed" rule); the person with the
-- link can mark an item done, which emails the owner to confirm it with
-- "Check it's fixed". The link never starts a scan.
--
--   fix_plans        one plan: the site, a title, the link's token hash,
--                    expiry and revocation
--   fix_plan_items   the findings in it, in order, with the fix text
--                    snapshotted when the plan was made, and when the person
--                    with the link marked it done
--
-- Only the SHA-256 of the link token is stored (as team_invites does), so a
-- database read never yields a working link.
--
-- Service-role only in both directions: owners manage plans through
-- /api/fix-plans, and the link is read through /api/plans/<token>. RLS on,
-- no policies.
--
-- Idempotent — safe to re-run.

create table if not exists public.fix_plans (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  target_host text not null check (length(target_host) between 1 and 253),
  source_scan_id uuid references public.scans (id) on delete set null,
  title text not null default '' check (length(title) <= 200),
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (expires_at > created_at)
);

create index if not exists fix_plans_owner_idx on public.fix_plans (owner, created_at desc);

create table if not exists public.fix_plan_items (
  plan_id uuid not null references public.fix_plans (id) on delete cascade,
  check_id text not null check (length(check_id) between 1 and 300),
  position integer not null check (position >= 1),
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  title text not null check (length(title) <= 500),
  remediation text not null default '' check (length(remediation) <= 6000),
  client_done_at timestamptz,
  client_note text not null default '' check (length(client_note) <= 1000),
  primary key (plan_id, check_id)
);

alter table public.fix_plans enable row level security;
alter table public.fix_plan_items enable row level security;

-- No policies on purpose: service-role only.
