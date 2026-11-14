-- Migration 076: Google Workspace connections (NEXT-BUILDS-DESIGN-2026-11.md task 10).
--
-- A customer's Workspace super admin authorises our Google Cloud app with
-- read-only Admin SDK scopes (src/lib/workspaceConsent.ts). Unlike Microsoft
-- 365, Google issues a per-customer refresh token, which IS a secret: it is
-- sealed with credentialEncryption.ts before it is written (CLAUDE.md rule
-- 20) and listed in secretMigration.ts's STRING_SECRET_TARGETS.
--
-- One connection per owner. Service-role only in both directions, because
-- the row holds a secret column that browser code must never select: the
-- owner reads its status through /api/account/workspace-connect. RLS on, no
-- policies. Cascades from auth.users, so account erasure removes the row.
--
-- Idempotent — safe to re-run.

create table if not exists public.workspace_connections (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null unique references auth.users (id) on delete cascade,
  refresh_token text not null,
  scopes text not null default '',
  connected_at timestamptz not null default now(),
  last_checked_at timestamptz
);

alter table public.workspace_connections enable row level security;

-- No policies on purpose: service-role only.
