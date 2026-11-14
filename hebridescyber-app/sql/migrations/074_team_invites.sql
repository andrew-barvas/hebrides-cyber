-- Migration 074: pending team invitations.
--
-- Inviting someone who has no account used to fail with "they need to sign
-- up first". Now it creates a pending invite with a one-time link
-- (/join/<token>) that the inviter sends; whoever signs in with the invited
-- email address can accept it within 14 days (src/lib/teamInvites.ts).
--
-- Only a SHA-256 hash of the token is stored, so a database read can't be
-- turned into a working link. Service-role only in both directions: the
-- owner and admins manage invites through /api/team/invites. RLS on, no
-- policies.
--
-- Idempotent — safe to re-run.

create table if not exists public.team_invites (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams (id) on delete cascade,
  email text not null check (email = lower(email) and position('@' in email) > 1),
  role text not null default 'member' check (role in ('admin', 'developer', 'auditor', 'member')),
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  invited_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '14 days'),
  accepted_at timestamptz
);

-- One pending invite per address per team; a new invite replaces the old one.
create unique index if not exists team_invites_pending_idx
  on public.team_invites (team_id, email)
  where accepted_at is null;

alter table public.team_invites enable row level security;

-- No policies on purpose: service-role only.
