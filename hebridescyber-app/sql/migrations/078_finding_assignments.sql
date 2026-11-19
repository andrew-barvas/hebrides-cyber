-- Migration 078: assign findings to a person (IMPROVEMENT-REVIEW-2026-11.md
-- UX fix 8, "assign to" on the Findings Explorer).
--
-- A finding is addressed by (owner, target_host, check_id), the identity
-- finding_lifecycle and finding_triage already share, so an assignment holds
-- across scans of that site. The assignee is the account owner or one of
-- their team members (teams/team_members, 007 and 025); the API checks that
-- on every write, and a reader ignores an assignment whose assignee has
-- since left the team (src/lib/findingAssignments.ts).
--
-- Service-role only in both directions: reads go through GET /api/findings
-- and /api/findings/assign. RLS on, no policies. Cascades from auth.users,
-- so account erasure (owner or assignee) removes the row.
--
-- Idempotent — safe to re-run.

create table if not exists public.finding_assignments (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  target_host text not null,
  check_id text not null,
  assignee uuid not null references auth.users (id) on delete cascade,
  assigned_by uuid references auth.users (id) on delete set null,
  assigned_at timestamptz not null default now(),
  unique (owner, target_host, check_id)
);

create index if not exists finding_assignments_owner_idx on public.finding_assignments (owner);

alter table public.finding_assignments enable row level security;

-- No policies on purpose: service-role only.
