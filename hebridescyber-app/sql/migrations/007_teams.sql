-- Teams: let a user share their dashboard (scans, reports, monitored
-- targets) with colleagues, read-only, without sharing their login.
--
-- Deliberately narrow scope. This does NOT touch how scans are created, and
-- does NOT share billing, API keys, webhooks, or share-link management —
-- those all stay owner-only. Every scan-creation code path (run-scan
-- Function, /api/v1/scans, the worker) keeps inserting `owner: callerId`
-- exactly as before; nothing about how a scan gets its owner changes.
--
-- The mechanism is additive RLS: existing SELECT policies on scans,
-- scan_results, and monitored_targets get an extra OR clause granting read
-- access to team members of the resource's owner, on top of the existing
-- "owner = auth.uid()" clause. No creation/write path needed a code change —
-- the dashboard's existing scan-list queries simply start returning more
-- rows once a team member is granted read access, the same way RLS already
-- worked for a single owner.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
--
-- Both tables are created up front, before any policy — teams' own read
-- policy needs to reference team_members (a team member can see the team
-- they belong to), so team_members must already exist by the time that
-- policy is created, not merely by the time this whole file finishes.

-- ---------------------------------------------------------------------------
-- teams
-- ---------------------------------------------------------------------------
-- One team per owner (unique on owner_id) — kept simple deliberately. A user
-- who wants two separate shared groups is out of scope for v1.
create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null unique references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- team_members
-- ---------------------------------------------------------------------------
-- role is a genuine (if small) permission distinction: 'admin' can invite and
-- remove other members; 'member' is read-only and cannot manage the team.
-- Neither role can create scans, manage API keys/webhooks, or see billing —
-- see the file header. The team owner (teams.owner_id) is implicitly a third,
-- always-superior role and is never a row in this table.
create table if not exists public.team_members (
  team_id uuid not null references public.teams (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'member' check (role in ('admin', 'member')),
  joined_at timestamptz not null default now(),
  primary key (team_id, user_id)
);

create index if not exists team_members_user_idx on public.team_members (user_id);

-- ---------------------------------------------------------------------------
-- caller_team_ids(): breaks the RLS recursion below
-- ---------------------------------------------------------------------------
-- teams' policy needs to check team_members, and team_members' own policy
-- needs to check team_members again (to see the rest of the roster, not just
-- the caller's own row) — a raw correlated subquery in either case re-enters
-- RLS on team_members, which re-evaluates the same policy, which re-enters
-- RLS again: "infinite recursion detected in policy for relation ...".
-- SECURITY DEFINER runs this function as its owner, which is exempt from RLS
-- (table owners bypass RLS by default), so the lookup inside it doesn't
-- re-trigger team_members' policies. Both recursive policies below call this
-- instead of querying team_members directly.
create or replace function public.caller_team_ids()
returns setof uuid
language sql
security definer
stable
set search_path = public
as $$
  select team_id from public.team_members where user_id = auth.uid();
$$;

grant execute on function public.caller_team_ids() to authenticated;

-- Same reason as caller_team_ids(): team_members' "team owner can view
-- members" policy needs to check teams.owner_id, and a raw subquery on teams
-- from within a team_members policy is the other half of the same cycle —
-- teams' own policy (below) already needs to check team_members. Routing
-- this specific lookup through a SECURITY DEFINER function too means neither
-- table's policies ever perform a plain (RLS-subject) query against the
-- other; every cross-table check happens inside a function that bypasses RLS
-- entirely, so there is no path left for the two tables' policies to
-- re-trigger each other.
create or replace function public.is_caller_team_owner(check_team_id uuid)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select exists (select 1 from public.teams where teams.id = check_team_id and teams.owner_id = auth.uid());
$$;

grant execute on function public.is_caller_team_owner(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- RLS: teams
-- ---------------------------------------------------------------------------
alter table public.teams enable row level security;

drop policy if exists "Users can view their own team" on public.teams;
create policy "Users can view their own team"
  on public.teams for select
  using (owner_id = auth.uid());

drop policy if exists "Team members can view the team they belong to" on public.teams;
create policy "Team members can view the team they belong to"
  on public.teams for select
  using (id in (select public.caller_team_ids()));

-- Inserts/deletes happen server-side only (src/pages/api/team.ts), using the
-- service role — so a "create team" request can validate the one-team-per-
-- owner rule and a clean error message, rather than surfacing a raw unique-
-- constraint violation to the user.

-- ---------------------------------------------------------------------------
-- RLS: team_members
-- ---------------------------------------------------------------------------
alter table public.team_members enable row level security;

drop policy if exists "Team owner can view their team's members" on public.team_members;
create policy "Team owner can view their team's members"
  on public.team_members for select
  using (public.is_caller_team_owner(team_members.team_id));

drop policy if exists "Members can view their own team's member list" on public.team_members;
create policy "Members can view their own team's member list"
  on public.team_members for select
  using (user_id = auth.uid() or team_id in (select public.caller_team_ids()));

-- Inserts/updates/deletes (invite, change role, remove) happen server-side
-- only, via src/pages/api/team/members.ts, using the service role — so an
-- invite can validate "does a user with this email exist" and enforce the
-- admin-can't-remove-the-owner rule with a clean error rather than relying
-- on RLS to reject it silently.

-- ---------------------------------------------------------------------------
-- Extend existing read policies to include team members
-- ---------------------------------------------------------------------------
-- scans: a team member can see everything the team owner can see. Re-created
-- with the exact name from 001_init.sql so this replaces it in place.
drop policy if exists "Users can view their scans" on public.scans;
create policy "Users can view their scans"
  on public.scans for select
  using (
    owner = auth.uid()
    or owner in (
      select teams.owner_id from public.teams
      join public.team_members on team_members.team_id = teams.id
      where team_members.user_id = auth.uid()
    )
  );

-- scan_results: mirrors scans' policy shape (joined-ownership), extended the
-- same way.
drop policy if exists "Users can view results for their own scans" on public.scan_results;
create policy "Users can view results for their own scans"
  on public.scan_results for select
  using (
    exists (
      select 1 from public.scans
      where scans.id = scan_results.scan_id
        and (
          scans.owner = auth.uid()
          or scans.owner in (
            select teams.owner_id from public.teams
            join public.team_members on team_members.team_id = teams.id
            where team_members.user_id = auth.uid()
          )
        )
    )
  );

-- monitored_targets: what's being watched is part of the shared security
-- posture view too.
drop policy if exists "Users can view their own monitored targets" on public.monitored_targets;
create policy "Users can view their own monitored targets"
  on public.monitored_targets for select
  using (
    owner = auth.uid()
    or owner in (
      select teams.owner_id from public.teams
      join public.team_members on team_members.team_id = teams.id
      where team_members.user_id = auth.uid()
    )
  );

-- Deliberately NOT extended: subscriptions, api_keys, webhooks,
-- report_shares, verifications. Those stay owner-only — a team shares the
-- security posture view, not account controls or billing.

-- users: a team member needs to read the team owner's profile row to show
-- "shared by owner@example.com" next to scans that aren't their own (see
-- ScanList.tsx's sharedByEmail) — 001_init.sql's policy only lets a user read
-- their own row, which would otherwise make that lookup silently return
-- nothing for every teammate.
drop policy if exists "Team members can view their team owner's profile" on public.users;
create policy "Team members can view their team owner's profile"
  on public.users for select
  using (
    id in (
      select teams.owner_id from public.teams
      join public.team_members on team_members.team_id = teams.id
      where team_members.user_id = auth.uid()
    )
  );
