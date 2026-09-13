-- Q4 #18 "Team Accounts" (docs/24-FEATURE-EXPANSION-SPEC.md). Widens
-- 007_teams.sql's team_members.role from a plain admin/read-only split
-- into two more roles with real write access to the owner's account:
--
--   admin      unchanged — invite/remove members, change roles
--   developer  NEW — may replay a scan, retest a finding, or create a
--              ticket on the owner's behalf (src/lib/teamAccess.ts's
--              callerCanActFor(), used by replay.ts/retest-finding.ts/
--              create-ticket.ts). May not touch billing, API keys,
--              webhooks, or team membership — those stay owner/admin-only,
--              enforced by those routes/pages never consulting this table.
--   auditor    NEW — read-only like 'member', plus the Executive Summary
--              (#13) and compliance exports (#12) views specifically;
--              enforced client-side via a viewMode flag (no new data this
--              role can see that 'member' couldn't already, so no RLS
--              change is needed for it).
--   member     unchanged default — read-only, exactly as before.
--
-- 'member' stays the default for existing rows; no backfill needed, and
-- every row that already has 'admin' or 'member' remains valid under the
-- widened constraint.
alter table public.team_members drop constraint if exists team_members_role_check;
alter table public.team_members
  add constraint team_members_role_check check (role in ('admin', 'developer', 'auditor', 'member'));
