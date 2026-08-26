-- Minimal "connect a repository" table. Created ahead of the full dependency-
-- manifest-scanning feature (see docs/decisions/ENGINEERING-LOG-2026-08.md) because
-- src/lib/scanners/secretScan.ts already needs somewhere to read a customer's
-- `owner/repo` from — it's a pure `{ githubRepo }` function by design so it
-- composes with this table without changes.
--
-- No UI writes to this yet. Until the connect-a-repo flow ships, a row is
-- added manually via the Supabase SQL editor:
--   insert into public.repo_connections (owner, github_repo)
--   values ('<user-uuid>', 'ownerOrg/reponame');
-- The customer must add the bot account (GITHUB_PAT's owner) as a repo
-- collaborator first — same precondition as generate-fix-pr.ts.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

create table if not exists public.repo_connections (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  -- "owner/repo" exactly as GitHub's API expects it — validated at the point
  -- of use (same regex as generate-fix-pr.ts), not here, so one validation
  -- rule lives in one place.
  github_repo text not null,
  connected_at timestamptz not null default now(),
  unique (owner, github_repo)
);

alter table public.repo_connections enable row level security;

drop policy if exists "Users can view their own repo connections" on public.repo_connections;
create policy "Users can view their own repo connections"
  on public.repo_connections for select
  using (owner = auth.uid());

-- No insert/update/delete policy yet — deliberately service-role-only until
-- the connect-a-repo API route (part of the dependency-manifest-scanning
-- feature) validates collaborator access before writing a row here.
