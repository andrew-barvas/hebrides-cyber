-- Migration 047: fix two RLS policies that Postgres rejects with
-- "infinite recursion detected in policy for relation ..." (SQLSTATE 42P17).
--
-- Found by the real-Postgres RLS tests (tests/db/). Both policies contained a
-- sub-select on the very table they protect; Postgres refuses to plan those
-- no matter which command the inner query would use, so every statement that
-- needed the policy failed (closed, not open — nothing leaked, but the
-- feature was dead):
--
--   * 018: "Users can add monitored targets within their plan's cap"
--          (INSERT on monitored_targets) counted the caller's rows inline, so
--          the dashboard's "Add site" could never succeed from the browser.
--   * 017: "Users can update their own profile (non-admin fields)"
--          (UPDATE on users) read the caller's current is_admin inline, so no
--          client could update their own profile.
--
-- The self-read moves into a SECURITY DEFINER function with a pinned
-- search_path (same pattern as caller_team_ids() in 007_teams.sql). Both
-- functions take no argument and only ever look at auth.uid(), so calling
-- them via RPC leaks nothing about other users. Policy semantics are exactly
-- what 017/018 documented. All statements are safe to re-run.
--
-- Each half only applies where its target exists, so this is safe on a
-- database that never received 017 or 018 (a production database that has had
-- migrations applied by hand can be missing some): the policies below are only
-- replaced if they are present, and nothing is created that depends on a
-- missing function.

-- ---- users: profile update (017) -------------------------------------------------
create or replace function public.current_user_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce((select u.is_admin from public.users u where u.id = auth.uid()), false);
$$;

revoke all on function public.current_user_is_admin() from public;
grant execute on function public.current_user_is_admin() to authenticated;

do $mig$
begin
  if exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'users'
      and policyname = 'Users can update their own profile (non-admin fields)'
  ) then
    drop policy "Users can update their own profile (non-admin fields)" on public.users;
    create policy "Users can update their own profile (non-admin fields)"
      on public.users for update
      using (id = auth.uid())
      with check (
        id = auth.uid()
        and is_admin = public.current_user_is_admin()
      );
  end if;
end
$mig$;

-- ---- monitored_targets: add within the plan's cap (018) ----------------------------
-- Needs monitored_targets_cap() from 018; skipped entirely where 018 isn't applied.
do $mig$
begin
  if to_regprocedure('public.monitored_targets_cap(uuid)') is not null then
    create or replace function public.monitored_targets_can_add()
    returns boolean
    language sql
    stable
    security definer
    set search_path = public
    as $fn$
      select (select count(*) from public.monitored_targets mt where mt.owner = auth.uid())
             < public.monitored_targets_cap(auth.uid());
    $fn$;

    revoke all on function public.monitored_targets_can_add() from public;
    grant execute on function public.monitored_targets_can_add() to authenticated;

    drop policy if exists "Users can add monitored targets within their plan's cap" on public.monitored_targets;
    create policy "Users can add monitored targets within their plan's cap"
      on public.monitored_targets for insert
      with check (
        owner = auth.uid()
        and public.monitored_targets_can_add()
      );
  end if;
end
$mig$;
