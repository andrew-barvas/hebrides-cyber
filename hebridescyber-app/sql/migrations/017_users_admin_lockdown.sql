-- Fixes a real privilege-escalation bug: 001_init.sql's UPDATE policy on
-- public.users checked only `id = auth.uid()` in its WITH CHECK clause —
-- who is updating the row — never WHICH COLUMNS changed. Its own comment
-- (and a TODO right above it) already admitted the real control was just
-- "the browser client only ever sends full_name/company_name," i.e. client
-- discipline, not a database guarantee. Any authenticated user could issue
-- `supabase.from("users").update({ is_admin: true }).eq("id", session.user.id)`
-- directly from the anon-key browser client and grant themselves admin —
-- src/lib/adminAuth.ts's requireAdmin() (and every /admin route/page) trusts
-- `profile?.is_admin` as its sole gate, so this was a full admin-panel
-- takeover, not a cosmetic gap.
--
-- Fix: the WITH CHECK clause now also requires the new row's is_admin to
-- equal the row's CURRENT is_admin value — i.e. this policy permits editing
-- every column except is_admin. A BEFORE UPDATE trigger (the alternative
-- the old comment considered "more bulletproof") is unnecessary once the
-- policy itself enforces this; RLS already re-evaluates WITH CHECK per row
-- on every UPDATE, so there's no gap between "checked" and "written."
-- is_admin can still only be set by service-role code (seed-users.ts, the
-- SQL editor), which already bypasses RLS entirely — this migration doesn't
-- change that path at all.
--
-- Verify manually against the Supabase SQL editor after running this
-- migration: as an authenticated non-admin user (via the anon key),
-- `update public.users set is_admin = true where id = auth.uid()` should
-- affect 0 rows under this policy (it affected 1 — silently granting
-- admin — under the old one). A true automated test of this would need a
-- real Postgres+RLS instance to exercise WITH CHECK, which this repo's
-- Vitest suite (mocked Supabase clients only) cannot do. src/lib/
-- adminAuth.test.ts adds real unit coverage for requireAdmin() itself
-- (the sole consumer of is_admin, previously untested) as the closest
-- verification achievable without a live database — it does not exercise
-- this RLS policy directly.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
drop policy if exists "Users can update their own profile" on public.users;
create policy "Users can update their own profile (non-admin fields)"
  on public.users for update
  using (id = auth.uid())
  with check (
    id = auth.uid()
    and is_admin = (select is_admin from public.users where id = auth.uid())
  );
