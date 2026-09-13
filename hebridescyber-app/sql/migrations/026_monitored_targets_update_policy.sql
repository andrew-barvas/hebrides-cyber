-- Adds the missing UPDATE RLS policy on monitored_targets. No migration
-- prior to this one ever created one — 018_monitored_targets_plan_cap.sql
-- added a SELECT and INSERT policy, and 001_init.sql created the table with
-- RLS enabled, but UPDATE was never granted. This means the scan-profile
-- selector UI (MonitoredTargets.tsx's ScanProfileConfig) silently no-ops
-- under RLS for every account, because the browser client uses the anon key
-- and RLS blocks the write.
--
-- Scoped to owner only — a team member viewing their owner's targets
-- (007_teams.sql's SELECT policy) should not be able to change the scan
-- profile; that's an owner decision.
--
-- Safe to re-run, matching the convention established in 002_improvements.sql
-- onward.

drop policy if exists "Users can update their own monitored targets" on public.monitored_targets;
create policy "Users can update their own monitored targets"
  on public.monitored_targets for update
  using (owner = auth.uid())
  with check (owner = auth.uid());
