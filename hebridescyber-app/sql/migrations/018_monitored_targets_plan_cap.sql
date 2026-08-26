-- E-01 (docs/ENHANCEMENTS.md): Basic/Pro subscribers had no way to
-- register a monitored target for scheduled scanning at all —
-- MonitoredTargets.tsx only rendered for plan === "agency". Scan cadence
-- itself (scanCadence.ts) was already plan-aware (Basic weekly, Pro/Agency
-- daily); the gap was purely UI access. Fixed alongside this migration —
-- see MonitoredTargets.tsx / dashboard/page.tsx.
--
-- That UI gate was also the *only* thing "enforcing" anything: this
-- table's insert policy (001_init.sql) has never checked plan or count —
-- any authenticated owner, Agency or not, could already insert unlimited
-- rows via a raw Supabase client call bypassing the UI entirely.
-- (001_init.sql's own comment beneath that policy — "no INSERT/UPDATE
-- policy is defined for regular users on purpose" — has been wrong since
-- the policy right above it was added; left as-is there per the "never
-- edit an already-applied migration" rule, corrected here instead.) This
-- migration adds the real, server-side cap that was missing for every
-- plan, not just the newly UI-exposed ones.
--
-- Cap numbers are a default pending explicit product confirmation, not a
-- researched decision — grounded only in marketing/03-pricing-page.md's
-- existing copy (Basic/Pro's copy describes a single site; Agency is the
-- only tier whose copy says "multi-site monitoring"): basic = 1, pro = 3,
-- agency = 15. Enforced in exactly one place (the function below), so
-- revising the numbers later is a one-line change here, not a
-- cross-codebase hunt.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.

create or replace function public.monitored_targets_cap(p_owner uuid)
returns integer
language sql
stable
as $$
  select coalesce(
    (
      select case s.plan
        when 'agency' then 15
        when 'pro' then 3
        when 'basic' then 1
        else 0
      end
      from public.subscriptions s
      where s.owner = p_owner and s.status = 'active'
    ),
    0
  );
$$;

-- No SECURITY DEFINER needed here, unlike caller_team_ids()/
-- is_caller_team_owner() in 007_teams.sql — this function only ever reads
-- p_owner's own subscriptions/monitored_targets rows, which the existing
-- "Users can view their own subscription" / "Users can view their own
-- monitored targets" SELECT policies already grant the calling user, so
-- there's no RLS-recursion or missing-privilege problem to work around.
grant execute on function public.monitored_targets_cap(uuid) to authenticated;

drop policy if exists "Users can manage their own monitored targets" on public.monitored_targets;
create policy "Users can add monitored targets within their plan's cap"
  on public.monitored_targets for insert
  with check (
    owner = auth.uid()
    and (select count(*) from public.monitored_targets mt where mt.owner = auth.uid())
        < public.monitored_targets_cap(auth.uid())
  );
