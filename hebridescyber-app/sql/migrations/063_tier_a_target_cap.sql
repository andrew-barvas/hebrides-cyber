-- Tier A monitored-target cap.
--
-- monitored_targets_cap() (018) maps plan -> cap and falls to 0 for anything it
-- doesn't name. Tier A (the top plan, which includes Agency) wasn't named, so a
-- Tier A owner's cap was 0: the insert policy (047's monitored_targets_can_add)
-- refused every new monitored site, and the dashboard showed a cap of 0.
-- Tier A gets Agency's cap. Idempotent: create or replace.
create or replace function public.monitored_targets_cap(p_owner uuid)
returns integer
language sql
stable
as $$
  select coalesce(
    (
      select case s.plan
        when 'tier_a' then 15
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

grant execute on function public.monitored_targets_cap(uuid) to authenticated;
