-- Migration 059: auto-create a public.users profile row for every new
-- auth.users row (magic-link, password, or future OAuth sign-up).
--
-- Before this, nothing in the application ever inserted into public.users
-- except src/scripts/seed-users.ts — a real new customer signing in via
-- magic link got an auth.users row with no matching public.users row.
-- company_name/is_admin reads then came back null, and the Stripe webhook's
-- welcome-email guard (`if (profile && !profile.onboarding_email_sent)` in
-- src/pages/api/stripe/webhook.ts) silently never sent the welcome email to
-- a single first-time customer, since `profile` was always null.
--
-- company_name, if supplied at sign-up (src/app/signup/page.tsx passes it as
-- auth metadata via signInWithOtp's `data` option), is read from
-- raw_user_meta_data so it's captured without a second write.
--
-- `on conflict do nothing`: idempotent if a profile row already exists by
-- some other path (e.g. the seed script, or re-running this migration).
--
-- Idempotent — safe to re-run.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.users (id, email, company_name)
  values (new.id, new.email, new.raw_user_meta_data->>'company_name')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Backfill: any auth.users row that predates this trigger (every production
-- account so far) and has no public.users row yet.
insert into public.users (id, email)
select u.id, u.email
from auth.users u
left join public.users pu on pu.id = u.id
where pu.id is null;
