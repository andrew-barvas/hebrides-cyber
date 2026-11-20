-- Migration 079: the weekly "one thing to fix" email (next-10 task 4,
-- src/lib/weeklyFixEmail.ts). One email a week with the single top-ranked
-- open finding, how to fix it and a link to check it's fixed.
--
-- On `subscriptions`, alongside the notify_* columns from 027:
--   notify_weekly_fix   the customer's opt-out (default on; the notification
--                       preferences section has the switch)
--   weekly_fix_*        what last week's email suggested and when it was
--                       sent, so the next one can say "last week's is fixed"
--                       and a re-run in the same week never sends twice
--
-- Idempotent — safe to re-run.

alter table public.subscriptions add column if not exists notify_weekly_fix boolean not null default true;
alter table public.subscriptions add column if not exists weekly_fix_sent_at timestamptz;
alter table public.subscriptions add column if not exists weekly_fix_host text;
alter table public.subscriptions add column if not exists weekly_fix_check_id text;
alter table public.subscriptions add column if not exists weekly_fix_title text;
