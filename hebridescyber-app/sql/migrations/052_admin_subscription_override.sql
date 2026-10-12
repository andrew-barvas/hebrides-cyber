-- Migration 052: Tier A storable as a subscription plan; admin plan override provenance.
--
-- 1. subscriptions.plan's CHECK constraint (001_init.sql) was never widened for
--    'tier_a' when Tier A was introduced in 051 — planAccess.ts, the Stripe
--    webhook (src/pages/api/stripe/webhook.ts) and the pricing page all treat
--    it as a valid plan value, but writing it would be rejected at the DB
--    today. Fix: widen the constraint, same drop-if-exists/fixed-name pattern
--    as 051.
--
-- 2. Admin: manual plan override (src/pages/api/admin/subscription.ts). Adds
--    provenance columns so an admin-granted plan is visibly distinct from a
--    Stripe-paid one, and so the admin UI/audit trail show who granted it and
--    why. A later real Stripe checkout for the same owner overwrites `plan`/
--    `status` and resets `source` back to 'stripe' (see the webhook's upsert/
--    update calls) — intended: a real payment supersedes a manual grant, not
--    the other way round.
--
-- Idempotent — safe to re-run.

alter table public.subscriptions drop constraint if exists subscriptions_plan_check;
alter table public.subscriptions add constraint subscriptions_plan_check
  check (plan in ('basic', 'pro', 'agency', 'tier_a'));

alter table public.subscriptions add column if not exists source text not null default 'stripe';
alter table public.subscriptions drop constraint if exists subscriptions_source_check;
alter table public.subscriptions add constraint subscriptions_source_check
  check (source in ('stripe', 'admin'));

-- Who granted a manual plan and why. Null for every Stripe-sourced row.
alter table public.subscriptions add column if not exists granted_by uuid;
alter table public.subscriptions add column if not exists grant_reason text;
