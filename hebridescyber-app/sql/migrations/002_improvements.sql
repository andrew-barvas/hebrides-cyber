-- Migration 002 — schema improvements
-- Run in Supabase SQL Editor after 001_init.sql.
-- All statements are safe to re-run (IF NOT EXISTS / DO blocks guard each one).

-- ─── blog_posts ──────────────────────────────────────────────────────────────
-- Rename body_markdown → body (consistent with admin API).
do $$ begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'blog_posts' and column_name = 'body_markdown'
  ) then
    alter table public.blog_posts rename column body_markdown to body;
  end if;
end $$;

-- New fields for admin CMS editor and public blog.
alter table public.blog_posts
  add column if not exists author_id uuid references auth.users (id),
  add column if not exists status text not null default 'draft'
    check (status in ('draft', 'published')),
  add column if not exists tags text[] not null default '{}',
  add column if not exists cover_image_url text,
  add column if not exists meta_description text,
  add column if not exists og_image text,
  add column if not exists updated_at timestamptz not null default now();

-- Back-fill status for rows that already have a published_at.
update public.blog_posts
  set status = 'published'
  where published_at is not null and status = 'draft';

-- Admin can read all posts (including drafts); anon key only sees published.
drop policy if exists "Anyone can read published posts" on public.blog_posts;
create policy "Anyone can read published posts"
  on public.blog_posts for select
  using (status = 'published' and published_at is not null);

-- ─── audit_logs ──────────────────────────────────────────────────────────────
-- Extend schema to match admin audit API expectations.
alter table public.audit_logs
  add column if not exists actor_email text,
  add column if not exists resource_type text,
  add column if not exists resource_id text;

-- ─── scans ───────────────────────────────────────────────────────────────────
-- Store the BullMQ job ID so the admin queue tab can correlate scans → jobs.
alter table public.scans
  add column if not exists job_id text;

-- ─── subscriptions ───────────────────────────────────────────────────────────
-- Persist current_period_end from Stripe for expiry checks.
-- Persist stripe_customer_id so billing portal can look it up.
alter table public.subscriptions
  add column if not exists current_period_end timestamptz;

-- Slack webhook URL stored per-subscription (Pro/Agency only).
alter table public.subscriptions
  add column if not exists slack_webhook_url text;

-- ─── users ───────────────────────────────────────────────────────────────────
-- Store the Stripe customer ID directly on the user profile as a fallback
-- lookup path (useful when subscriptions row doesn't exist yet).
alter table public.users
  add column if not exists stripe_customer_id text,
  add column if not exists onboarding_email_sent boolean not null default false;

-- Allow users to update their own slack_webhook_url on subscriptions.
drop policy if exists "Users can update their own subscription" on public.subscriptions;
create policy "Users can update their own subscription"
  on public.subscriptions for update
  using (owner = auth.uid())
  with check (owner = auth.uid());
