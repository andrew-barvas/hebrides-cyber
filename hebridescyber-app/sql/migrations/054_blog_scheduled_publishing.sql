-- Migration 054: scheduled/future-dated blog publishing.
--
-- Adds a genuine third status, 'scheduled', rather than letting status
-- jump straight to 'published' with a future published_at. Every public
-- read of blog_posts — the RLS policy below, and every app-level query
-- (blog/page.tsx, blog/[slug]/page.tsx, sitemap.ts, feed.xml/route.ts) —
-- filters on status = 'published' by exact match, so a 'scheduled' row is
-- excluded everywhere automatically, with zero RLS/query changes and no
-- "forgot the date check" leak risk. A scheduled publish-time cron
-- (src/scripts/publish-scheduled-posts.ts) flips status to 'published'
-- once published_at is due, leaving published_at exactly as the admin set
-- it.
--
-- Idempotent — safe to re-run.

alter table public.blog_posts
  drop constraint if exists blog_posts_status_check;

alter table public.blog_posts
  add constraint blog_posts_status_check
  check (status in ('draft', 'published', 'scheduled'));
