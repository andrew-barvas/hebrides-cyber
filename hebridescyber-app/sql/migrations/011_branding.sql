-- White-label branding fields for the Agency-tier PDF report.
--
-- Not DB-enforced to Agency-only (matches slack_webhook_url on this same
-- table, which sits unrestricted at the schema level too) — the Agency gate
-- is applied in application code (src/pages/api/account/branding.ts) at
-- write time, and again in generate-report.ts at render time. A downgraded
-- account simply stops having its branding rendered; the columns are left
-- populated so nothing is lost if they resubscribe to Agency later.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
alter table public.subscriptions
  add column if not exists brand_logo_url text,
  add column if not exists brand_name text;
