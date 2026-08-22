-- Microsoft Teams webhook URL, stored per-subscription — parity with
-- slack_webhook_url (002_improvements.sql). Named ms_teams_webhook_url, not
-- teams_webhook_url, to avoid any confusion with the unrelated public.teams
-- table from 007_teams.sql (view-only account collaboration, nothing to do
-- with Microsoft Teams).
--
-- No new RLS policy needed: "Users can update their own subscription"
-- (002_improvements.sql) already covers every column on this row via
-- `owner = auth.uid()`, slack_webhook_url included — this column is no
-- different.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
alter table public.subscriptions
  add column if not exists ms_teams_webhook_url text;
