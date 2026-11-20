-- Migration 080: remember which unlinked repository connections have been
-- emailed about it (next-10 task 9, src/lib/repoLinkReminder.ts).
--
-- Since 077 an unlinked repository (target_host null) is never scanned. Owners
-- with one get a single email asking them to pick its site; this column
-- records that, so the reminder is sent once per connection, never repeated.
--
-- Idempotent — safe to re-run.

alter table public.repo_connections add column if not exists link_reminder_sent_at timestamptz;
