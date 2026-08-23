-- Ledger linking one finding to the Jira/Linear issue created for it.
--
-- Until now nothing recorded that link at all: createJiraIssue() read the
-- issue key out of Jira's response purely to build a browse URL and then
-- discarded it, so clicking "Create ticket" twice on the same finding
-- opened two identical issues, and there was no way to find the ticket for
-- a finding that a later scan reported as fixed. Both duplicate detection
-- and auto-close need this row to exist.
--
-- Keyed on check_id, not the finding's title: titles routinely embed a
-- count or version that changes between scans ("Missing recommended
-- headers (3)"), which is the same reason src/lib/findingsDiff.ts matches
-- on check_id rather than text. This makes the ledger agree with the
-- new/fixed diff by construction rather than by coincidence.
--
-- Keyed on target_host rather than the raw target_url for the same reason
-- src/lib/scanReport.ts's findPreviousFindings() matches on hostname:
-- target_url is stored exactly as the user typed it, so protocol,
-- trailing-slash and case differences would otherwise hide a match between
-- two scans of what is plainly the same site — and would then open a
-- duplicate ticket for a finding already tracked.
--
-- provider is part of the unique key so an owner who has connected both
-- Jira and Linear gets an independent ledger entry per tracker, rather than
-- the first one to create a ticket blocking the other.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
create table if not exists public.ticket_links (
  id            uuid primary key default gen_random_uuid(),
  owner         uuid not null references auth.users (id) on delete cascade,
  provider      text not null check (provider in ('jira', 'linear')),
  -- Lowercased hostname of the scanned target, e.g. "example.com".
  target_host   text not null,
  -- Finding.checkId — the stable "<module>.<check-name>[:<key>]" identity.
  check_id      text not null,
  -- Jira: the issue key ("SEC-123"). Linear: the issue id (a uuid) — Linear's
  -- GraphQL API addresses issues by id, not by its human-facing identifier.
  issue_key     text not null,
  issue_url     text not null,
  first_seen_at timestamptz not null default now(),
  -- Bumped every time a scan re-detects this finding while the ticket is
  -- still open — drives the "open for N days" age column in reporting.
  last_seen_at  timestamptz not null default now(),
  -- Set when a later scan confirmed the finding gone AND the ticket was
  -- transitioned/commented as fixed. A closed row is kept rather than
  -- deleted so a regression of the same finding can be seen as a
  -- reoccurrence rather than looking like a brand-new issue.
  closed_at     timestamptz,
  unique (owner, provider, target_host, check_id)
);

create index if not exists ticket_links_owner_host_idx
  on public.ticket_links (owner, target_host);

alter table public.ticket_links enable row level security;

-- Read-only for the owner so the dashboard can show "already ticketed" state
-- next to a finding. All writes go through service-role code paths
-- (src/pages/api/scans/[id]/create-ticket.ts and the auto-close hook in
-- src/lib/scanExecution.ts), matching ticket_integrations' own
-- service-role-only write model — a client that could forge a ticket_links
-- row could suppress ticket creation for a real finding.
drop policy if exists "Users can view their own ticket links" on public.ticket_links;
create policy "Users can view their own ticket links"
  on public.ticket_links for select
  using (owner = auth.uid());

-- Auto-close opt-in. Deliberately defaults to false: transitioning an issue
-- in someone else's Jira is a real, visible side effect in a system this app
-- does not own, so a customer who connected Jira before this feature existed
-- must never find tickets moving on their board without having asked for it.
alter table public.ticket_integrations
  add column if not exists auto_close_enabled boolean not null default false;
