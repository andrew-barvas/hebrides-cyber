-- Jira/Linear ticket-creation integration — lets a customer turn a finding
-- into a real ticket in their own issue tracker, alongside the existing
-- "AI-tailored fix" and remediation-PR options on the same finding.
--
-- One row per (owner, provider) rather than columns on subscriptions
-- (slack_webhook_url's precedent): these credentials are meaningfully more
-- sensitive than a webhook URL (a webhook can only post messages; a Jira/
-- Linear API token/key can read and write across the connected
-- project/team), so they get their own table with no client-writable RLS
-- policy — same reasoning and same shape as repo_connections
-- (009_repo_connections.sql): only src/pages/api/account/ticket-integration.ts
-- may write a row, and only after verifying the credentials actually work
-- against the real API first.
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
create table if not exists public.ticket_integrations (
  id               uuid primary key default gen_random_uuid(),
  owner            uuid not null references auth.users (id) on delete cascade,
  provider         text not null check (provider in ('jira', 'linear')),
  -- Jira Cloud: base_url like "https://yourteam.atlassian.net", email is the
  -- Atlassian account email the api_token belongs to (Jira Cloud auth is
  -- Basic email:api_token, not a bearer token).
  jira_base_url    text,
  jira_email       text,
  jira_api_token   text,
  jira_project_key text,
  -- Linear: a personal API key and the target team's id (not its human name
  -- — Linear's GraphQL API keys teams by id).
  linear_api_key   text,
  linear_team_id   text,
  created_at       timestamptz not null default now(),
  unique (owner, provider)
);

alter table public.ticket_integrations enable row level security;

-- Read-only for the owner, and even then the API routes that display
-- integration status select only non-secret columns (provider, base_url/
-- project_key/team_id, created_at) — never jira_api_token/linear_api_key
-- back to the browser once saved, an application-layer convention (Postgres
-- RLS is row-level, not column-level) matching src/lib/apiKeys.ts's
-- shown-once-at-creation precedent.
drop policy if exists "Users can view their own ticket integrations" on public.ticket_integrations;
create policy "Users can view their own ticket integrations"
  on public.ticket_integrations for select
  using (owner = auth.uid());

-- No insert/update/delete policy — deliberately service-role-only, same as
-- repo_connections: src/pages/api/account/ticket-integration.ts validates
-- the credentials against the real Jira/Linear API before a row is ever
-- written.
