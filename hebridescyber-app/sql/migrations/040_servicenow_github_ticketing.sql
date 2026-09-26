-- Migration 040: ServiceNow and GitHub Issues as ticket providers, alongside
-- Jira and Linear. The provider clients already existed in
-- src/lib/ticketProviders.ts; this adds somewhere to store their credentials
-- and lets both tables accept the new provider values.
--
-- Credentials follow 013_ticket_integrations.sql's model: service-role writes
-- only (src/pages/api/account/ticket-integration.ts, after a live validation
-- call), and the browser only ever selects non-secret columns.
--
-- Idempotent — safe to re-run, matching 028/039.

-- ticket_integrations.provider: add servicenow + github to 028's list.
DO $$
BEGIN
  ALTER TABLE public.ticket_integrations DROP CONSTRAINT IF EXISTS ticket_integrations_provider_check;
  ALTER TABLE public.ticket_integrations
    ADD CONSTRAINT ticket_integrations_provider_check
    CHECK (provider IN ('jira', 'linear', 'servicenow', 'github', 'pagerduty', 'opsgenie'));
END $$;

-- ticket_links.provider: 016 created an inline check allowing only jira/linear.
DO $$
BEGIN
  ALTER TABLE public.ticket_links DROP CONSTRAINT IF EXISTS ticket_links_provider_check;
  ALTER TABLE public.ticket_links
    ADD CONSTRAINT ticket_links_provider_check
    CHECK (provider IN ('jira', 'linear', 'servicenow', 'github'));
END $$;

-- ServiceNow: instance URL (always https://<instance>.service-now.com — the
-- API route refuses anything else, which is also its SSRF guard) and a
-- Basic-auth integration user. Incidents only, for now.
ALTER TABLE public.ticket_integrations ADD COLUMN IF NOT EXISTS servicenow_instance_url text;
ALTER TABLE public.ticket_integrations ADD COLUMN IF NOT EXISTS servicenow_username text;
ALTER TABLE public.ticket_integrations ADD COLUMN IF NOT EXISTS servicenow_password text;

-- GitHub Issues: a token with issues:write on one repository.
ALTER TABLE public.ticket_integrations ADD COLUMN IF NOT EXISTS github_token text;
ALTER TABLE public.ticket_integrations ADD COLUMN IF NOT EXISTS github_owner text;
ALTER TABLE public.ticket_integrations ADD COLUMN IF NOT EXISTS github_repo text;
