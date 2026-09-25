-- Migration 039: E-54 PagerDuty/Opsgenie credential columns.
-- Migration 028 extended ticket_integrations.provider's CHECK constraint to
-- accept 'pagerduty'/'opsgenie' and added a `region` column, but never added
-- anywhere to actually store the PagerDuty routing key or Opsgenie API key.
-- Reusing jira_api_token/linear_api_key would be semantically wrong (those
-- names are provider-specific in every other reader of this table), so these
-- get their own dedicated columns instead. Idempotent — safe to re-run,
-- matching migration 028's own style.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'ticket_integrations' AND column_name = 'pagerduty_routing_key'
  ) THEN
    ALTER TABLE public.ticket_integrations ADD COLUMN pagerduty_routing_key text;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'ticket_integrations' AND column_name = 'opsgenie_api_key'
  ) THEN
    ALTER TABLE public.ticket_integrations ADD COLUMN opsgenie_api_key text;
  END IF;
END $$;
