-- Migration 060: DMARC aggregate (RUA) report storage (E-66).
--
-- One row per ingested DMARC aggregate report. Reports are POSTed to
-- /api/dmarc/ingest (authenticated by a per-owner ingest token), parsed by
-- src/lib/dmarcAggregate.ts into a per-source summary, and stored here. Written
-- only server-side (service role via the ingest route); owners read their own
-- rows. This is the half of the retired NCSC Mail Check that the passive
-- dns.ts DMARC check can't provide — who is actually sending as your domain and
-- whether it passes SPF/DKIM.
--
-- rows is the parsed per-source array (source_ip, count, disposition, dkim,
-- spf, header_from) stored as JSONB for the dashboard to render; the scalar
-- rollups (total/passing/failing) are denormalised so the panel and any
-- future alerting don't re-walk the array.
--
-- UNIQUE(owner, domain, report_id) makes re-POSTing the same report idempotent
-- (reporters retry); a null report_id can't participate in the constraint, so
-- those are coalesced to a synthetic key by the ingest route before insert.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.dmarc_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  domain text NOT NULL,
  org_name text NOT NULL,
  report_id text NOT NULL,
  date_begin timestamptz,
  date_end timestamptz,
  total_messages integer NOT NULL DEFAULT 0,
  passing_messages integer NOT NULL DEFAULT 0,
  failing_messages integer NOT NULL DEFAULT 0,
  rows jsonb NOT NULL DEFAULT '[]'::jsonb,
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, domain, report_id)
);

CREATE INDEX IF NOT EXISTS dmarc_reports_owner_received_idx
  ON public.dmarc_reports (owner, received_at DESC);

ALTER TABLE public.dmarc_reports ENABLE ROW LEVEL SECURITY;

-- Owner-read only; all writes are service-role (the ingest route), same as
-- emerging_threat_alerts / asset_inventory. Deliberately no insert/update/delete
-- policy — a client-forgeable report row could show false "all mail passing".
DROP POLICY IF EXISTS "Users can view their own dmarc reports" ON public.dmarc_reports;
CREATE POLICY "Users can view their own dmarc reports"
  ON public.dmarc_reports FOR SELECT
  USING (auth.uid() = owner);

-- Per-owner DMARC ingest token: the credential a mail/forwarding provider uses
-- to POST reports to /api/dmarc/ingest, mapped back to the owning account. One
-- row per owner, rotatable. Service-role write; owner may read their own token
-- so the dashboard can show the ingest URL to configure.
CREATE TABLE IF NOT EXISTS public.dmarc_ingest_tokens (
  owner uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  token text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.dmarc_ingest_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own dmarc ingest token" ON public.dmarc_ingest_tokens;
CREATE POLICY "Users can view their own dmarc ingest token"
  ON public.dmarc_ingest_tokens FOR SELECT
  USING (auth.uid() = owner);
