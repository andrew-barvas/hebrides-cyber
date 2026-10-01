-- Migration 045: emerging-threat alerts.
--
-- One row per (owner, target host, CVE) when a vulnerability newly added to
-- CISA's Known Exploited Vulnerabilities catalog matches a technology and
-- version seen in that site's latest scan. Written only by the scheduled
-- job (src/scripts/check-emerging-threats.ts) with the service role; owners
-- can read their own rows. notified_at is stamped only after an alert was
-- actually delivered, so a failed send is retried on the next run and a
-- delivered one is never repeated.
--
-- confidence: 'affected' = detected version inside a vulnerable range;
-- 'possibly_affected' = product detected but its version unknown, or
-- installed from a distribution package (vendors backport fixes).
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.emerging_threat_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_host text NOT NULL,
  cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]+$'),
  confidence text NOT NULL CHECK (confidence IN ('affected', 'possibly_affected')),
  product text NOT NULL,
  detected_version text,
  kev_date_added date,
  scan_id uuid,
  matched_at timestamptz NOT NULL DEFAULT now(),
  notified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, target_host, cve_id)
);

CREATE INDEX IF NOT EXISTS emerging_threat_alerts_unnotified_idx
  ON public.emerging_threat_alerts (owner)
  WHERE notified_at IS NULL;

CREATE INDEX IF NOT EXISTS emerging_threat_alerts_owner_matched_idx
  ON public.emerging_threat_alerts (owner, matched_at DESC);

ALTER TABLE public.emerging_threat_alerts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own emerging threat alerts" ON public.emerging_threat_alerts;
CREATE POLICY "Users can view their own emerging threat alerts"
  ON public.emerging_threat_alerts FOR SELECT
  USING (auth.uid() = owner);
