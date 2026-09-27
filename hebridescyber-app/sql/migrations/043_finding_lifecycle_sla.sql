-- Migration 043: finding lifecycle + remediation SLAs.
--
-- finding_lifecycle holds one row per (owner, target host, checkId): when a
-- finding was first seen, last seen, and resolved. Written only by the scan
-- worker (src/lib/findingLifecycle.ts, called from executeScan), never the
-- browser — a forged row could hide a real finding's age.
--
-- "Resolved" is only ever set by a scan that actually ran the check that
-- produced the finding: a passive on-demand scan runs none of the active
-- tools, so its silence says nothing about a nuclei/sqlmap finding. `source`
-- records which suite (or which extended tool) produced the row so that
-- rule can be applied. A finding that reappears within 7 days of being
-- resolved reopens the same row with its original first_seen_at, so a
-- flapping check can't reset its SLA clock.
--
-- sla_policies holds each account's remediation targets in days. No row =
-- the defaults in src/lib/slaMonitoring.ts (critical/high follow CISA BOD
-- 19-02's 15/30 days).
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.finding_lifecycle (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_host text NOT NULL,
  check_id text NOT NULL,
  severity text NOT NULL,
  title text NOT NULL,
  source text NOT NULL DEFAULT 'base',
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  last_scan_id uuid,
  resolved_at timestamptz,
  -- One alert per stage per occurrence; cleared when the row reopens fresh.
  sla_warned_at timestamptz,
  sla_breach_notified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, target_host, check_id)
);

CREATE INDEX IF NOT EXISTS finding_lifecycle_owner_open_idx
  ON public.finding_lifecycle (owner, target_host)
  WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS finding_lifecycle_owner_resolved_idx
  ON public.finding_lifecycle (owner, resolved_at)
  WHERE resolved_at IS NOT NULL;

ALTER TABLE public.finding_lifecycle ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own finding lifecycle" ON public.finding_lifecycle;
CREATE POLICY "Users can view their own finding lifecycle"
  ON public.finding_lifecycle FOR SELECT
  USING (auth.uid() = owner);

CREATE TABLE IF NOT EXISTS public.sla_policies (
  owner uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  critical_days integer NOT NULL DEFAULT 15 CHECK (critical_days BETWEEN 1 AND 365),
  high_days integer NOT NULL DEFAULT 30 CHECK (high_days BETWEEN 1 AND 365),
  medium_days integer NOT NULL DEFAULT 90 CHECK (medium_days BETWEEN 1 AND 365),
  low_days integer NOT NULL DEFAULT 180 CHECK (low_days BETWEEN 1 AND 365),
  warn_days integer NOT NULL DEFAULT 3 CHECK (warn_days BETWEEN 0 AND 30),
  alerts_enabled boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.sla_policies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own SLA policy" ON public.sla_policies;
CREATE POLICY "Users can view their own SLA policy"
  ON public.sla_policies FOR SELECT
  USING (auth.uid() = owner);
