-- Migration 049: attack-surface change monitoring.
--
-- After each completed scan, src/lib/attackSurfaceMonitor.ts tells the owner
-- about two kinds of change:
--   1. new hostnames: names under the site's domain whose first certificate
--      in Certificate Transparency logs was issued since the previous scan
--      (or in the last 14 days). A certificate for a subdomain nobody knew
--      about is the classic sign of shadow IT, or of someone else using the
--      domain;
--   2. changes to the domain's NS, MX, SPF and DMARC records, where an
--      unexpected change can mean a hijacked domain or broken email.
--
-- asset_inventory.notified_at: when the hostname stopped being pending,
-- either reported to the owner or recorded as already known (no evidence it
-- was new). Existing rows are backfilled as known, so the first run after
-- this migration doesn't treat every hostname ever seen as pending.
--
-- dns_snapshots: the last NS/MX/SPF/DMARC values seen per (owner, registrable
-- domain from the Public Suffix List), so www.example.com and example.com
-- share one. known_fields lists the fields that have ever answered; only
-- those values mean anything (NULL = the domain publishes no such record). A
-- field that couldn't be looked up keeps its value and is never a change. A
-- change is claimed by advancing the row only if captured_at is still what
-- was read, and released (put back) if no channel delivered it, so two scans
-- of the same domain can't both send it and a failed alert is retried.
--
-- Owners can read their own rows; only the service role writes.
--
-- Idempotent — safe to re-run.

-- The backfill runs only when the column is first added: on a re-run it
-- would mark genuinely pending hostnames as already known.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'asset_inventory' AND column_name = 'notified_at'
  ) THEN
    ALTER TABLE public.asset_inventory ADD COLUMN notified_at timestamptz;
    UPDATE public.asset_inventory SET notified_at = first_seen_at;
  END IF;
END $$;

-- The monitor reads an owner's unreported hostnames per site after every scan.
CREATE INDEX IF NOT EXISTS asset_inventory_pending_idx
  ON public.asset_inventory (owner, target_url)
  WHERE notified_at IS NULL;

CREATE TABLE IF NOT EXISTS public.dns_snapshots (
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_host text NOT NULL,
  ns text[],
  mx text[],
  spf text,
  dmarc text,
  known_fields text[] NOT NULL DEFAULT '{}',
  captured_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, target_host)
);

ALTER TABLE public.dns_snapshots ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own DNS snapshots" ON public.dns_snapshots;
CREATE POLICY "Users can view their own DNS snapshots"
  ON public.dns_snapshots FOR SELECT
  USING (auth.uid() = owner);
