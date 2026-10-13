-- Migration 053: lookalike-domain / phishing monitoring.
--
-- src/lib/lookalikeDomainMonitor.ts periodically generates a small, bounded
-- set of domains that look like one character different from an owner's
-- own domain (a letter dropped/doubled/swapped, a hyphen inserted, a
-- different common TLD) and checks the real Certificate Transparency logs
-- (crt.sh) for each one. A candidate with a real certificate already issued
-- is reported — strong, freely-available evidence it is registered and
-- actively served, the classic setup for phishing or business-email-
-- compromise against the owner's brand.
--
-- Two tables, kept separate on purpose:
--   lookalike_domain_sweeps: one row per (owner, target domain), recording
--     only *when* a full candidate sweep last ran. A quiet domain with zero
--     findings still has a row here, so the next sweep is throttled
--     correctly even though lookalike_domains has nothing to show for it.
--   lookalike_domains: the findings ledger — only domains a sweep actually
--     found registered. notified_at follows the same convention as
--     asset_inventory.notified_at: null means "found, not yet reported."
--     Once a domain is known (a row exists at all, reported or not), it is
--     never re-alerted — a phishing domain usually stays registered.
--
-- Both owner-readable, service-role-write-only — these are produced by
-- server-side monitoring, not written by the client.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.lookalike_domain_sweeps (
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_domain text NOT NULL,
  swept_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, target_domain)
);

ALTER TABLE public.lookalike_domain_sweeps ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own lookalike-domain sweeps" ON public.lookalike_domain_sweeps;
CREATE POLICY "Users can view their own lookalike-domain sweeps"
  ON public.lookalike_domain_sweeps FOR SELECT
  USING (auth.uid() = owner);

CREATE TABLE IF NOT EXISTS public.lookalike_domains (
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  target_domain text NOT NULL,
  candidate_domain text NOT NULL,
  technique text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  notified_at timestamptz,
  UNIQUE (owner, candidate_domain)
);

ALTER TABLE public.lookalike_domains ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own lookalike domains" ON public.lookalike_domains;
CREATE POLICY "Users can view their own lookalike domains"
  ON public.lookalike_domains FOR SELECT
  USING (auth.uid() = owner);

CREATE INDEX IF NOT EXISTS lookalike_domains_pending_idx
  ON public.lookalike_domains (owner, target_domain)
  WHERE notified_at IS NULL;
