-- Migration 042: per-API-key IP allowlists.
--
-- A key with a non-empty allowed_cidrs only authenticates from those
-- addresses (src/lib/apiAuth.ts); empty means any address, so every existing
-- key keeps working unchanged. Set from the dashboard via PATCH /api/keys,
-- which validates entries with src/lib/ipAllowlist.ts.
--
-- last_blocked_ip / last_blocked_at record the most recent request refused
-- by the allowlist. A refused request gets the same 401 as a bad key (so a
-- leaked key doesn't confirm itself to whoever holds it), which leaves the
-- key's owner no other way to see that their CI moved to a new address.
--
-- Per key rather than per account on purpose: a CI key can be pinned to a
-- runner's egress range while a laptop key stays unrestricted. 037's
-- org-scoped ip_allowlist table predates this and nothing reads it.
--
-- Idempotent — safe to re-run.

ALTER TABLE public.api_keys ADD COLUMN IF NOT EXISTS allowed_cidrs text[] NOT NULL DEFAULT '{}';
ALTER TABLE public.api_keys ADD COLUMN IF NOT EXISTS last_blocked_ip text;
ALTER TABLE public.api_keys ADD COLUMN IF NOT EXISTS last_blocked_at timestamptz;

-- Mirrors MAX_ALLOWLIST_ENTRIES in src/lib/ipAllowlist.ts.
DO $$
BEGIN
  ALTER TABLE public.api_keys DROP CONSTRAINT IF EXISTS api_keys_allowed_cidrs_max;
  ALTER TABLE public.api_keys
    ADD CONSTRAINT api_keys_allowed_cidrs_max CHECK (cardinality(allowed_cidrs) <= 20);
END $$;
