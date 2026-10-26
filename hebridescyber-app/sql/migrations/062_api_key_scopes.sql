-- Migration 062: scoped API keys.
--
-- A key's scopes limit what it may do on the public API (/api/v1). Every
-- existing key is backfilled with all scopes, so nothing already deployed in a
-- CI pipeline changes behaviour; new keys can be created narrower from the
-- dashboard. Sessions (the dashboard) are not scoped. Scope names mirror
-- API_SCOPES in src/lib/apiScopes.ts, which is the source of truth.
--
-- The check constraint pins the vocabulary so a typo can never silently
-- create a key that matches no scope. Idempotent — safe to re-run.

ALTER TABLE public.api_keys
  ADD COLUMN IF NOT EXISTS scopes text[] NOT NULL DEFAULT ARRAY['scans:read', 'scans:write', 'dependency:check'];

DO $$
BEGIN
  ALTER TABLE public.api_keys DROP CONSTRAINT IF EXISTS api_keys_scopes_valid;
  ALTER TABLE public.api_keys
    ADD CONSTRAINT api_keys_scopes_valid CHECK (
      cardinality(scopes) >= 1
      AND scopes <@ ARRAY['scans:read', 'scans:write', 'dependency:check']::text[]
    );
END $$;
