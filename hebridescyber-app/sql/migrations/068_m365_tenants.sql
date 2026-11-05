-- Migration 068: Microsoft 365 / Entra ID tenant connections (P1-4).
--
-- A customer's Global Admin grants our multi-tenant Entra app read-only
-- Microsoft Graph permissions through Microsoft's admin-consent flow
-- (src/pages/api/account/m365-connect.ts and m365-callback.ts). After that
-- the scanner reads the tenant's identity and mail settings with OUR app's
-- own credential (M365_CLIENT_ID / M365_CLIENT_SECRET, environment only), so
-- the one thing we need to remember about the customer is which tenant they
-- connected. This table stores the tenant ID and when consent happened. It
-- holds no secret, token or refresh token: there is nothing here to seal
-- under CLAUDE.md rule 20.
--
-- One tenant per owner. Two accounts may connect the same tenant (an agency
-- and its customer), so tenant_id is not unique on its own.
--
-- RLS: the owner may read their own row; every write goes through the API
-- routes with the service role, so a client can never point the scanner at
-- a tenant it did not consent through Microsoft.
--
-- Cascades from auth.users, so account erasure removes the row.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.m365_tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL,
  consented_at timestamptz NOT NULL DEFAULT now(),
  last_checked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner)
);

ALTER TABLE public.m365_tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own m365 tenant" ON public.m365_tenants;
CREATE POLICY "Users can view their own m365 tenant"
  ON public.m365_tenants FOR SELECT
  USING (auth.uid() = owner);
