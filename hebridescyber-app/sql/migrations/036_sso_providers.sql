-- 036: SSO/SAML/OIDC provider configuration per organization.
-- Enterprise orgs can configure their own identity provider for
-- single sign-on.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS sso_providers (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider_type     text NOT NULL CHECK (provider_type IN ('saml', 'oidc')),
  name              text NOT NULL DEFAULT 'SSO Provider',
  -- SAML fields
  entity_id         text,
  sso_url           text,
  certificate       text,
  -- OIDC fields
  client_id         text,
  client_secret     text,
  issuer_url        text,
  -- Shared
  enabled           boolean NOT NULL DEFAULT false,
  auto_provision    boolean NOT NULL DEFAULT true,
  default_role      text NOT NULL DEFAULT 'member' CHECK (default_role IN ('admin', 'analyst', 'viewer', 'member')),
  allowed_domains   text[] NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, provider_type)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'sso_providers' AND policyname = 'org_admin_select'
  ) THEN
    ALTER TABLE sso_providers ENABLE ROW LEVEL SECURITY;
    CREATE POLICY org_admin_select ON sso_providers FOR SELECT
      USING (org_id IN (
        SELECT org_id FROM org_members
        WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
      ));
    CREATE POLICY org_owner_manage ON sso_providers FOR ALL
      USING (org_id IN (
        SELECT org_id FROM org_members
        WHERE user_id = auth.uid() AND role = 'owner'
      ));
  END IF;
END $$;

COMMENT ON TABLE sso_providers IS 'SSO/SAML/OIDC configuration per organization. Enterprise feature.';
