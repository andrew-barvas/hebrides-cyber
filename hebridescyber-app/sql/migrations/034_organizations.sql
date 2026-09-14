-- 034: Organizations / workspaces — multi-tenant entity model.
-- An organization groups users under a shared billing/admin context.
-- Users belong to orgs via org_members with a role.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS organizations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  slug          text NOT NULL UNIQUE,
  owner_id      uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  plan          text NOT NULL DEFAULT 'basic' CHECK (plan IN ('basic', 'pro', 'agency', 'enterprise')),
  billing_email text,
  logo_url      text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_members (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role        text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'analyst', 'viewer', 'member')),
  invited_by  uuid REFERENCES auth.users(id),
  joined_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, user_id)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'organizations' AND policyname = 'org_member_select'
  ) THEN
    ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
    CREATE POLICY org_member_select ON organizations FOR SELECT
      USING (id IN (SELECT org_id FROM org_members WHERE user_id = auth.uid()));
    CREATE POLICY org_owner_update ON organizations FOR UPDATE
      USING (owner_id = auth.uid());

    ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
    CREATE POLICY org_members_select ON org_members FOR SELECT
      USING (org_id IN (SELECT org_id FROM org_members m WHERE m.user_id = auth.uid()));
  END IF;
END $$;

COMMENT ON TABLE organizations IS 'Multi-tenant organization entity. Each user can belong to multiple orgs.';
COMMENT ON COLUMN org_members.role IS 'owner=full control, admin=manage members+settings, analyst=run scans+view reports, viewer=read-only, member=default';
