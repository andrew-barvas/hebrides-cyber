-- 035: RBAC — formal role-based access control with permissions.
-- Maps org_members.role to granular permissions checked at API boundaries.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS rbac_permissions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role        text NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer', 'member')),
  resource    text NOT NULL,
  action      text NOT NULL CHECK (action IN ('create', 'read', 'update', 'delete', 'execute')),
  allowed     boolean NOT NULL DEFAULT true,
  UNIQUE (role, resource, action)
);

-- Default permission matrix
INSERT INTO rbac_permissions (role, resource, action, allowed) VALUES
  -- Owner: full access
  ('owner', '*', 'create', true), ('owner', '*', 'read', true),
  ('owner', '*', 'update', true), ('owner', '*', 'delete', true),
  ('owner', '*', 'execute', true),
  -- Admin: everything except org deletion and billing
  ('admin', 'scans', 'create', true), ('admin', 'scans', 'read', true),
  ('admin', 'scans', 'execute', true), ('admin', 'scans', 'delete', true),
  ('admin', 'members', 'create', true), ('admin', 'members', 'read', true),
  ('admin', 'members', 'update', true), ('admin', 'members', 'delete', true),
  ('admin', 'settings', 'read', true), ('admin', 'settings', 'update', true),
  ('admin', 'reports', 'create', true), ('admin', 'reports', 'read', true),
  ('admin', 'integrations', 'create', true), ('admin', 'integrations', 'read', true),
  ('admin', 'integrations', 'update', true), ('admin', 'integrations', 'delete', true),
  -- Analyst: run scans, view reports, manage findings
  ('analyst', 'scans', 'create', true), ('analyst', 'scans', 'read', true),
  ('analyst', 'scans', 'execute', true),
  ('analyst', 'reports', 'create', true), ('analyst', 'reports', 'read', true),
  ('analyst', 'findings', 'read', true), ('analyst', 'findings', 'update', true),
  ('analyst', 'integrations', 'read', true),
  -- Viewer: read-only
  ('viewer', 'scans', 'read', true), ('viewer', 'reports', 'read', true),
  ('viewer', 'findings', 'read', true), ('viewer', 'integrations', 'read', true),
  -- Member: same as viewer by default
  ('member', 'scans', 'read', true), ('member', 'reports', 'read', true),
  ('member', 'findings', 'read', true)
ON CONFLICT (role, resource, action) DO NOTHING;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'rbac_permissions' AND policyname = 'rbac_read'
  ) THEN
    ALTER TABLE rbac_permissions ENABLE ROW LEVEL SECURITY;
    CREATE POLICY rbac_read ON rbac_permissions FOR SELECT USING (true);
  END IF;
END $$;
