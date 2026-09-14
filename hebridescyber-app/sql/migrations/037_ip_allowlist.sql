-- Migration 037: IP allowlist per organization
-- Stores CIDR ranges that restrict API access for an org's resources.

create table if not exists ip_allowlist (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  cidr text not null,
  label text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create index if not exists idx_ip_allowlist_org on ip_allowlist(org_id);

alter table ip_allowlist enable row level security;

create policy "Org owners and admins can manage IP allowlist"
  on ip_allowlist for all
  using (
    exists (
      select 1 from org_members
      where org_members.org_id = ip_allowlist.org_id
        and org_members.user_id = auth.uid()
        and org_members.role in ('owner', 'admin')
    )
  );
