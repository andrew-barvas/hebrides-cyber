-- Migration 075: Lookout analyst reports (NEXT-BUILDS-DESIGN-2026-11.md, task 5).
--
-- An analyst (an admin, for now) turns a period of a Lookout customer's
-- results into a dated report with commentary; the customer reads it in the
-- portal and confirms they've read it (src/lib/lookoutReports.ts).
--
--   lookout_reports        one report: period, status, the analyst's summary
--   lookout_report_items   the findings it covers, in priority order, each
--                          with the analyst's note and business impact
--
-- status: draft → published → acknowledged. "acknowledged" means the customer
-- clicked "I've read this report"; it is not acceptance of any risk.
--
-- Service-role only in both directions: admins write through /api/admin/
-- lookout/reports, customers read published reports through /api/lookout/
-- reports, which check ownership. RLS on, no policies.
--
-- Idempotent — safe to re-run.

create table if not exists public.lookout_reports (
  id uuid primary key default gen_random_uuid(),
  customer uuid not null references auth.users (id) on delete cascade,
  period_start date not null,
  period_end date not null,
  status text not null default 'draft' check (status in ('draft', 'published', 'acknowledged')),
  summary text not null default '' check (length(summary) <= 20000),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  published_at timestamptz,
  acknowledged_at timestamptz,
  acknowledged_by uuid references auth.users (id) on delete set null,
  check (period_end >= period_start)
);

create index if not exists lookout_reports_customer_idx on public.lookout_reports (customer, created_at desc);

create table if not exists public.lookout_report_items (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.lookout_reports (id) on delete cascade,
  host text not null,
  check_id text not null,
  severity text not null,
  title text not null,
  included boolean not null default true,
  priority integer not null check (priority >= 1),
  analyst_note text not null default '' check (length(analyst_note) <= 5000),
  business_impact text not null default '' check (length(business_impact) <= 2000),
  fix_owner text not null default 'customer' check (fix_owner in ('customer', 'it_supplier', 'hosting_provider', 'unknown')),
  unique (report_id, host, check_id)
);

alter table public.lookout_reports enable row level security;
alter table public.lookout_report_items enable row level security;

-- No policies on purpose: service-role only.
