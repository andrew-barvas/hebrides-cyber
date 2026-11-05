-- Migration 069: local CPE -> CVE index (P1-3, service CVE matching).
--
-- A copy of NVD's CVE data, reduced to what version matching needs, so scans
-- match the services nmap identifies against known CVEs without calling the
-- rate-limited NVD API per scan. Built and kept current by the nightly
-- .github/workflows/cve-index-sync.yml (src/lib/cveIndexFeed.ts); read by
-- src/lib/cveIndex.ts, whose lookup API the device patch-audit agent (P1-5)
-- will reuse.
--
--   cve_records      one row per CVE: best CVSS score/vector, short summary.
--   cve_cpe_matches  one row per vulnerable, version-bounded CPE criterion
--                    (an exact version, or start/end bounds). Criteria naming
--                    every version are never stored: a name match alone is
--                    not evidence. Looked up by (vendor, product).
--   cve_index_state  single row: backfill progress and freshness. Lookups
--                    answer "error" until backfill_completed_at is set and
--                    while last_success_at is older than 7 days.
--
-- Public vulnerability data, not owner data, but service-role only in both
-- directions like tool_kill_switches: nothing in the browser reads it, and a
-- forged row could hide a CVE from every scan. RLS on, no policies.
--
-- replace_cve_batch() replaces each CVE in a batch atomically (delete, then
-- insert record and criteria), so a lookup never sees a CVE with half its
-- criteria. Executable by the service role only.
--
-- Idempotent — safe to re-run.

create table if not exists public.cve_records (
  cve_id text primary key check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  cvss_score numeric(3, 1) check (cvss_score is null or (cvss_score >= 0 and cvss_score <= 10)),
  cvss_version text,
  cvss_vector text,
  summary text,
  published_at timestamptz,
  last_modified_at timestamptz not null,
  vuln_status text
);

create table if not exists public.cve_cpe_matches (
  id bigint generated always as identity primary key,
  cve_id text not null references public.cve_records (cve_id) on delete cascade,
  part text not null check (part in ('a', 'o', 'h')),
  vendor text not null,
  product text not null,
  exact_version text,
  any_update boolean not null default false,
  start_including text,
  start_excluding text,
  end_including text,
  end_excluding text,
  conditional boolean not null default false,
  criteria text not null,
  constraint cve_cpe_matches_version_bounded check (
    exact_version is not null
    or start_including is not null or start_excluding is not null
    or end_including is not null or end_excluding is not null
  )
);

create index if not exists cve_cpe_matches_product_idx on public.cve_cpe_matches (vendor, product);
create index if not exists cve_cpe_matches_cve_idx on public.cve_cpe_matches (cve_id);

create table if not exists public.cve_index_state (
  id boolean primary key default true check (id),
  backfill_started_at timestamptz,
  backfill_next_index integer,
  backfill_completed_at timestamptz,
  last_modified_through timestamptz,
  last_success_at timestamptz,
  last_run_at timestamptz,
  last_error text,
  cve_count integer
);

alter table public.cve_records enable row level security;
alter table public.cve_cpe_matches enable row level security;
alter table public.cve_index_state enable row level security;

-- No policies on purpose: service-role only.

create or replace function public.replace_cve_batch(p_entries jsonb)
returns integer
language plpgsql
set search_path = public
as $$
declare
  inserted integer;
begin
  -- Rejected and re-analysed CVEs alike: drop the old rows (criteria cascade).
  delete from public.cve_records r
  using jsonb_array_elements(p_entries) e
  where r.cve_id = e ->> 'cve_id';

  insert into public.cve_records (cve_id, cvss_score, cvss_version, cvss_vector, summary, published_at, last_modified_at, vuln_status)
  select
    e ->> 'cve_id',
    (e ->> 'cvss_score')::numeric,
    e ->> 'cvss_version',
    e ->> 'cvss_vector',
    e ->> 'summary',
    (e ->> 'published_at')::timestamptz,
    (e ->> 'last_modified_at')::timestamptz,
    e ->> 'vuln_status'
  from jsonb_array_elements(p_entries) e
  where not coalesce((e ->> 'rejected')::boolean, false);

  insert into public.cve_cpe_matches (
    cve_id, part, vendor, product, exact_version, any_update,
    start_including, start_excluding, end_including, end_excluding, conditional, criteria
  )
  select
    e ->> 'cve_id',
    m ->> 'part',
    m ->> 'vendor',
    m ->> 'product',
    m ->> 'exact_version',
    coalesce((m ->> 'any_update')::boolean, false),
    m ->> 'start_including',
    m ->> 'start_excluding',
    m ->> 'end_including',
    m ->> 'end_excluding',
    coalesce((m ->> 'conditional')::boolean, false),
    m ->> 'criteria'
  from jsonb_array_elements(p_entries) e
  cross join lateral jsonb_array_elements(coalesce(e -> 'matches', '[]'::jsonb)) m
  where not coalesce((e ->> 'rejected')::boolean, false);

  get diagnostics inserted = row_count;
  return inserted;
end;
$$;

revoke all on function public.replace_cve_batch(jsonb) from public;
revoke all on function public.replace_cve_batch(jsonb) from anon, authenticated;
grant execute on function public.replace_cve_batch(jsonb) to service_role;
