-- Migration 086: "how you compare" score benchmarks
-- (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 4). Dark until the owner
-- sets SCORE_BENCHMARK_ENABLED (owner decision 6: aggregate use and the
-- privacy-notice line); nothing is written while it is off.
--
-- Two benchmarks, never mixed, because the scores come from different checks:
--   free check  the passive TLS / headers / email check on /check, compared
--               only with other free checks. instant_check_scores keeps the
--               score and when, nothing else: no site, no IP, no user.
--   full scan   a scan's score compared with the latest full-scan score of
--               every other site scanned in the window (one per owner and
--               host), read from the existing scans and scan_results.
--
-- Both functions return counts only (how many, how many scored lower), and
-- only to the service role: anon and signed-in users can't call them.
--
-- Idempotent — safe to re-run.

create table if not exists public.instant_check_scores (
  id bigserial primary key,
  checked_at timestamptz not null default now(),
  score smallint not null check (score between 0 and 100)
);

create index if not exists instant_check_scores_checked_at_idx on public.instant_check_scores (checked_at);

alter table public.instant_check_scores enable row level security;
-- No policies on purpose: service-role only.

create or replace function public.instant_check_score_counts(p_score integer, p_days integer)
returns table (total bigint, lower bigint)
language sql
stable
as $$
  select count(*)::bigint, count(*) filter (where score < p_score)::bigint
  from public.instant_check_scores
  where checked_at > now() - make_interval(days => greatest(1, least(p_days, 365)));
$$;

create or replace function public.scan_score_counts(p_score integer, p_days integer, p_exclude_owner uuid)
returns table (total bigint, lower bigint)
language sql
stable
as $$
  with latest as (
    select distinct on (s.owner, lower(substring(s.target_url from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)')))
      r.score
    from public.scans s
    join public.scan_results r on r.scan_id = s.id
    where s.status = 'completed'
      and r.score is not null
      and s.created_at > now() - make_interval(days => greatest(1, least(p_days, 365)))
      and (p_exclude_owner is null or s.owner <> p_exclude_owner)
    order by s.owner, lower(substring(s.target_url from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)')), s.created_at desc
  )
  select count(*)::bigint, count(*) filter (where score < p_score)::bigint from latest;
$$;

revoke all on function public.instant_check_score_counts(integer, integer) from public, anon, authenticated;
revoke all on function public.scan_score_counts(integer, integer, uuid) from public, anon, authenticated;
grant execute on function public.instant_check_score_counts(integer, integer) to service_role;
grant execute on function public.scan_score_counts(integer, integer, uuid) to service_role;
