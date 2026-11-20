-- Migration 081: the CVE index leaves Postgres.
--
-- Migration 069's tables held the local CPE -> CVE index: 2.27 million
-- criteria and 409,000 CVEs, 612 MB, which on its own exceeded the Supabase
-- Free plan's 500 MB database limit (measured 2026-11-20: the database was
-- 629 MB; every other table together was about 15 MB). The index now lives
-- in object storage as gzipped files (src/lib/cveIndexObjects.ts, 63 MB in
-- the private `cve-index` Storage bucket), copied there with the sync state
-- by src/scripts/export-cve-index.ts before this migration shipped, and the
-- nightly sync and the scanners read and write it there.
--
-- Dropping the tables frees their space immediately. Idempotent.

drop function if exists public.replace_cve_batch(jsonb);
drop table if exists public.cve_cpe_matches;
drop table if exists public.cve_records;
drop table if exists public.cve_index_state;
