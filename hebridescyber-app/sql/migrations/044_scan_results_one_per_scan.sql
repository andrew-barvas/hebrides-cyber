-- Migration 044: exactly one scan_results row per scan.
--
-- scan_results.scan_id had no uniqueness, and executeScan() always appended,
-- so any path that ran a scan twice (two racing "Run scan" step-2 calls each
-- enqueueing a job; an admin retry or stale-job recovery re-running a scan
-- that already had a result) left two rows. Every reader that asks for "the
-- result for this scan" uses .maybeSingle() and failed with
-- "JSON object requested, multiple (or no) rows returned" — the scan report
-- page among them.
--
-- The application now prevents it (conditional pending→queued claim in
-- run-scan.ts, replace-not-append in executeScan, completed-scan skip in the
-- worker). This makes it impossible at the database level too:
--   1. remove existing duplicates, keeping the newest result per scan;
--   2. add a unique index on scan_id.
--
-- Idempotent — safe to re-run.

DELETE FROM public.scan_results r
USING (
  SELECT id,
         row_number() OVER (PARTITION BY scan_id ORDER BY created_at DESC, id DESC) AS rn
  FROM public.scan_results
) ranked
WHERE r.id = ranked.id
  AND ranked.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS scan_results_scan_id_key ON public.scan_results (scan_id);
