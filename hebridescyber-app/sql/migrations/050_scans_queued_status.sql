-- Migration 050: allow scans.status = 'queued'.
--
-- The app has written 'queued' since 2026-09-25 (a scan waiting for a
-- worker: run-scan.ts's pending → queued claim, POST /api/v1/scans's insert,
-- and 041's reset_stale_scan_jobs), but 001's check constraint only allows
-- pending/running/completed/failed, and no migration ever widened it. So:
--   - every dashboard scan stayed 'pending' (the claim failed, and run-scan.ts
--     reported "queued" without enqueuing anything), which the scan list then
--     shows as "not started";
--   - every POST /api/v1/scans (GitHub Action, CI templates) failed with 500;
--   - reset_stale_scan_jobs() failed whenever it had a stale job to recover.
--
-- Scans left 'pending' by this are not re-queued here: nobody asked for them
-- to run now, and their ownership check happens in the request that queues
-- them. Running the scan again from the dashboard works once this is applied.
--
-- Idempotent — safe to re-run.

ALTER TABLE public.scans DROP CONSTRAINT IF EXISTS scans_status_check;
ALTER TABLE public.scans
  ADD CONSTRAINT scans_status_check CHECK (status IN ('pending', 'queued', 'running', 'completed', 'failed'));
