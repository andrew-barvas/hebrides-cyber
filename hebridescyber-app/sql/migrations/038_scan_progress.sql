-- Migration 038: Add progress tracking to scans for real-time UI feedback.
-- Stores which checks have completed and their results during a scan.
-- Idempotent — safe to re-run.

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS progress jsonb DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS started_at timestamptz DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS completed_at timestamptz DEFAULT NULL;

COMMENT ON COLUMN public.scans.progress IS 'Real-time progress data: { phase, checks_completed, checks_total, current_check, elapsed_ms }';
COMMENT ON COLUMN public.scans.started_at IS 'When the worker actually began executing this scan (distinct from created_at)';
COMMENT ON COLUMN public.scans.completed_at IS 'When the scan finished (completed or failed)';
