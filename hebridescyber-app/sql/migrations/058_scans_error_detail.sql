-- Migration 058: record WHY a scan failed, not just that it did.
--
-- Previously a failed scan was only visible as scans.status = 'failed' with no
-- reason (review Phase 6 / architecture.md "Observability"); the worker already
-- stored scan_jobs.last_error, but that wasn't mirrored onto the scan the owner
-- (and admin) actually see. This adds a free-text column populated on failure
-- from the same message. Idempotent.

ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS error_detail text;

COMMENT ON COLUMN public.scans.error_detail IS
  'Human-readable reason the scan failed (mirrors scan_jobs.last_error); null on success.';
