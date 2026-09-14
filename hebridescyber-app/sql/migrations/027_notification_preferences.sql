-- Migration 027: notification preferences for E-50 (email alerts) and E-51
-- (custom notification rules).
--
-- Adds columns to subscriptions for email notification opt-in and threshold
-- filtering. Idempotent — safe to re-run.

-- E-50: email notification on scan completion (opt-in, default true for new
-- accounts; existing accounts get true so they start receiving emails).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'subscriptions' AND column_name = 'notify_email'
  ) THEN
    ALTER TABLE public.subscriptions ADD COLUMN notify_email boolean NOT NULL DEFAULT true;
  END IF;
END $$;

-- E-51: score threshold — only fire alerts when score drops below this value.
-- NULL means "always alert" (no threshold filtering). Range 0-100.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'subscriptions' AND column_name = 'notify_score_threshold'
  ) THEN
    ALTER TABLE public.subscriptions ADD COLUMN notify_score_threshold integer;
  END IF;
END $$;

-- E-51: minimum severity filter — only fire alerts when a new finding meets
-- this severity or higher. NULL means "alert on any new finding".
-- Values: 'info', 'low', 'medium', 'high', 'critical'
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'subscriptions' AND column_name = 'notify_severity_min'
  ) THEN
    ALTER TABLE public.subscriptions ADD COLUMN notify_severity_min text;
  END IF;
END $$;
