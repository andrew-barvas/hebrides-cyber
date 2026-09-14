-- Migration 029: E-33 API spec storage for OpenAPI/Swagger-driven testing.
-- Stores customer-uploaded API specs for spec-aware security testing.
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.api_specs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  monitored_target_id uuid REFERENCES public.monitored_targets(id) ON DELETE SET NULL,
  spec_format text NOT NULL DEFAULT 'openapi' CHECK (spec_format IN ('openapi', 'postman')),
  source_url text,
  raw_spec jsonb NOT NULL,
  uploaded_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.api_specs ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'api_specs' AND policyname = 'api_specs_owner_select'
  ) THEN
    CREATE POLICY api_specs_owner_select ON public.api_specs
      FOR SELECT USING (auth.uid() = owner);
  END IF;
END $$;
