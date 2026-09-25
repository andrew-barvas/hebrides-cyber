-- Migration 029: E-33 API spec storage for OpenAPI/Swagger-driven testing.
-- Stores customer-uploaded API specs for spec-aware security testing.
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS public.api_specs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url text NOT NULL,
  spec_format text NOT NULL DEFAULT 'openapi3' CHECK (spec_format IN ('openapi3', 'openapi2', 'swagger')),
  spec_content jsonb NOT NULL,
  source_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
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

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'api_specs' AND policyname = 'api_specs_owner_insert'
  ) THEN
    CREATE POLICY api_specs_owner_insert ON public.api_specs
      FOR INSERT WITH CHECK (auth.uid() = owner);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'api_specs' AND policyname = 'api_specs_owner_delete'
  ) THEN
    CREATE POLICY api_specs_owner_delete ON public.api_specs
      FOR DELETE USING (auth.uid() = owner);
  END IF;
END $$;

-- Backfill: if old schema had raw_spec/uploaded_at/monitored_target_id columns,
-- add the new columns. Idempotent via IF NOT EXISTS on the column check.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'api_specs' AND column_name = 'raw_spec'
  ) THEN
    -- Rename raw_spec → spec_content if the old column name still exists
    ALTER TABLE public.api_specs RENAME COLUMN raw_spec TO spec_content;
  END IF;
EXCEPTION WHEN undefined_column THEN
  NULL; -- already renamed or never existed
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'api_specs' AND column_name = 'target_url'
  ) THEN
    ALTER TABLE public.api_specs ADD COLUMN target_url text NOT NULL DEFAULT '';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'api_specs' AND column_name = 'updated_at'
  ) THEN
    ALTER TABLE public.api_specs ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
  END IF;
END $$;
