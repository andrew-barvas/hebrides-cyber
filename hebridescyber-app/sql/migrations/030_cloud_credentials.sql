-- Migration 030: E-32 cloud posture scanning — credential storage for
-- AWS/Azure/GCP configuration review. Encrypted at rest by Supabase's
-- pgcrypto (column-level encryption for secrets). Idempotent.

CREATE TABLE IF NOT EXISTS public.cloud_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
  label text NOT NULL DEFAULT '',
  credentials_encrypted jsonb NOT NULL,
  validated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, provider, label)
);

ALTER TABLE public.cloud_credentials ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'cloud_credentials' AND policyname = 'cloud_credentials_owner_select'
  ) THEN
    CREATE POLICY cloud_credentials_owner_select ON public.cloud_credentials
      FOR SELECT USING (auth.uid() = owner);
  END IF;
END $$;
