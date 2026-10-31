-- Migration 064: customer-defined nuclei checks (Agency and Tier A).
--
-- A customer writes their own HTTP-only nuclei template ("is /internal-admin
-- reachable on our site?"). Each is validated by src/lib/customNucleiTemplates.ts
-- before it is stored and again before every run, and only ever runs against
-- the target being scanned.
--
-- Owner can read their own rows; ALL writes are service role. That is the
-- point: the validator is the security boundary, and a client policy that let
-- the owner insert directly would let them store a template that skips it.
--
-- Cascades from auth.users, so account erasure removes them.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS public.custom_nuclei_templates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  template_id text NOT NULL CHECK (template_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  yaml text NOT NULL CHECK (char_length(yaml) <= 16384),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner, template_id)
);

CREATE INDEX IF NOT EXISTS custom_nuclei_templates_owner_idx ON public.custom_nuclei_templates (owner);

ALTER TABLE public.custom_nuclei_templates ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own custom nuclei templates" ON public.custom_nuclei_templates;
CREATE POLICY "Users can view their own custom nuclei templates"
  ON public.custom_nuclei_templates FOR SELECT
  USING (auth.uid() = owner);
