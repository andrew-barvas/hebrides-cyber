-- Migration 057: correct the cloud_credentials storage comment.
--
-- Migration 030 claimed `credentials_encrypted` was "Encrypted at rest by
-- Supabase's pgcrypto", but nothing ever encrypted it — values were stored as
-- plaintext JSONB (review finding S-1). Encryption now happens in the
-- application layer (AES-256-GCM, src/lib/credentialEncryption.ts) before the
-- value is written. This migration only fixes the misleading metadata; the
-- column type/shape is unchanged (it now holds the {v,iv,tag,data} blob, or a
-- legacy plaintext object for rows written before the fix, until re-saved).
-- Idempotent.

COMMENT ON COLUMN public.cloud_credentials.credentials_encrypted IS
  'AES-256-GCM envelope-encrypted credentials blob {v,iv,tag,data} (app layer, CREDENTIALS_ENC_KEY). Legacy rows written before migration 057 may hold a plaintext JSON object until re-saved.';
