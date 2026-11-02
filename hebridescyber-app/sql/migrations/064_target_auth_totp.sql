-- Optional TOTP shared secret for a recorded-login credential, so a login
-- form behind authenticator-app MFA can be re-recorded without retyping the
-- secret. Stored encrypted (enc:v1:..., credentialEncryption.ts) and written
-- only by src/pages/api/account/record-login.ts (service role); never selected
-- by browser code. Idempotent.
alter table public.target_auth_credentials add column if not exists totp_secret text;
