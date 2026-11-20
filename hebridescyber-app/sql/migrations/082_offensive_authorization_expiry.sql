-- Migration 082: Tier A offensive-scan authorizations expire (audit M5,
-- AUDIT-2026-11-POST-MERGE.md).
--
-- Recording one now requires an expiry at most 30 days away
-- (offensiveAuthorization.ts MAX_AUTHORIZATION_DAYS). Rows recorded before
-- this with no expiry were open-ended; each current one gets 30 days from
-- this migration, after which the owner re-authorises. Revoked rows are left
-- as they are. Idempotent: only null expiries change.

update public.offensive_scan_authorizations
set expires_at = now() + interval '30 days'
where expires_at is null
  and revoked_at is null;
