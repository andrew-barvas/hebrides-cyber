-- Target criticality and environment (P1-2, "fix this first" estate ranking).
--
-- estatePriority.ts ranks every open finding across an account's sites. Two
-- findings with the same severity and threat intel are not equally urgent if
-- one sits on the customer's payment site and the other on a brochure page.
-- The customer says which is which here:
--   criticality  low | normal | high  (default normal, so every existing row
--                ranks exactly as it would have without this column)
--   environment  production | staging | development | test, or null for
--                "not said" (null never changes a rank)
--
-- Writes: no new grant or policy. 026's owner-only UPDATE policy already
-- covers every column of the row, and that is the right scope — criticality is
-- an owner decision, like scan_profile; a team member who can read the
-- owner's targets (007) cannot change it. The CHECKs keep a browser-client
-- write from storing a value the ranking doesn't know.
--
-- Readers must no-op before this migration: estatePriority's loader treats a
-- missing column as "every target normal", and MonitoredTargets.tsx reads the
-- two columns in a separate, failure-tolerant query.
--
-- Idempotent: add column if not exists (with its inline CHECK) re-applies
-- cleanly.

alter table public.monitored_targets
  add column if not exists criticality text not null default 'normal'
    check (criticality in ('low', 'normal', 'high'));

alter table public.monitored_targets
  add column if not exists environment text
    check (environment is null or environment in ('production', 'staging', 'development', 'test'));

comment on column public.monitored_targets.criticality is
  'How much this site matters to the business: low | normal | high. Weights the estate "fix this first" ranking (estatePriority.ts).';
comment on column public.monitored_targets.environment is
  'production | staging | development | test, or null when not stated. A non-production site ranks slightly lower.';
