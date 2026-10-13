-- Migration 056: email deliverability events.
--
-- The shared Resend sender (src/lib/email.ts's sendEmail) is best-effort and
-- its failures were only ever console.error'd by each caller — so a spell of
-- bounced or rejected mail (bad API key, Resend outage, a sender-reputation
-- block) was invisible operationally. This records one row per real send
-- attempt (ok or failed), which the admin "Email" view summarises into a
-- recent send count and failure rate.
--
-- PII-minimised: only the recipient DOMAIN is stored, never the full address
-- or the body — enough to spot "all mail to acme.com is bouncing" without
-- keeping a log of who was emailed what. Global ops data, not owner data, so
-- service-role-only like audit_logs (no client policy at all).
--
-- Idempotent — safe to re-run.

create table if not exists public.email_events (
  id uuid primary key default gen_random_uuid(),
  recipient_domain text,
  subject text,
  status text not null check (status in ('sent', 'failed')),
  provider text not null default 'resend',
  error text,
  created_at timestamptz not null default now()
);

create index if not exists email_events_created_idx on public.email_events (created_at desc);

alter table public.email_events enable row level security;

-- No policies on purpose: service-role only, exactly like audit_logs.
