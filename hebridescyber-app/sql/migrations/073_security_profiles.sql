-- Migration 073: public security profiles (opt-in).
--
-- A customer can publish a page for one verified site showing its grade,
-- score, last-checked date and the good practices it passes, plus an
-- embeddable badge (src/lib/securityProfile.ts, /profile/<slug>,
-- /api/badge/<slug>). Open problems are never shown publicly.
--
-- slug is random and unguessable (generated server-side); publishing again
-- keeps the same slug, unpublishing deletes the row and the link stops working.
--
-- Service-role only in both directions, like cve_records: the owner manages
-- it through /api/security-profile, and the public page reads it on the
-- server. RLS on, no policies.
--
-- Idempotent — safe to re-run.

create table if not exists public.security_profiles (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  target_host text not null check (target_host = lower(target_host) and length(target_host) between 1 and 253),
  slug text not null unique check (slug ~ '^[a-z0-9]{12,32}$'),
  created_at timestamptz not null default now(),
  unique (owner, target_host)
);

alter table public.security_profiles enable row level security;

-- No policies on purpose: service-role only.
