-- Migration 087: documents on the public security profile
-- (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 14: a small trust centre).
--
-- An owner attaches PDFs (a Cyber Essentials certificate, an insurance
-- certificate, a policy) to the public security profile of one verified site
-- (security_profiles, migration 073). Each is either:
--   public       anyone viewing the profile can download it
--   on_request   a visitor asks with their name, email and reason; the owner
--                approves or declines; an approval emails the requester a
--                link that works for a few days and a few downloads
--
--   trust_documents          one PDF: site, title, kind, visibility, where
--                            the file is stored, its size and SHA-256
--   trust_document_requests  one request: who asked and why, the decision,
--                            and the download link's token hash and limits
--
-- Documents are keyed by owner and host, not by the profile row, so they
-- survive the profile being unpublished and published again; they are only
-- shown while it is published. Files live in a private storage bucket and
-- are only ever served through the API. Only the SHA-256 of a download token
-- is stored.
--
-- Service-role only in both directions. RLS on, no policies.
--
-- Idempotent — safe to re-run.

create table if not exists public.trust_documents (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  target_host text not null check (target_host = lower(target_host) and length(target_host) between 1 and 253),
  title text not null check (length(title) between 1 and 120),
  kind text not null check (kind in ('cyber_essentials', 'insurance', 'policy', 'penetration_test', 'other')),
  visibility text not null default 'on_request' check (visibility in ('public', 'on_request')),
  object_key text not null unique check (length(object_key) <= 400),
  size_bytes integer not null check (size_bytes > 0 and size_bytes <= 5242880),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  uploaded_by uuid references auth.users (id) on delete set null,
  uploaded_at timestamptz not null default now(),
  deleted_at timestamptz
);

create index if not exists trust_documents_site_idx on public.trust_documents (owner, target_host) where deleted_at is null;

create table if not exists public.trust_document_requests (
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references public.trust_documents (id) on delete cascade,
  requester_name text not null check (length(requester_name) between 1 and 120),
  requester_email text not null check (length(requester_email) between 3 and 254),
  requester_company text not null default '' check (length(requester_company) <= 120),
  reason text not null default '' check (length(reason) <= 1000),
  status text not null default 'pending' check (status in ('pending', 'approved', 'declined')),
  token_hash text unique check (token_hash is null or token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  decided_by uuid references auth.users (id) on delete set null,
  expires_at timestamptz,
  download_count integer not null default 0 check (download_count >= 0)
);

create index if not exists trust_document_requests_document_idx on public.trust_document_requests (document_id, created_at desc);

alter table public.trust_documents enable row level security;
alter table public.trust_document_requests enable row level security;

-- No policies on purpose: service-role only.
