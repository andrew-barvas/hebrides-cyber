-- Contact enquiries — submissions from the /contact page.
-- Run in Supabase SQL editor or via `supabase db push`.

create table if not exists public.contact_enquiries (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  email       text not null,
  url         text,
  message     text not null,
  read        boolean not null default false,
  created_at  timestamptz not null default now()
);

-- Admin-only: only the service role (used by /api/contact and /api/admin/contacts)
-- can select/insert — no RLS policy grants browser access.
alter table public.contact_enquiries enable row level security;
-- (No policies = no access from the browser anon/authed keys, only service role.)
