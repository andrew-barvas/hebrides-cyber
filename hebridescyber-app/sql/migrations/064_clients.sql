-- Migration 064: agency client workspaces.
--
-- A `clients` row groups an agency's monitored sites (and verified domains)
-- under one named client. client_id on monitored_targets / verifications is
-- nullable and ON DELETE SET NULL: null means "Unassigned", so every existing
-- row and raw insert keeps working and deleting a client never deletes sites.
--
-- brand_name / brand_logo_url optionally override the account brand on that
-- client's reports. Writes happen server-side (src/pages/api/clients.ts); the
-- owner policy exists as defence in depth, and team members get read-only
-- access like they do for monitored_targets (007_teams.sql).
--
-- A trigger rejects assigning a site to another owner's client. Idempotent.

create table if not exists public.clients (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 80),
  notes text,
  brand_name text,
  brand_logo_url text,
  created_at timestamptz not null default now()
);

create unique index if not exists clients_owner_name_idx on public.clients (owner, lower(name));

alter table public.clients enable row level security;

drop policy if exists "Owners manage their own clients" on public.clients;
create policy "Owners manage their own clients"
  on public.clients for all
  using (owner = auth.uid())
  with check (owner = auth.uid());

drop policy if exists "Team members can view the owner's clients" on public.clients;
create policy "Team members can view the owner's clients"
  on public.clients for select
  using (
    owner in (
      select teams.owner_id from public.teams
      where teams.id in (select public.caller_team_ids())
    )
  );

alter table public.monitored_targets
  add column if not exists client_id uuid references public.clients(id) on delete set null;
alter table public.verifications
  add column if not exists client_id uuid references public.clients(id) on delete set null;

create index if not exists monitored_targets_client_idx on public.monitored_targets (client_id) where client_id is not null;
create index if not exists verifications_client_idx on public.verifications (client_id) where client_id is not null;

create or replace function public.enforce_client_owner()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if new.client_id is not null
     and not exists (select 1 from public.clients c where c.id = new.client_id and c.owner = new.owner) then
    raise exception 'client % does not belong to owner', new.client_id using errcode = '23514';
  end if;
  return new;
end;
$$;

drop trigger if exists monitored_targets_client_owner on public.monitored_targets;
create trigger monitored_targets_client_owner
  before insert or update of client_id, owner on public.monitored_targets
  for each row execute function public.enforce_client_owner();

drop trigger if exists verifications_client_owner on public.verifications;
create trigger verifications_client_owner
  before insert or update of client_id, owner on public.verifications
  for each row execute function public.enforce_client_owner();
