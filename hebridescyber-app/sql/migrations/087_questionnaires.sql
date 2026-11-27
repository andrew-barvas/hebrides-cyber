-- Migration 087: security questionnaire autopilot.
--
-- A customer uploads a supplier or insurer security questionnaire (.xlsx or
-- .csv). We draft an answer to each question from their own evidence only
-- (src/lib/questionnaire/), and they accept, edit or reject each one before
-- exporting. Nothing is final until a person accepts it.
--
--   questionnaires         one uploaded questionnaire: its name, the original
--                          header row and data rows (kept so the export can
--                          return them unchanged), and which column holds the
--                          questions
--   questionnaire_answers  one drafted answer per question row: the draft, the
--                          customer's final wording, the evidence it cites, a
--                          confidence level and the review status
--
-- Accepted answers are reused: a later questionnaire's similar questions
-- start from them (questionnaire_answers_reuse_idx).
--
-- Owner-readable, and read-only for the owner's team members, as
-- asset_inventory (022) is. Every write goes through /api/questionnaires with
-- the service role, which validates it first. No insert/update/delete policy.
--
-- Idempotent — safe to re-run.

create table if not exists public.questionnaires (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users (id) on delete cascade,
  name text not null check (length(name) between 1 and 200),
  source_format text not null check (source_format in ('xlsx', 'csv')),
  sheet_name text check (length(sheet_name) <= 100),
  headers jsonb not null default '[]'::jsonb check (jsonb_typeof(headers) = 'array'),
  rows jsonb not null default '[]'::jsonb check (jsonb_typeof(rows) = 'array' and octet_length(rows::text) <= 3000000),
  question_column integer not null check (question_column between 0 and 199),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists questionnaires_owner_idx on public.questionnaires (owner, created_at desc);

create table if not exists public.questionnaire_answers (
  id uuid primary key default gen_random_uuid(),
  questionnaire_id uuid not null references public.questionnaires (id) on delete cascade,
  owner uuid not null references auth.users (id) on delete cascade,
  row_index integer not null check (row_index between 0 and 4999),
  question text not null check (length(question) between 1 and 4000),
  topic text check (length(topic) <= 60),
  draft_answer text not null default '' check (length(draft_answer) <= 4000),
  answer text not null default '' check (length(answer) <= 4000),
  evidence jsonb not null default '[]'::jsonb check (jsonb_typeof(evidence) = 'array'),
  confidence text not null default 'none' check (confidence in ('high', 'medium', 'low', 'none')),
  status text not null default 'draft' check (status in ('draft', 'needs_answer', 'accepted', 'rejected')),
  edited boolean not null default false,
  -- ai_checked: sent for AI wording (worded or not); ai_worded: the answer is the AI's rewording.
  ai_checked boolean not null default false,
  ai_worded boolean not null default false,
  reused_from uuid references public.questionnaire_answers (id) on delete set null,
  decided_by uuid references auth.users (id) on delete set null,
  decided_at timestamptz,
  updated_at timestamptz not null default now(),
  unique (questionnaire_id, row_index)
);

create index if not exists questionnaire_answers_questionnaire_idx on public.questionnaire_answers (questionnaire_id, row_index);
-- Reuse lookup: an owner's accepted answers, newest first.
create index if not exists questionnaire_answers_reuse_idx on public.questionnaire_answers (owner, decided_at desc)
  where status = 'accepted';

alter table public.questionnaires enable row level security;
alter table public.questionnaire_answers enable row level security;

drop policy if exists "Users can view their own questionnaires" on public.questionnaires;
create policy "Users can view their own questionnaires"
  on public.questionnaires for select
  using (owner = auth.uid());

drop policy if exists "Team members can view their team owner's questionnaires" on public.questionnaires;
create policy "Team members can view their team owner's questionnaires"
  on public.questionnaires for select
  using (
    owner in (
      select teams.owner_id from public.teams
      join public.team_members on team_members.team_id = teams.id
      where team_members.user_id = auth.uid()
    )
  );

drop policy if exists "Users can view their own questionnaire answers" on public.questionnaire_answers;
create policy "Users can view their own questionnaire answers"
  on public.questionnaire_answers for select
  using (owner = auth.uid());

drop policy if exists "Team members can view their team owner's questionnaire answers" on public.questionnaire_answers;
create policy "Team members can view their team owner's questionnaire answers"
  on public.questionnaire_answers for select
  using (
    owner in (
      select teams.owner_id from public.teams
      join public.team_members on team_members.team_id = teams.id
      where team_members.user_id = auth.uid()
    )
  );

-- No insert/update/delete policy — writes are service-role only, through
-- /api/questionnaires.
