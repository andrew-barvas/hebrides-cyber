-- Migration 055: per-tool kill switches (admin feature flags).
--
-- A global, admin-controlled on/off switch for individual extended-scan
-- tools (nuclei, zap, sqlmap, …). When a tool starts misbehaving — a
-- third-party binary breaks, a template set goes bad, a tool floods a
-- target — an admin can disable it from the panel so the scan worker skips
-- it on every scan, without waiting for a code deploy. The worker reads
-- this table and forces the named tool's enable flag to false after the
-- scan profile has been resolved (see src/lib/toolKillSwitch.ts and
-- scanExecution.ts); a disabled tool then produces exactly the same
-- "not run" shape as a tool missing its binary, so nothing downstream
-- needs to special-case it.
--
-- Global config, not owner data: one row per tool, keyed by tool_name.
-- Like audit_logs/contact_enquiries it has NO client policy at all — only
-- the service role (the worker and the admin API) reads or writes it. An
-- absent row means "enabled" (the default), so the table only ever needs
-- rows for tools an admin has actually touched.
--
-- Idempotent — safe to re-run.

create table if not exists public.tool_kill_switches (
  tool_name text primary key,
  disabled boolean not null default false,
  note text,
  updated_by uuid,
  updated_at timestamptz not null default now()
);

alter table public.tool_kill_switches enable row level security;

-- No policies on purpose: service-role only. A client gets zero rows and
-- cannot write, exactly like audit_logs.
