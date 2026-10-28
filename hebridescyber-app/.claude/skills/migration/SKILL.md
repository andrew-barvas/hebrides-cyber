---
name: migration
description: Add a Postgres/Supabase migration to hebridescyber-app/sql/migrations/ — picking the next number, the idempotency and RLS requirements, the SECURITY DEFINER rule for self-referencing policies, the db tests to update, and how it auto-applies on merge. Use whenever a change needs a schema, policy, trigger or RPC change.
---

# Add a migration

Migrations live in **`hebridescyber-app/sql/migrations/`** — not the repo-root
`sql/` directory, which holds only a stray early file. They apply
automatically on push to master, so a bad one lands in production without a
manual step.

## Pick the number

```bash
ls hebridescyber-app/sql/migrations/ | tail -3
```

Take the next free number after the highest, zero-padded to three digits:
`NNN_short_snake_case_name.sql`. **The sequence skips `023`** — the file count
is one lower than the highest number, so count from the filename, never from
`ls | wc -l`.

## Write it

- **It must apply cleanly and re-apply idempotently.** `migrations.db.test.ts`
  applies every file in order to a throwaway database and then re-applies it.
  Use `create table if not exists`, `drop policy if exists` before
  `create policy`, `add column if not exists`, `create or replace function`.
  Known exceptions are listed in `migrations.db.test.ts` and **may only
  shrink** — don't add one.
- **A policy must never sub-select its own table inline.** Postgres fails it
  with `42P17 "infinite recursion"`. Put the read in a `SECURITY DEFINER`
  function with a pinned `search_path`, as `047` does and as
  `caller_team_ids()` in `007_teams.sql` does.
- **Decide the sensitivity tier.** Most new tables are owner-readable and
  service-role-write-only — a forgeable row in `ticket_links` could suppress
  ticketing for a real finding, so writes go through a server route, not RLS.
  Global config (`tool_kill_switches`, `audit_logs`) is service-role-only in
  both directions. `docs/DATA-MODEL.md` has the tiers.
- **Widening a CHECK constraint is a migration.** `subscriptions.plan`'s CHECK
  was never widened for `'tier_a'` when Tier A shipped, and the webhook,
  `planAccess.ts` and the pricing page all already treated it as valid —
  caught only later, by `052`.
- **Every consumer must no-op before the migration exists.** Reads degrade to
  the empty/absent answer and writes answer 503, so a deploy where the code
  lands before the migration doesn't 500. Each feature's section in
  `docs/ARCHITECTURE-NOTES.md` says "before NNN it no-ops" — match that.

## Update the tests

- **A new client-readable table needs an entry in `rls.db.test.ts`** — it
  asserts what `anon` / `authenticated` / `service_role` can each see.
- A new RPC that takes a lock or claims a row wants a concurrency test, as
  `claim_scan_job()` has in `claimScanJob.db.test.ts`.
- Run them:

```bash
npm run test:db
```

Needs `DATABASE_URL` — a superuser connection, default
`postgres://postgres:postgres@localhost:5432/postgres`. Each run creates and
drops its own database. `tests/db/shim.sql` stands in for Supabase (roles,
`auth.users`, `auth.uid()`). Without a local Postgres this gate only runs in
`.github/workflows/db-tests.yml`, so say so rather than claiming it passed.

## Check it against the ledger

```bash
cd hebridescyber-app && npx tsx src/scripts/apply-migrations.ts status
```

Read-only; exits 1 on checksum drift or unknown history. Without
`DATABASE_URL` it exits 0 and says so, which is not a pass.

Other commands: `apply` (applies pending in order, each in its own
transaction) and `baseline NNN` (records files up to NNN as applied without
running them — a one-time operation, already done through 047).

## How it lands

`.github/workflows/deploy.yml`'s `migration-check` job runs before the deploy
on every push to master: it applies pending migrations through
`apply-migrations.ts`, records each in `public.schema_migrations` with a
checksum, then re-verifies the schema. It stops on the first failure, refuses
an edited already-applied migration, and refuses a database that has tables
but no ledger.

So: **a migration in a PR applies automatically when that PR merges.** No
manual SQL-editor step except in genuine exceptions. Watch the `Deploy` run
after merging — a failed migration blocks the deploy.
