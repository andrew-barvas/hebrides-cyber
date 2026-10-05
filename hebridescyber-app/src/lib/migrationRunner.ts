// Migration runner with a ledger (`schema_migrations`) and drift detection.
//
// Why: deploy.yml's old "apply migrations" step re-ran every file on every
// deploy and ignored failures (and, because its `if` read a step-level env, it
// never ran at all — production quietly missed migrations 018 and 037). This
// applies each file once, in order, in its own transaction, records it with a
// checksum, and refuses to guess when the database's history is unknown.
//
// Rules:
// - A migration is applied only if it has no ledger row; the file and its ledger
//   row are committed together, so a failure leaves neither.
// - A file whose checksum differs from its ledger row was edited after being
//   applied ("never edit an applied migration"): reported as drift, never re-run.
// - A ledger row with no file is reported (a file was removed or renamed).
// - A database that already has tables but no ledger (applied by hand) is NOT
//   assumed to be in any state: `apply` refuses until someone records the
//   history with `baseline <upTo>` after checking what is really there.
//
// The IO is behind a minimal `Queryable` so it is testable without a database;
// tests/db/migrationRunner.db.test.ts runs it against a real Postgres.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

export type MigrationFile = { name: string; checksum: string; sql: string };
export type Recorded = { name: string; checksum: string; baseline: boolean };

export interface Queryable {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/** Hash of the file's content with line endings normalised (the repo mixes CRLF and LF). */
export function checksumOf(sql: string): string {
  return createHash("sha256").update(sql.replace(/\r\n/g, "\n")).digest("hex");
}

const MIGRATION_FILE = /^(\d{3})_[a-z0-9_]+\.sql$/i;

/** Migration files in numeric order. Non-migration files are ignored; duplicate numbers are an error. */
export function listMigrations(dir: string): MigrationFile[] {
  const names = readdirSync(dir).filter((f) => MIGRATION_FILE.test(f)).sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
  const seen = new Map<string, string>();
  for (const name of names) {
    const number = name.slice(0, 3);
    const clash = seen.get(number);
    if (clash) throw new Error(`Two migrations share the number ${number}: ${clash} and ${name}`);
    seen.set(number, name);
  }
  return names.map((name) => {
    const sql = readFileSync(path.join(dir, name), "utf8");
    return { name, sql, checksum: checksumOf(sql) };
  });
}

export type Plan = {
  pending: MigrationFile[];
  /** Applied, but the file has changed since. */
  drifted: { name: string; recorded: string; current: string }[];
  /** Recorded as applied, but there is no such file now. */
  orphaned: string[];
  applied: string[];
};

/** Pure: what a run would do, and what is wrong. */
export function planMigrations(files: MigrationFile[], recorded: Recorded[]): Plan {
  const byName = new Map(recorded.map((r) => [r.name, r]));
  const fileNames = new Set(files.map((f) => f.name));
  const plan: Plan = { pending: [], drifted: [], orphaned: [], applied: [] };
  for (const file of files) {
    const row = byName.get(file.name);
    if (!row) plan.pending.push(file);
    else {
      plan.applied.push(file.name);
      // A baselined row has no trustworthy checksum (the file was assumed, not run).
      if (!row.baseline && row.checksum !== file.checksum) plan.drifted.push({ name: file.name, recorded: row.checksum, current: file.checksum });
    }
  }
  plan.orphaned = recorded.filter((r) => !fileNames.has(r.name)).map((r) => r.name);
  return plan;
}

const LEDGER_DDL = `
create table if not exists public.schema_migrations (
  name        text primary key,
  checksum    text not null,
  baseline    boolean not null default false,
  applied_at  timestamptz not null default now()
);
alter table public.schema_migrations enable row level security;
`;

export async function ensureLedger(db: Queryable): Promise<void> {
  await db.query(LEDGER_DDL);
}

export async function loadRecorded(db: Queryable): Promise<Recorded[]> {
  const { rows } = await db.query("select name, checksum, baseline from public.schema_migrations order by name");
  return rows.map((r) => ({ name: String(r.name), checksum: String(r.checksum), baseline: Boolean(r.baseline) }));
}

/** True when the database already has application tables (so an empty ledger can't be trusted). */
export async function looksLikeExistingDatabase(db: Queryable): Promise<boolean> {
  const { rows } = await db.query("select to_regclass('public.scans') is not null as exists");
  return Boolean(rows[0]?.exists);
}

export class RunnerError extends Error {}

export type ApplyResult = { applied: string[]; plan: Plan };

/**
 * Applies pending migrations in order. Each runs with its ledger row in one
 * transaction; the first failure stops the run (later files may depend on it).
 */
export async function applyPending(db: Queryable, files: MigrationFile[], log: (line: string) => void = () => undefined): Promise<ApplyResult> {
  await ensureLedger(db);
  const recorded = await loadRecorded(db);
  if (recorded.length === 0 && (await looksLikeExistingDatabase(db))) {
    throw new RunnerError(
      "This database already has tables but no migration history. Check what is applied, then record it with `baseline <last-applied-number>` (for example `baseline 047`) before applying anything."
    );
  }
  const plan = planMigrations(files, recorded);
  if (plan.drifted.length > 0) {
    throw new RunnerError(`Applied migrations were edited after the fact: ${plan.drifted.map((d) => d.name).join(", ")}. Add a new migration instead of changing an applied one.`);
  }
  const applied: string[] = [];
  for (const file of plan.pending) {
    log(`applying ${file.name}`);
    await db.query("begin");
    try {
      await db.query(file.sql);
      await db.query("insert into public.schema_migrations (name, checksum) values ($1, $2)", [file.name, file.checksum]);
      await db.query("commit");
    } catch (err) {
      await db.query("rollback");
      throw new RunnerError(`Migration ${file.name} failed and was rolled back: ${(err as Error).message}`);
    }
    applied.push(file.name);
  }
  return { applied, plan };
}

/** Records every file up to and including `upTo` ("047") as already applied, without running it. */
export async function recordBaseline(db: Queryable, files: MigrationFile[], upTo: string): Promise<string[]> {
  if (!/^\d{3}$/.test(upTo)) throw new RunnerError(`Baseline needs a three-digit migration number, got "${upTo}".`);
  await ensureLedger(db);
  const existing = new Set((await loadRecorded(db)).map((r) => r.name));
  const recorded: string[] = [];
  for (const file of files) {
    if (file.name.slice(0, 3) > upTo || existing.has(file.name)) continue;
    await db.query("insert into public.schema_migrations (name, checksum, baseline) values ($1, $2, true)", [file.name, file.checksum]);
    recorded.push(file.name);
  }
  return recorded;
}

/** Read-only report for CI: nothing is changed. */
export async function statusReport(db: Queryable, files: MigrationFile[]): Promise<Plan & { hasLedger: boolean; existingDatabaseWithoutLedger: boolean }> {
  const { rows } = await db.query("select to_regclass('public.schema_migrations') is not null as exists");
  const hasLedger = Boolean(rows[0]?.exists);
  const recorded = hasLedger ? await loadRecorded(db) : [];
  const existingDatabaseWithoutLedger = recorded.length === 0 && (await looksLikeExistingDatabase(db));
  return { ...planMigrations(files, recorded), hasLedger, existingDatabaseWithoutLedger };
}
