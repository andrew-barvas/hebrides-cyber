// Real-Postgres test harness: creates a throwaway database, installs the
// Supabase shim (tests/db/shim.sql) and applies every migration in
// sql/migrations in filename order. Used only by `npm run test:db`
// (vitest.db.config.mts); the normal unit run never imports it.
//
// Connection: DATABASE_URL (superuser, default
// postgres://postgres:postgres@localhost:5432/postgres). Each run creates and
// drops its own database, so it is safe against a shared server.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { Client, Pool, type PoolClient, type QueryResult } from "pg";

export const DB_TESTS_ENABLED = process.env.RUN_DB_TESTS === "1";

export const ADMIN_URL =
  process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";

const HERE = __dirname;
export const MIGRATIONS_DIR = path.resolve(HERE, "../../sql/migrations");
const SHIM_PATH = path.resolve(HERE, "shim.sql");

export function listMigrations(): string[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();
}

export function readMigration(file: string): string {
  return readFileSync(path.join(MIGRATIONS_DIR, file), "utf8");
}

function withDatabase(url: string, db: string): string {
  const u = new URL(url);
  u.pathname = `/${db}`;
  return u.toString();
}

export interface TestDb {
  name: string;
  /** Superuser pool: use for seeding and DDL. Bypasses RLS. */
  pool: Pool;
  url: string;
  drop(): Promise<void>;
}

export async function createTestDb(opts: { migrate?: boolean } = {}): Promise<TestDb> {
  const name = `hc_test_${randomBytes(6).toString("hex")}`;
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`create database ${name}`);
  await admin.end();

  const url = withDatabase(ADMIN_URL, name);
  const pool = new Pool({ connectionString: url, max: 10 });
  await pool.query(readFileSync(SHIM_PATH, "utf8"));
  if (opts.migrate !== false) {
    for (const file of listMigrations()) {
      try {
        await pool.query(readMigration(file));
      } catch (err) {
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }
  }

  return {
    name,
    pool,
    url,
    async drop() {
      await pool.end();
      const a = new Client({ connectionString: ADMIN_URL });
      await a.connect();
      await a.query(`drop database if exists ${name} with (force)`);
      await a.end();
    },
  };
}

export type Actor =
  | { role: "anon" }
  | { role: "authenticated"; uid: string }
  | { role: "service_role" };

/** Mirrors PostgREST: switch to the API role and set the JWT claim GUCs. */
async function becomeActor(client: PoolClient, actor: Actor): Promise<void> {
  await client.query(`set local role ${actor.role}`);
  if (actor.role === "authenticated") {
    await client.query(
      `select set_config('request.jwt.claim.sub', $1, true),
              set_config('request.jwt.claim.role', 'authenticated', true)`,
      [actor.uid],
    );
  } else {
    await client.query(`select set_config('request.jwt.claim.role', $1, true)`, [actor.role]);
  }
}

/**
 * Run `fn` inside a transaction as the given actor. Always rolled back, so a
 * test's writes never leak into another's. A statement that errors aborts the
 * transaction, so use `attempt()` for statements expected to fail.
 */
export async function asActor<T>(
  db: TestDb,
  actor: Actor,
  fn: (c: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await db.pool.connect();
  try {
    await client.query("begin");
    await becomeActor(client, actor);
    return await fn(client);
  } finally {
    try {
      await client.query("rollback");
    } finally {
      client.release();
    }
  }
}

export interface Attempt {
  ok: boolean;
  /** SQLSTATE of the error when !ok (42501 = insufficient_privilege / RLS). */
  code?: string;
  rowCount?: number;
  rows?: Record<string, unknown>[];
}

/** Run one statement in its own savepoint; failure doesn't abort the tx. */
export async function attempt(
  c: PoolClient,
  sql: string,
  params: unknown[] = [],
): Promise<Attempt> {
  await c.query("savepoint attempt_sp");
  try {
    const r: QueryResult = await c.query(sql, params);
    await c.query("release savepoint attempt_sp");
    return { ok: true, rowCount: r.rowCount ?? 0, rows: r.rows };
  } catch (err) {
    await c.query("rollback to savepoint attempt_sp");
    return { ok: false, code: (err as { code?: string }).code };
  }
}
