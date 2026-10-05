// The migration runner (src/lib/migrationRunner.ts) against a real Postgres and
// the repo's real migrations: apply from scratch, re-run as a no-op, refuse a
// database whose history is unknown, baseline it, and flag an edited migration.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { DB_TESTS_ENABLED, MIGRATIONS_DIR, createTestDb, type TestDb } from "./harness";
import { applyPending, listMigrations, loadRecorded, planMigrations, recordBaseline, statusReport } from "../../src/lib/migrationRunner";

describe.skipIf(!DB_TESTS_ENABLED)("migration runner against real Postgres", () => {
  const files = listMigrations(MIGRATIONS_DIR);
  let fresh: TestDb;
  let handBuilt: TestDb;
  let freshClient: Client;
  let handClient: Client;

  beforeAll(async () => {
    fresh = await createTestDb({ migrate: false });
    handBuilt = await createTestDb(); // migrations applied "by hand": no ledger
    freshClient = new Client({ connectionString: fresh.url });
    handClient = new Client({ connectionString: handBuilt.url });
    await Promise.all([freshClient.connect(), handClient.connect()]);
  }, 120_000);

  afterAll(async () => {
    await Promise.all([freshClient?.end(), handClient?.end()]);
    await Promise.all([fresh?.drop(), handBuilt?.drop()]);
  });

  it("applies every migration to an empty database, in order, and records each", async () => {
    const result = await applyPending(freshClient, files);
    expect(result.applied).toEqual(files.map((f) => f.name));
    const recorded = await loadRecorded(freshClient);
    expect(recorded.map((r) => r.name)).toEqual(files.map((f) => f.name));
    expect(recorded.every((r) => !r.baseline)).toBe(true);
    const { rows } = await freshClient.query("select to_regclass('public.finding_triage') is not null as ok");
    expect(rows[0].ok).toBe(true);
  }, 120_000);

  it("is a no-op the second time (migrations that can't re-apply are never re-run)", async () => {
    expect((await applyPending(freshClient, files)).applied).toEqual([]);
    const report = await statusReport(freshClient, files);
    expect(report).toMatchObject({ pending: [], drifted: [], orphaned: [] });
  });

  it("applies only a new migration, and a failing one rolls back leaving no trace", async () => {
    const next = { name: "999_runner_test.sql", sql: "create table public.runner_test_ok(id int);", checksum: "c1" };
    expect((await applyPending(freshClient, [...files, next])).applied).toEqual(["999_runner_test.sql"]);

    const broken = { name: "998_broken.sql", sql: "create table public.runner_test_half(id int); select nope from nowhere;", checksum: "c2" };
    await expect(applyPending(freshClient, [...files, broken, next])).rejects.toThrow(/998_broken.sql failed and was rolled back/);
    const { rows } = await freshClient.query("select to_regclass('public.runner_test_half') is not null as half");
    expect(rows[0].half).toBe(false);
    expect((await loadRecorded(freshClient)).some((r) => r.name === "998_broken.sql")).toBe(false);
  });

  it("flags a migration edited after it was applied, and refuses to continue", async () => {
    const edited = files.map((f, i) => (i === 0 ? { ...f, checksum: "edited" } : f));
    expect(planMigrations(edited, await loadRecorded(freshClient)).drifted.map((d) => d.name)).toEqual([files[0].name]);
    await expect(applyPending(freshClient, edited)).rejects.toThrow(/edited after the fact/);
  });

  it("refuses a database that was built by hand and has no history", async () => {
    await expect(applyPending(handClient, files)).rejects.toThrow(/no migration history/);
    expect(await statusReport(handClient, files)).toMatchObject({ existingDatabaseWithoutLedger: true });
  });

  it("accepts a baseline for it, then applies only what comes after", async () => {
    const through = files[files.length - 1].name.slice(0, 3);
    expect(await recordBaseline(handClient, files, through)).toHaveLength(files.length);
    const extra = { name: "999_after_baseline.sql", sql: "create table public.after_baseline(id int);", checksum: "c3" };
    expect((await applyPending(handClient, [...files, extra])).applied).toEqual(["999_after_baseline.sql"]);
    const { rows } = await handClient.query("select count(*)::int as n from public.schema_migrations where baseline");
    expect(rows[0].n).toBe(files.length);
  });
});
