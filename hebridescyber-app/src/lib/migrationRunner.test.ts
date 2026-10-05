import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  applyPending,
  checksumOf,
  ensureLedger,
  listMigrations,
  loadRecorded,
  looksLikeExistingDatabase,
  planMigrations,
  recordBaseline,
  RunnerError,
  statusReport,
  type MigrationFile,
  type Queryable,
  type Recorded,
} from "./migrationRunner";

const file = (name: string, sql = "select 1;"): MigrationFile => ({ name, sql, checksum: checksumOf(sql) });
const rec = (f: MigrationFile, baseline = false): Recorded => ({ name: f.name, checksum: f.checksum, baseline });

/** A scripted fake database: tracks the ledger rows and every statement it was sent. */
function fakeDb(opts: { ledger?: Recorded[]; hasScansTable?: boolean; failOn?: string } = {}) {
  const ledger: Recorded[] = [...(opts.ledger ?? [])];
  const statements: string[] = [];
  let hasLedger = opts.ledger !== undefined;
  const db: Queryable = {
    async query(text, params = []) {
      statements.push(text.trim().split("\n")[0].slice(0, 70));
      if (text.includes("create table if not exists public.schema_migrations")) hasLedger = true;
      if (text.includes("to_regclass('public.schema_migrations')")) return { rows: [{ exists: hasLedger }] };
      if (text.includes("to_regclass('public.scans')")) return { rows: [{ exists: opts.hasScansTable ?? false }] };
      if (text.startsWith("select name, checksum, baseline")) return { rows: ledger.map((r) => ({ ...r })) };
      if (text.startsWith("insert into public.schema_migrations")) {
        ledger.push({ name: String(params[0]), checksum: String(params[1]), baseline: text.includes("true") });
        return { rows: [] };
      }
      if (opts.failOn && text.includes(opts.failOn)) throw new Error("syntax error near boom");
      return { rows: [] };
    },
  };
  return { db, ledger, statements };
}

describe("checksumOf", () => {
  it("ignores line-ending differences", () => {
    expect(checksumOf("a\r\nb\r\n")).toBe(checksumOf("a\nb\n"));
    expect(checksumOf("a")).not.toBe(checksumOf("b"));
  });
});

describe("listMigrations", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), "mig-"));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("returns numbered files in order and ignores everything else", () => {
    for (const [n, c] of [["010_ten.sql", "select 10;"], ["002_two.sql", "select 2;"], ["README.md", "x"], ["notes.sql", "x"]]) writeFileSync(path.join(dir, n), c);
    const files = listMigrations(dir);
    expect(files.map((f) => f.name)).toEqual(["002_two.sql", "010_ten.sql"]);
    expect(files[0]).toMatchObject({ sql: "select 2;", checksum: checksumOf("select 2;") });
  });

  it("refuses two files with the same number", () => {
    writeFileSync(path.join(dir, "002_other.sql"), "select 3;");
    expect(() => listMigrations(dir)).toThrow(/share the number 002/);
  });
});

describe("planMigrations", () => {
  const a = file("001_a.sql");
  const b = file("002_b.sql");
  const c = file("003_c.sql");

  it("separates applied from pending, in file order", () => {
    const plan = planMigrations([a, b, c], [rec(a), rec(b)]);
    expect(plan.applied).toEqual(["001_a.sql", "002_b.sql"]);
    expect(plan.pending.map((f) => f.name)).toEqual(["003_c.sql"]);
    expect(plan.drifted).toEqual([]);
    expect(plan.orphaned).toEqual([]);
  });

  it("reports a file edited after it was applied", () => {
    const plan = planMigrations([{ ...a, checksum: "different" }, b], [rec(a), rec(b)]);
    expect(plan.drifted).toEqual([{ name: "001_a.sql", recorded: a.checksum, current: "different" }]);
  });

  it("does not call a baselined file drifted: its checksum was assumed, not observed", () => {
    expect(planMigrations([{ ...a, checksum: "different" }], [rec(a, true)]).drifted).toEqual([]);
  });

  it("reports a ledger row whose file is gone", () => {
    expect(planMigrations([a], [rec(a), rec(b)]).orphaned).toEqual(["002_b.sql"]);
  });
});

describe("ledger IO", () => {
  it("creates the ledger and reads it back", async () => {
    const { db } = fakeDb({ ledger: [rec(file("001_a.sql"))] });
    await ensureLedger(db);
    expect(await loadRecorded(db)).toEqual([rec(file("001_a.sql"))]);
  });

  it("detects an existing database by its scans table", async () => {
    expect(await looksLikeExistingDatabase(fakeDb({ hasScansTable: true }).db)).toBe(true);
    expect(await looksLikeExistingDatabase(fakeDb().db)).toBe(false);
  });
});

describe("applyPending", () => {
  const a = file("001_a.sql", "create table a();");
  const b = file("002_b.sql", "create table b();");

  it("applies pending files in order, each in a transaction with its ledger row", async () => {
    const { db, ledger, statements } = fakeDb();
    const lines: string[] = [];
    const result = await applyPending(db, [a, b], (l) => lines.push(l));
    expect(result.applied).toEqual(["001_a.sql", "002_b.sql"]);
    expect(ledger.map((r) => r.name)).toEqual(["001_a.sql", "002_b.sql"]);
    expect(lines).toEqual(["applying 001_a.sql", "applying 002_b.sql"]);
    const order = statements.filter((s) => /^(begin|commit|rollback|create table a|create table b|insert into)/.test(s));
    expect(order).toEqual(["begin", "create table a();", "insert into public.schema_migrations (name, checksum) values ($1, $2)", "commit", "begin", "create table b();", "insert into public.schema_migrations (name, checksum) values ($1, $2)", "commit"]);
  });

  it("does nothing, quietly, when everything is applied", async () => {
    const { db } = fakeDb({ ledger: [rec(a), rec(b)] });
    expect((await applyPending(db, [a, b])).applied).toEqual([]);
  });

  it("stops at the first failure, rolls it back and records nothing for it", async () => {
    const { db, ledger, statements } = fakeDb({ failOn: "create table b" });
    await expect(applyPending(db, [a, b, file("003_c.sql")])).rejects.toThrow(/002_b.sql failed and was rolled back: syntax error near boom/);
    expect(ledger.map((r) => r.name)).toEqual(["001_a.sql"]);
    expect(statements).toContain("rollback");
    expect(statements.some((s) => s.includes("003_c") || s === "select 1;")).toBe(false);
  });

  it("refuses a database that has tables but no history", async () => {
    const { db, statements } = fakeDb({ hasScansTable: true });
    await expect(applyPending(db, [a])).rejects.toThrow(/no migration history.*baseline/s);
    expect(statements.some((s) => s.startsWith("begin"))).toBe(false);
  });

  it("refuses when an applied migration was edited", async () => {
    const { db } = fakeDb({ ledger: [rec(a)] });
    await expect(applyPending(db, [{ ...a, checksum: "x" }])).rejects.toBeInstanceOf(RunnerError);
    await expect(applyPending(db, [{ ...a, checksum: "x" }])).rejects.toThrow(/001_a.sql/);
  });
});

describe("recordBaseline", () => {
  const files = [file("001_a.sql"), file("002_b.sql"), file("003_c.sql")];

  it("records files up to the number as baseline, without running them, and skips ones already recorded", async () => {
    const { db, ledger, statements } = fakeDb({ ledger: [rec(files[0])] });
    expect(await recordBaseline(db, files, "002")).toEqual(["002_b.sql"]);
    expect(ledger.map((r) => `${r.name}:${r.baseline}`)).toEqual(["001_a.sql:false", "002_b.sql:true"]);
    expect(statements.some((s) => s === "select 1;")).toBe(false);
  });

  it("needs a three-digit number", async () => {
    await expect(recordBaseline(fakeDb().db, files, "47")).rejects.toThrow(/three-digit/);
    await expect(recordBaseline(fakeDb().db, files, "")).rejects.toThrow(/three-digit/);
  });
});

describe("statusReport", () => {
  const a = file("001_a.sql");
  const b = file("002_b.sql");

  it("is read-only and reports pending, drift and the missing-ledger case", async () => {
    const withLedger = fakeDb({ ledger: [rec(a)] });
    const report = await statusReport(withLedger.db, [a, b]);
    expect(report).toMatchObject({ hasLedger: true, existingDatabaseWithoutLedger: false });
    expect(report.pending.map((f) => f.name)).toEqual(["002_b.sql"]);
    expect(withLedger.statements.some((s) => /^(create|insert|begin|alter)/.test(s))).toBe(false);

    const existing = await statusReport(fakeDb({ hasScansTable: true }).db, [a]);
    expect(existing).toMatchObject({ hasLedger: false, existingDatabaseWithoutLedger: true });

    const fresh = await statusReport(fakeDb().db, [a]);
    expect(fresh).toMatchObject({ hasLedger: false, existingDatabaseWithoutLedger: false });
    expect(fresh.pending).toHaveLength(1);
  });
});
