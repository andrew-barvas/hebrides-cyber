// @vitest-environment node
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  DB_TESTS_ENABLED,
  createTestDb,
  listMigrations,
  readMigration,
  type TestDb,
} from "./harness";

// Migrations that are NOT safe to re-run on a fully migrated database today.
// Every other migration must re-apply cleanly (the repo convention since
// 002_improvements.sql is "all statements are safe to re-run"). The set may
// only shrink: fixing one means deleting it here.
const KNOWN_NON_IDEMPOTENT: Record<string, string> = {
  "001_init.sql": "create policy without a preceding drop policy if exists",
  "008_scan_jobs.sql": "claim_scan_job was redefined by 010 with a new return type; 008 cannot replace it",
  "017_users_admin_lockdown.sql": "create policy without a preceding drop policy if exists",
  "018_monitored_targets_plan_cap.sql": "create policy without a preceding drop policy if exists",
  "037_ip_allowlist.sql": "create policy without a preceding drop policy if exists",
};

// Numbers that are intentionally absent from the sequence.
const KNOWN_GAPS = new Set([23]);

describe.skipIf(!DB_TESTS_ENABLED)("migrations (real Postgres)", () => {
  let db: TestDb;

  beforeAll(async () => {
    // createTestDb applies every migration in order and throws, naming the
    // file, on the first failure.
    db = await createTestDb();
  });

  afterAll(async () => {
    await db?.drop();
  });

  it("has an ordered, duplicate-free numbering", () => {
    const nums = listMigrations().map((f) => {
      const m = /^(\d{3})_[a-z0-9_]+\.sql$/.exec(f);
      expect(m, `bad migration filename: ${f}`).not.toBeNull();
      return Number(m![1]);
    });
    expect(new Set(nums).size).toBe(nums.length);
    for (let i = 1; i < nums.length; i++) {
      expect(nums[i]).toBeGreaterThan(nums[i - 1]);
      for (let gap = nums[i - 1] + 1; gap < nums[i]; gap++) {
        expect(KNOWN_GAPS.has(gap), `unexpected gap: migration ${gap} is missing`).toBe(true);
      }
    }
  });

  it("applies every migration in order on an empty database", async () => {
    const { rows } = await db.pool.query<{ n: string }>(
      "select count(*) n from pg_tables where schemaname = 'public'",
    );
    expect(Number(rows[0].n)).toBeGreaterThan(20);
  });

  it("re-applies idempotently, except the documented exceptions", async () => {
    const failed: string[] = [];
    for (const file of listMigrations()) {
      try {
        await db.pool.query(readMigration(file));
      } catch {
        failed.push(file);
      }
    }
    const unexpected = failed.filter((f) => !(f in KNOWN_NON_IDEMPOTENT));
    expect(unexpected, `non-idempotent migrations not on the known list: ${unexpected.join(", ")}`).toEqual([]);
  });

  it("has row level security enabled on every public table", async () => {
    const { rows } = await db.pool.query<{ relname: string }>(
      `select c.relname
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind in ('r', 'p') and not c.relrowsecurity
        order by 1`,
    );
    expect(rows.map((r) => r.relname)).toEqual([]);
  });

  it("049 marks existing hostnames as already reported, but only when it first adds the column", async () => {
    const owner = "eeeeeeee-0000-0000-0000-000000000049";
    const q = (sql: string, p: unknown[] = []) => db.pool.query(sql, p);
    await q("insert into auth.users (id, email) values ($1, 'm049@x.test')", [owner]);
    await q("alter table asset_inventory drop column notified_at");
    await q("insert into asset_inventory (owner, target_url, hostname, kind, first_seen_at) values ($1, 'https://a.test', 'old.a.test', 'subdomain', '2026-01-01T00:00:00Z')", [owner]);

    await q(readMigration("049_attack_surface_monitoring.sql"));
    await q("insert into asset_inventory (owner, target_url, hostname, kind) values ($1, 'https://a.test', 'new.a.test', 'subdomain')", [owner]);
    await q(readMigration("049_attack_surface_monitoring.sql"));

    const { rows } = await q("select hostname, notified_at from asset_inventory where owner = $1 order by hostname", [owner]);
    expect(rows).toEqual([
      { hostname: "new.a.test", notified_at: null },
      { hostname: "old.a.test", notified_at: new Date("2026-01-01T00:00:00Z") },
    ]);
  });

  it("creates every key table", async () => {
    const { rows } = await db.pool.query<{ tablename: string }>(
      "select tablename from pg_tables where schemaname = 'public'",
    );
    const have = new Set(rows.map((r) => r.tablename));
    for (const t of [
      "scans", "scan_results", "subscriptions", "finding_lifecycle", "finding_triage",
      "ticket_links", "emerging_threat_alerts", "api_keys", "repo_connections",
      "monitored_targets", "audit_logs", "contact_enquiries", "verifications", "scan_jobs",
      "asset_inventory", "dns_snapshots", "deletion_requests",
    ]) {
      expect(have.has(t), `missing table ${t}`).toBe(true);
    }
  });

  it("pins search_path on every SECURITY DEFINER function", async () => {
    const { rows } = await db.pool.query<{ proname: string }>(
      `select p.proname
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prosecdef
          and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')`,
    );
    expect(rows.map((r) => r.proname)).toEqual([]);
  });
});
