// @vitest-environment node
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PoolClient } from "pg";
import { DB_TESTS_ENABLED, createTestDb, type TestDb } from "./harness";

const OWNER = "aaaaaaaa-0000-0000-0000-000000000001";

async function asService(db: TestDb): Promise<PoolClient> {
  const c = await db.pool.connect();
  await c.query("begin");
  await c.query("set local role service_role");
  return c;
}

describe.skipIf(!DB_TESTS_ENABLED)("claim_scan_job() (real Postgres)", () => {
  let db: TestDb;

  async function seedJobs(n: number) {
    await db.pool.query("delete from scan_jobs");
    await db.pool.query(
      `insert into scan_jobs (owner, target_url, created_at)
       select $1, 'https://t' || g || '.test', now() + (g || ' seconds')::interval from generate_series(1, $2) g`,
      [OWNER, n],
    );
  }

  beforeAll(async () => {
    db = await createTestDb();
    await db.pool.query("insert into auth.users (id, email) values ($1, 'a@x.test')", [OWNER]);
  });

  afterAll(async () => {
    await db?.drop();
  });

  it("claims the oldest pending job and marks it running", async () => {
    await seedJobs(3);
    const c = await asService(db);
    try {
      const { rows } = await c.query("select * from claim_scan_job('w1')");
      expect(rows).toHaveLength(1);
      expect(rows[0].target_url).toBe("https://t1.test");
      await c.query("commit");
    } finally {
      c.release();
    }
    const { rows } = await db.pool.query("select status, claimed_by, attempts from scan_jobs where target_url = 'https://t1.test'");
    expect(rows[0]).toMatchObject({ status: "running", claimed_by: "w1", attempts: 1 });
  });

  it("returns no row when the queue is empty", async () => {
    await seedJobs(0);
    const c = await asService(db);
    try {
      expect((await c.query("select * from claim_scan_job('w1')")).rows).toEqual([]);
    } finally {
      await c.query("rollback");
      c.release();
    }
  });

  it("SKIP LOCKED: a second claimer skips a job the first holds, without blocking", async () => {
    await seedJobs(3);
    const c1 = await asService(db);
    const c2 = await asService(db);
    try {
      const first = (await c1.query("select * from claim_scan_job('w1')")).rows;
      // c1 has NOT committed: its row lock is still held. c2 must not wait for it.
      const second = (await c2.query("select * from claim_scan_job('w2')")).rows;
      expect(first).toHaveLength(1);
      expect(second).toHaveLength(1);
      expect(second[0].id).not.toBe(first[0].id);
      expect(first[0].target_url).toBe("https://t1.test");
      expect(second[0].target_url).toBe("https://t2.test");
    } finally {
      await c1.query("rollback");
      await c2.query("rollback");
      c1.release();
      c2.release();
    }
  });

  it("a rolled-back claim leaves the job pending for the next claimer", async () => {
    await seedJobs(1);
    const c1 = await asService(db);
    try {
      expect((await c1.query("select * from claim_scan_job('w1')")).rows).toHaveLength(1);
    } finally {
      await c1.query("rollback");
      c1.release();
    }
    const c2 = await asService(db);
    try {
      expect((await c2.query("select * from claim_scan_job('w2')")).rows).toHaveLength(1);
    } finally {
      await c2.query("rollback");
      c2.release();
    }
  });

  it("never hands the same job to two concurrent workers", async () => {
    const jobs = 40;
    await seedJobs(jobs);
    const workers = 8;
    const claimedBy = await Promise.all(
      Array.from({ length: workers }, async (_, w) => {
        const ids: string[] = [];
        // each worker autocommits one claim at a time, racing the others
        const c = await db.pool.connect();
        try {
          await c.query("set role service_role");
          for (;;) {
            const { rows } = await c.query("select id from claim_scan_job($1)", [`w${w}`]);
            if (rows.length === 0) break;
            ids.push(rows[0].id);
          }
        } finally {
          await c.query("reset role");
          c.release();
        }
        return ids;
      }),
    );
    const all = claimedBy.flat();
    expect(all).toHaveLength(jobs);
    expect(new Set(all).size).toBe(jobs);
    const { rows } = await db.pool.query("select count(*)::int n from scan_jobs where status = 'running' and attempts = 1");
    expect(rows[0].n).toBe(jobs);
  });

  // Regression: scans.status rejected 'queued' until migration 050, so the
  // dashboard's pending → queued claim and POST /api/v1/scans both failed,
  // and every on-demand scan stayed 'pending' ("not started").
  it("lets a scan take every status the app writes", async () => {
    for (const status of ["pending", "queued", "running", "completed", "failed"]) {
      const { rows } = await db.pool.query("insert into scans (owner, target_url, status) values ($1, 'https://s.test', $2) returning status", [OWNER, status]);
      expect(rows[0].status).toBe(status);
    }
    const { rows } = await db.pool.query("insert into scans (owner, target_url) values ($1, 'https://s.test') returning id", [OWNER]);
    await db.pool.query("update scans set status = 'queued' where id = $1 and status = 'pending'", [rows[0].id]);
    await expect(db.pool.query("update scans set status = 'stuck' where id = $1", [rows[0].id])).rejects.toThrow(/scans_status_check/);
  });

  it("recovers a job orphaned by a killed runner, putting its scan back to queued", async () => {
    await db.pool.query("delete from scan_jobs");
    const scan = (await db.pool.query("insert into scans (owner, target_url, status) values ($1, 'https://orphan.test', 'running') returning id", [OWNER])).rows[0].id;
    await db.pool.query(
      "insert into scan_jobs (owner, target_url, scan_id, status, claimed_at, claimed_by) values ($1, 'https://orphan.test', $2, 'running', now() - interval '7 hours', 'dead-runner')",
      [OWNER, scan],
    );
    const c = await asService(db);
    try {
      expect((await c.query("select reset_stale_scan_jobs() as n")).rows[0].n).toBe(1);
      await c.query("commit");
    } finally {
      c.release();
    }
    expect((await db.pool.query("select status from scan_jobs where scan_id = $1", [scan])).rows[0].status).toBe("pending");
    expect((await db.pool.query("select status from scans where id = $1", [scan])).rows[0].status).toBe("queued");
  });
});
