// @vitest-environment node
// Migration 084's constraints: the parts of the engagement record the database
// itself refuses, whatever a route lets through.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DB_TESTS_ENABLED, createTestDb, type TestDb } from "./harness";

const OWNER = "aaaaaaaa-0000-0000-0000-000000000001";
const ENGAGEMENT = "e1000000-0000-0000-0000-000000000001";

describe.skipIf(!DB_TESTS_ENABLED)("engagement record (migration 084, real Postgres)", () => {
  let db: TestDb;
  const q = (sql: string, params: unknown[] = []) => db.pool.query(sql, params);
  const fails = async (sql: string, params: unknown[] = []) => {
    await expect(q(sql, params)).rejects.toThrow();
  };

  beforeAll(async () => {
    db = await createTestDb();
  });

  afterAll(async () => {
    await db?.drop();
  });

  beforeEach(async () => {
    await q("delete from engagements");
    await q("insert into engagements (id, owner, reference, created_by, window_start, window_end) values ($1, $2, 'one', $2, '2026-11-01', '2026-11-30')", [ENGAGEMENT, OWNER]);
  });

  it("refuses an expiry before the window ends, and accepts one on or after it", async () => {
    await fails("update engagements set expires_at = '2026-11-29' where id = $1", [ENGAGEMENT]);
    await q("update engagements set expires_at = '2026-11-30' where id = $1", [ENGAGEMENT]);
    await q("update engagements set expires_at = '2026-12-31' where id = $1", [ENGAGEMENT]);
  });

  it("accepts only a lowercase hex SHA-256 for the rules-of-engagement document", async () => {
    await fails("update engagements set roe_document_sha256 = 'abc' where id = $1", [ENGAGEMENT]);
    await fails("update engagements set roe_document_sha256 = $2 where id = $1", [ENGAGEMENT, "A".repeat(64)]);
    await q("update engagements set roe_document_sha256 = $2 where id = $1", [ENGAGEMENT, "a1".repeat(32)]);
  });

  it("refuses a contact with no way to reach them, or an unknown kind", async () => {
    await fails("insert into engagement_contacts (engagement_id, owner, kind, name, added_by) values ($1, $2, 'emergency', 'n', $2)", [ENGAGEMENT, OWNER]);
    await fails("insert into engagement_contacts (engagement_id, owner, kind, name, email, added_by) values ($1, $2, 'boss', 'n', 'n@x.test', $2)", [ENGAGEMENT, OWNER]);
    await q("insert into engagement_contacts (engagement_id, owner, kind, name, phone, added_by) values ($1, $2, 'emergency', 'n', '+44 1', $2)", [ENGAGEMENT, OWNER]);
  });

  it("refuses a testing window that ends before it starts", async () => {
    await fails("insert into engagement_testing_windows (engagement_id, owner, starts_at, ends_at, added_by) values ($1, $2, '2026-11-02 17:00', '2026-11-02 09:00', $2)", [ENGAGEMENT, OWNER]);
  });

  it("removes contacts and windows with their engagement", async () => {
    await q("insert into engagement_contacts (engagement_id, owner, kind, name, email, added_by) values ($1, $2, 'technical', 'n', 'n@x.test', $2)", [ENGAGEMENT, OWNER]);
    await q("insert into engagement_testing_windows (engagement_id, owner, starts_at, ends_at, added_by) values ($1, $2, '2026-11-02 09:00', '2026-11-02 17:00', $2)", [ENGAGEMENT, OWNER]);
    await q("delete from engagements where id = $1", [ENGAGEMENT]);
    expect((await q("select count(*)::int n from engagement_contacts")).rows[0].n).toBe(0);
    expect((await q("select count(*)::int n from engagement_testing_windows")).rows[0].n).toBe(0);
  });
});
