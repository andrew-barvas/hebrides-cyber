// @vitest-environment node
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DB_TESTS_ENABLED, asActor, attempt, createTestDb, type Actor, type TestDb } from "./harness";

const OWNER = "aaaaaaaa-0000-0000-0000-000000000001";
const OTHER_ENGAGEMENT = "e2000000-0000-0000-0000-000000000002";
const ENGAGEMENT = "e1000000-0000-0000-0000-000000000001";
const ABORT = "select abort_engagement($1, $2) as result";

describe.skipIf(!DB_TESTS_ENABLED)("abort_engagement() (real Postgres)", () => {
  let db: TestDb;

  const authorisation = (host: string, engagementId: string | null) =>
    db.pool.query("insert into offensive_scan_authorizations (owner, target_host, authorized_by, scope, engagement_id) values ($1, $2, $1, 'test', $3)", [OWNER, host, engagementId]);
  const simulation = (status: string, engagementId = ENGAGEMENT) =>
    db.pool.query("insert into exploit_simulations (owner, engagement_id, requested_by, plan, status, model_version) values ($1, $2, $1, '{}', $3, 'exp-v1')", [OWNER, engagementId, status]);
  const abort = async (id = ENGAGEMENT, reason = "stop") => (await db.pool.query(ABORT, [id, reason])).rows[0].result;
  const revokedAt = async (host: string) => (await db.pool.query("select revoked_at from offensive_scan_authorizations where target_host = $1", [host])).rows[0].revoked_at;

  beforeAll(async () => {
    db = await createTestDb();
  });

  afterAll(async () => {
    await db?.drop();
  });

  beforeEach(async () => {
    await db.pool.query("delete from offensive_scan_authorizations");
    await db.pool.query("delete from engagements");
    await db.pool.query("insert into engagements (id, owner, reference, created_by, state) values ($1, $2, 'one', $2, 'in_window'), ($3, $2, 'two', $2, 'in_window')", [ENGAGEMENT, OWNER, OTHER_ENGAGEMENT]);
  });

  it("aborts, revokes every linked authorisation and withdraws open simulations", async () => {
    await authorisation("a.test", ENGAGEMENT);
    await authorisation("b.test", ENGAGEMENT);
    await simulation("planned");
    await simulation("accepted");
    await simulation("validation_scheduled");

    expect(await abort()).toEqual({ outcome: "aborted", from: "in_window", revoked_hosts: ["a.test", "b.test"], simulations_withdrawn: 3 });

    expect(await revokedAt("a.test")).not.toBeNull();
    expect(await revokedAt("b.test")).not.toBeNull();
    const { rows } = await db.pool.query("select state, aborted_at, abort_reason from engagements where id = $1", [ENGAGEMENT]);
    expect(rows[0]).toMatchObject({ state: "aborted", abort_reason: "stop" });
    expect(rows[0].aborted_at).not.toBeNull();
    const statuses = await db.pool.query("select distinct status from exploit_simulations where engagement_id = $1", [ENGAGEMENT]);
    expect(statuses.rows).toEqual([{ status: "withdrawn" }]);
  });

  it("leaves other engagements' authorisations, and unlinked ones, alone", async () => {
    await authorisation("linked.test", ENGAGEMENT);
    await authorisation("other.test", OTHER_ENGAGEMENT);
    await authorisation("legacy.test", null);
    await simulation("planned", OTHER_ENGAGEMENT);

    await abort();

    expect(await revokedAt("linked.test")).not.toBeNull();
    expect(await revokedAt("other.test")).toBeNull();
    expect(await revokedAt("legacy.test")).toBeNull();
    const other = await db.pool.query("select status from exploit_simulations where engagement_id = $1", [OTHER_ENGAGEMENT]);
    expect(other.rows).toEqual([{ status: "planned" }]);
  });

  it("revokes anything linked since when run again, keeping the first reason", async () => {
    await abort(ENGAGEMENT, "first");
    await authorisation("late.test", ENGAGEMENT);

    expect(await abort(ENGAGEMENT, "second")).toEqual({ outcome: "already_aborted", from: "aborted", revoked_hosts: ["late.test"], simulations_withdrawn: 0 });
    const { rows } = await db.pool.query("select abort_reason from engagements where id = $1", [ENGAGEMENT]);
    expect(rows[0].abort_reason).toBe("first");
  });

  it("leaves a closed engagement alone and says so", async () => {
    await db.pool.query("update engagements set state = 'closed' where id = $1", [ENGAGEMENT]);
    await authorisation("closed.test", ENGAGEMENT);

    expect(await abort()).toEqual({ outcome: "closed" });
    expect(await revokedAt("closed.test")).toBeNull();
  });

  it("reports an engagement that doesn't exist", async () => {
    expect(await abort("e9000000-0000-0000-0000-000000000009")).toEqual({ outcome: "not_found" });
  });

  it("can be called by the service role, and by no client", async () => {
    const asRole = (actor: Actor) => asActor(db, actor, (c) => attempt(c, ABORT, [ENGAGEMENT, "x"]));
    expect((await asRole({ role: "anon" })).code).toBe("42501");
    expect((await asRole({ role: "authenticated", uid: OWNER })).code).toBe("42501");
    const { rows } = await db.pool.query("select state from engagements where id = $1", [ENGAGEMENT]);
    expect(rows[0].state).toBe("in_window");
    expect((await asRole({ role: "service_role" })).ok).toBe(true);
  });
});
