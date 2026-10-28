// @vitest-environment node
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DB_TESTS_ENABLED, asActor, attempt, createTestDb, type Actor, type TestDb } from "./harness";

// Fixed ids so assertions read clearly.
const A = "aaaaaaaa-0000-0000-0000-000000000001"; // owner A (active pro subscription)
const B = "bbbbbbbb-0000-0000-0000-000000000002"; // owner B (no subscription)
const M = "cccccccc-0000-0000-0000-000000000003"; // member of A's team
const SCAN_A = "a1000000-0000-0000-0000-000000000001";
const SCAN_B = "b1000000-0000-0000-0000-000000000002";

const asA: Actor = { role: "authenticated", uid: A };
const asB: Actor = { role: "authenticated", uid: B };
const asM: Actor = { role: "authenticated", uid: M };
const anon: Actor = { role: "anon" };
const service: Actor = { role: "service_role" };

/**
 * Per-table: how to select "the owner's rows", and a valid insert for an owner.
 * ownerCol is the column that holds the owning user id.
 */
interface TableSpec {
  table: string;
  ownerCol: string;
  /** insert statement taking the owner uuid as $1 (and unique-safe) */
  insert: string;
}

const KEY_TABLES: TableSpec[] = [
  { table: "scans", ownerCol: "owner", insert: "insert into scans (owner, target_url) values ($1, 'https://x.test')" },
  { table: "subscriptions", ownerCol: "owner", insert: "insert into subscriptions (owner, plan) values ($1, 'basic')" },
  { table: "finding_lifecycle", ownerCol: "owner", insert: "insert into finding_lifecycle (owner, target_host, check_id, severity, title, first_seen_at, last_seen_at) values ($1, 'new.test', 'c.new', 'low', 't', now(), now())" },
  { table: "finding_triage", ownerCol: "owner", insert: "insert into finding_triage (owner, target_host, check_id, state, reason) values ($1, 'new.test', 'c.new', 'false_positive', 'a sufficiently long reason')" },
  { table: "ticket_links", ownerCol: "owner", insert: "insert into ticket_links (owner, provider, target_host, check_id, issue_key, issue_url) values ($1, 'jira', 'new.test', 'c.new', 'K-1', 'https://j.test/K-1')" },
  { table: "emerging_threat_alerts", ownerCol: "owner", insert: "insert into emerging_threat_alerts (owner, target_host, cve_id, confidence, product) values ($1, 'new.test', 'CVE-2099-1', 'affected', 'p')" },
  { table: "api_keys", ownerCol: "owner", insert: "insert into api_keys (owner, name, key_hash, key_prefix) values ($1, 'k', 'hash-new', 'hc_new')" },
  { table: "repo_connections", ownerCol: "owner", insert: "insert into repo_connections (owner, github_repo) values ($1, 'org/new')" },
  { table: "monitored_targets", ownerCol: "owner", insert: "insert into monitored_targets (owner, target_url) values ($1, 'https://new.test')" },
  { table: "verifications", ownerCol: "owner", insert: "insert into verifications (owner, domain, token) values ($1, 'new.test', 'tok-new')" },
  { table: "scan_jobs", ownerCol: "owner", insert: "insert into scan_jobs (owner, target_url) values ($1, 'https://new.test')" },
  { table: "deletion_requests", ownerCol: "owner", insert: "insert into deletion_requests (owner) values ($1)" },
  { table: "asset_inventory", ownerCol: "owner", insert: "insert into asset_inventory (owner, target_url, hostname, kind) values ($1, 'https://new.test', 'new.test', 'domain')" },
  { table: "dns_snapshots", ownerCol: "owner", insert: "insert into dns_snapshots (owner, target_host) values ($1, 'new.test')" },
  { table: "offensive_scan_authorizations", ownerCol: "owner", insert: "insert into offensive_scan_authorizations (owner, target_host, authorized_by, scope) values ($1, 'new.test', $1, 'ack')" },
  { table: "lookalike_domain_sweeps", ownerCol: "owner", insert: "insert into lookalike_domain_sweeps (owner, target_domain) values ($1, 'new.test')" },
  { table: "lookalike_domains", ownerCol: "owner", insert: "insert into lookalike_domains (owner, target_domain, candidate_domain, technique) values ($1, 'new.test', 'new-x.test', 'omission')" },
  { table: "cloud_credentials", ownerCol: "owner", insert: "insert into cloud_credentials (owner, provider, label, credentials_encrypted) values ($1, 'aws', 'new', '{}'::jsonb)" },
  { table: "sla_policies", ownerCol: "owner", insert: "insert into sla_policies (owner) values ($1)" },
  { table: "dmarc_reports", ownerCol: "owner", insert: "insert into dmarc_reports (owner, domain, org_name, report_id) values ($1, 'new.test', 'google.com', 'rpt-new')" },
  { table: "dmarc_ingest_tokens", ownerCol: "owner", insert: "insert into dmarc_ingest_tokens (owner, token) values ($1, 'tok-new-0123456789abcdef')" },
  { table: "ce_self_assessment", ownerCol: "owner", insert: "insert into ce_self_assessment (owner, control, question_key, answer) values ($1, 'Malware protection', 'malware.protection', 'yes')" },
  { table: "uptime_monitors", ownerCol: "owner", insert: "insert into uptime_monitors (owner, target_url, provider, external_id) values ($1, 'https://new.test', 'uptimerobot', '999')" },
];

// Tables a logged-in user may only READ (the server writes with the service
// role). Anything a client forges here would be trusted by server code.
const SERVICE_WRITE_ONLY = [
  "subscriptions", "finding_lifecycle", "finding_triage", "ticket_links",
  "emerging_threat_alerts", "repo_connections", "verifications", "scan_jobs",
  "deletion_requests", "asset_inventory", "dns_snapshots", "offensive_scan_authorizations",
  "lookalike_domain_sweeps", "lookalike_domains", "cloud_credentials", "sla_policies",
  "dmarc_reports", "dmarc_ingest_tokens", "ce_self_assessment", "uptime_monitors",
];

// Tables with no client policy at all: even the owner reads nothing.
const SERVICE_ONLY = ["audit_logs", "contact_enquiries", "uptime_integrations"];

// What a client insert attempt looks like for each service-only table, and the parameter it takes.
const SERVICE_ONLY_INSERTS: Record<string, { sql: string; param: string }> = {
  audit_logs: { sql: "insert into audit_logs (actor, action) values ($1, 'x.y')", param: A },
  contact_enquiries: { sql: "insert into contact_enquiries (name, email, message) values ('n', 'e@x.test', $1::text)", param: "m" },
  uptime_integrations: { sql: "insert into uptime_integrations (owner, provider, api_key) values ($1, 'uptimerobot', 'k')", param: A },
};

describe.skipIf(!DB_TESTS_ENABLED)("row level security (real Postgres)", () => {
  let db: TestDb;

  async function count(actor: Actor, sql: string, params: unknown[] = []): Promise<number> {
    return asActor(db, actor, async (c) => (await c.query(sql, params)).rowCount ?? 0);
  }

  beforeAll(async () => {
    db = await createTestDb();
    const q = (sql: string, p: unknown[] = []) => db.pool.query(sql, p);
    // Migration 059's handle_new_user() trigger creates the matching
    // public.users row automatically on this insert.
    for (const [id, email] of [[A, "a@x.test"], [B, "b@x.test"], [M, "m@x.test"]]) {
      await q("insert into auth.users (id, email) values ($1, $2)", [id, email]);
    }
    await q("insert into scans (id, owner, target_url) values ($1, $2, 'https://a.test')", [SCAN_A, A]);
    await q("insert into scans (id, owner, target_url) values ($1, $2, 'https://b.test')", [SCAN_B, B]);
    await q("insert into scan_results (scan_id, results) values ($1, '{}'), ($2, '{}')", [SCAN_A, SCAN_B]);
    await q("insert into subscriptions (owner, plan, status) values ($1, 'pro', 'active')", [A]);
    await q("insert into subscriptions (owner, plan, status) values ($1, 'basic', 'active')", [B]);
    for (const [o, h] of [[A, "a.test"], [B, "b.test"]]) {
      await q("insert into finding_lifecycle (owner, target_host, check_id, severity, title, first_seen_at, last_seen_at) values ($1, $2, 'c.1', 'low', 't', now(), now())", [o, h]);
      await q("insert into finding_triage (owner, target_host, check_id, state, reason) values ($1, $2, 'c.1', 'false_positive', 'a sufficiently long reason')", [o, h]);
      await q("insert into ticket_links (owner, provider, target_host, check_id, issue_key, issue_url) values ($1, 'jira', $2, 'c.1', 'K-1', 'https://j.test/K-1')", [o, h]);
      await q("insert into emerging_threat_alerts (owner, target_host, cve_id, confidence, product) values ($1, $2, 'CVE-2099-0', 'affected', 'p')", [o, h]);
      await q("insert into api_keys (owner, name, key_hash, key_prefix) values ($1, 'k', $2, $3)", [o, `hash-${h}`, `hc_${h}`]);
      await q("insert into repo_connections (owner, github_repo) values ($1, $2)", [o, `org/${h}`]);
      await q("insert into monitored_targets (owner, target_url) values ($1, $2)", [o, `https://${h}`]);
      await q("insert into verifications (owner, domain, token) values ($1, $2, 'tok')", [o, h]);
      await q("insert into scan_jobs (owner, target_url) values ($1, $2)", [o, `https://${h}`]);
      await q("insert into deletion_requests (owner) values ($1)", [o]);
      await q("insert into asset_inventory (owner, target_url, hostname, kind) values ($1, $2, $3, 'domain')", [o, `https://${h}`, h]);
      await q("insert into dns_snapshots (owner, target_host, ns) values ($1, $2, '{ns1.x.test}')", [o, h]);
      await q("insert into offensive_scan_authorizations (owner, target_host, authorized_by, scope) values ($1, $2, $1, 'ack')", [o, h]);
      await q("insert into lookalike_domain_sweeps (owner, target_domain) values ($1, $2)", [o, h]);
      await q("insert into lookalike_domains (owner, target_domain, candidate_domain, technique) values ($1, $2, $3, 'omission')", [o, h, `x-${h}`]);
      await q("insert into cloud_credentials (owner, provider, label, credentials_encrypted) values ($1, 'aws', $2, '{}'::jsonb)", [o, `cred-${h}`]);
      await q("insert into sla_policies (owner) values ($1)", [o]);
      await q("insert into dmarc_reports (owner, domain, org_name, report_id) values ($1, $2, 'google.com', $3)", [o, h, `rpt-${h}`]);
      await q("insert into dmarc_ingest_tokens (owner, token) values ($1, $2)", [o, `tok-${h}-0123456789abcdef`]);
      await q("insert into ce_self_assessment (owner, control, question_key, answer) values ($1, 'Malware protection', 'malware.protection', 'yes')", [o]);
      await q("insert into uptime_monitors (owner, target_url, provider, external_id) values ($1, $2, 'uptimerobot', $3)", [o, `https://${h}`, `ext-${h}`]);
      await q("insert into uptime_integrations (owner, provider, api_key) values ($1, 'uptimerobot', 'enc:k')", [o]);
    }
    await q("insert into audit_logs (actor, action) values ($1, 'scan.started')", [A]);
    await q("insert into contact_enquiries (name, email, message) values ('n', 'e@x.test', 'm')");
    await q("insert into tool_kill_switches (tool_name, disabled) values ('nuclei', true)");
    await q("insert into email_events (recipient_domain, subject, status) values ('acme.test', 's', 'sent')");
    // M is a member of A's team (read-only access to A's scans/targets).
    await q("insert into teams (id, name, owner_id) values ('dddddddd-0000-0000-0000-000000000004', 'A team', $1)", [A]);
    await q("insert into team_members (team_id, user_id) values ('dddddddd-0000-0000-0000-000000000004', $1)", [M]);
  });

  afterAll(async () => {
    await db?.drop();
  });

  describe.each(KEY_TABLES)("$table", ({ table, ownerCol, insert }) => {
    it("lets an owner read exactly their own rows", async () => {
      const mine = await asActor(db, asA, async (c) => (await c.query(`select ${ownerCol} from ${table}`)).rows);
      expect(mine.length).toBeGreaterThan(0);
      expect(mine.every((r) => r[ownerCol] === A)).toBe(true);
    });

    it("hides another owner's rows", async () => {
      expect(await count(asA, `select 1 from ${table} where ${ownerCol} = $1`, [B])).toBe(0);
      expect(await count(asB, `select 1 from ${table} where ${ownerCol} = $1`, [A])).toBe(0);
    });

    it("shows anon nothing", async () => {
      expect(await count(anon, `select 1 from ${table}`)).toBe(0);
    });

    it("lets the service role read everything", async () => {
      expect(await count(service, `select 1 from ${table}`)).toBeGreaterThanOrEqual(2);
    });

    it("rejects anon writes with an RLS violation", async () => {
      const r = await asActor(db, anon, (c) => attempt(c, insert, [A]));
      expect(r.ok).toBe(false);
      expect(r.code).toBe("42501");
    });

    it("rejects inserting a row owned by someone else with an RLS violation", async () => {
      const r = await asActor(db, asB, (c) => attempt(c, insert, [A]));
      expect(r.ok).toBe(false);
      expect(r.code).toBe("42501");
    });

    it("lets the service role insert", async () => {
      // fresh owner: several tables are unique per owner
      const owner = randomUUID();
      await db.pool.query("insert into auth.users (id, email) values ($1, $2)", [owner, `${owner}@x.test`]);
      const r = await asActor(db, service, (c) => attempt(c, insert, [owner]));
      expect(r.ok, `service_role insert failed: ${r.code}`).toBe(true);
    });
  });

  describe.each(SERVICE_WRITE_ONLY)("%s is service-role-write-only", (table) => {
    const spec = KEY_TABLES.find((t) => t.table === table)!;

    it("rejects an owner inserting their own row", async () => {
      const r = await asActor(db, asA, (c) => attempt(c, spec.insert, [A]));
      expect(r.ok).toBe(false);
      expect(r.code).toBe("42501");
    });

    it("silently affects zero rows on owner UPDATE and DELETE", async () => {
      await asActor(db, asA, async (c) => {
        const upd = await attempt(c, `update ${table} set ${spec.ownerCol} = ${spec.ownerCol}`);
        expect(upd.ok ? upd.rowCount : 0).toBe(0);
        const del = await attempt(c, `delete from ${table}`);
        expect(del.ok ? del.rowCount : 0).toBe(0);
      });
      const { rows } = await db.pool.query(`select count(*)::int n from ${table} where ${spec.ownerCol} = $1`, [A]);
      expect(rows[0].n).toBeGreaterThan(0);
    });
  });

  describe.each(SERVICE_ONLY)("%s has no client access", (table) => {
    it("returns nothing to owners or anon, and rejects client inserts", async () => {
      expect(await count(asA, `select 1 from ${table}`)).toBe(0);
      expect(await count(anon, `select 1 from ${table}`)).toBe(0);
      const { sql: ins, param } = SERVICE_ONLY_INSERTS[table];
      const r = await asActor(db, asA, (c) => attempt(c, ins, [param]));
      expect(r.ok).toBe(false);
      const anonR = await asActor(db, anon, (c) => attempt(c, ins, [param]));
      expect(anonR.ok).toBe(false);
      expect(await count(service, `select 1 from ${table}`)).toBeGreaterThan(0);
    });
  });

  describe("tool_kill_switches", () => {
    it("is service-role-only: owners and anon can neither read nor write it", async () => {
      expect(await count(asA, "select 1 from tool_kill_switches")).toBe(0);
      expect(await count(anon, "select 1 from tool_kill_switches")).toBe(0);
      const ins = "insert into tool_kill_switches (tool_name, disabled) values ('zap', true)";
      expect((await asActor(db, asA, (c) => attempt(c, ins))).ok).toBe(false);
      expect((await asActor(db, anon, (c) => attempt(c, ins))).ok).toBe(false);
      expect(await count(service, "select 1 from tool_kill_switches")).toBeGreaterThan(0);
    });
  });

  describe("email_events", () => {
    it("is service-role-only: owners and anon can neither read nor write it", async () => {
      expect(await count(asA, "select 1 from email_events")).toBe(0);
      expect(await count(anon, "select 1 from email_events")).toBe(0);
      const ins = "insert into email_events (recipient_domain, subject, status) values ('x.test', 's', 'sent')";
      expect((await asActor(db, asA, (c) => attempt(c, ins))).ok).toBe(false);
      expect((await asActor(db, anon, (c) => attempt(c, ins))).ok).toBe(false);
      expect(await count(service, "select 1 from email_events")).toBeGreaterThan(0);
    });
  });

  describe("scan_results", () => {
    it("is readable only through an owned scan", async () => {
      expect(await count(asA, "select 1 from scan_results where scan_id = $1", [SCAN_A])).toBe(1);
      expect(await count(asA, "select 1 from scan_results where scan_id = $1", [SCAN_B])).toBe(0);
      expect(await count(anon, "select 1 from scan_results")).toBe(0);
    });

    it("rejects client writes", async () => {
      await asActor(db, asA, async (c) => {
        expect((await attempt(c, "insert into scan_results (scan_id, results) values ($1, '{}')", [SCAN_A])).code).toBe("42501");
        const upd = await attempt(c, "update scan_results set score = 100");
        expect(upd.ok ? upd.rowCount : 0).toBe(0);
        const del = await attempt(c, "delete from scan_results");
        expect(del.ok ? del.rowCount : 0).toBe(0);
      });
    });
  });

  describe("scans (client-writable)", () => {
    it("lets an owner insert and delete their own scan", async () => {
      await asActor(db, asA, async (c) => {
        expect((await attempt(c, "insert into scans (owner, target_url) values ($1, 'https://n.test')", [A])).ok).toBe(true);
        const del = await attempt(c, "delete from scans where id = $1", [SCAN_A]);
        expect(del.rowCount).toBe(1);
      });
    });

    it("cannot delete or update another owner's scan", async () => {
      await asActor(db, asA, async (c) => {
        expect((await attempt(c, "delete from scans where id = $1", [SCAN_B])).rowCount).toBe(0);
        expect((await attempt(c, "update scans set status = 'failed' where id = $1", [SCAN_B])).rowCount).toBe(0);
      });
    });

    it("has no UPDATE policy, so a client cannot change its own scan status", async () => {
      await asActor(db, asA, async (c) => {
        const r = await attempt(c, "update scans set status = 'completed' where id = $1", [SCAN_A]);
        expect(r.rowCount).toBe(0);
      });
    });

    // KNOWN GAP (reported, not fixed): the INSERT policy only checks owner, so
    // a client can insert a scan with any status/owner_verified/proof_token.
    // owner_verified is display-only server-side (see retest-finding.ts), so
    // the impact is low (fabricated rows in the owner's own history, and the
    // free-tier counter in freeTier.ts counts rows the client can add). If a
    // migration tightens this policy, flip this test.
    it("KNOWN GAP: a client can forge owner_verified/status on its own scan", async () => {
      const r = await asActor(db, asA, (c) =>
        attempt(c, "insert into scans (owner, target_url, status, owner_verified) values ($1, 'https://forged.test', 'completed', true) returning id", [A]),
      );
      expect(r.ok).toBe(true);
    });
  });

  describe("monitored_targets (client-writable within plan cap)", () => {
    it("enforces the plan cap on insert (pro = 3, has 1)", async () => {
      await asActor(db, asA, async (c) => {
        expect((await attempt(c, "insert into monitored_targets (owner, target_url) values ($1, 'https://2.test')", [A])).ok).toBe(true);
        expect((await attempt(c, "insert into monitored_targets (owner, target_url) values ($1, 'https://3.test')", [A])).ok).toBe(true);
        const over = await attempt(c, "insert into monitored_targets (owner, target_url) values ($1, 'https://4.test')", [A]);
        expect(over.ok).toBe(false);
        expect(over.code).toBe("42501");
      });
    });

    it("rejects insert for an owner whose plan cap is 1 and is full (B)", async () => {
      const r = await asActor(db, asB, (c) => attempt(c, "insert into monitored_targets (owner, target_url) values ($1, 'https://extra.test')", [B]));
      expect(r.ok).toBe(false);
    });

    it("rejects insert when the user has no active subscription", async () => {
      await db.pool.query("update subscriptions set status = 'cancelled' where owner = $1", [B]);
      await db.pool.query("delete from monitored_targets where owner = $1", [B]);
      try {
        const r = await asActor(db, asB, (c) => attempt(c, "insert into monitored_targets (owner, target_url) values ($1, 'https://n.test')", [B]));
        expect(r.ok).toBe(false);
      } finally {
        await db.pool.query("update subscriptions set status = 'active' where owner = $1", [B]);
        await db.pool.query("insert into monitored_targets (owner, target_url) values ($1, 'https://b.test')", [B]);
      }
    });

    it("lets an owner update/delete their own target but not another's, nor re-home it", async () => {
      await asActor(db, asA, async (c) => {
        expect((await attempt(c, "update monitored_targets set scan_profile = 'safe' where owner = $1", [A])).rowCount).toBeGreaterThan(0);
        expect((await attempt(c, "update monitored_targets set scan_profile = 'safe' where owner = $1", [B])).rowCount).toBe(0);
        expect((await attempt(c, "delete from monitored_targets where owner = $1", [B])).rowCount).toBe(0);
        const rehome = await attempt(c, "update monitored_targets set owner = $1 where owner = $2", [B, A]);
        expect(rehome.ok).toBe(false);
        expect((await attempt(c, "delete from monitored_targets where owner = $1", [A])).rowCount).toBeGreaterThan(0);
      });
    });
  });

  describe("api_keys (owner can read/revoke/delete, never create)", () => {
    it("rejects client inserts", async () => {
      const r = await asActor(db, asA, (c) => attempt(c, "insert into api_keys (owner, name, key_hash, key_prefix) values ($1, 'k', 'h2', 'p2')", [A]));
      expect(r.ok).toBe(false);
    });

    it("lets an owner revoke and delete only their own keys", async () => {
      await asActor(db, asA, async (c) => {
        expect((await attempt(c, "update api_keys set revoked_at = now() where owner = $1", [A])).rowCount).toBe(1);
        expect((await attempt(c, "update api_keys set revoked_at = now() where owner = $1", [B])).rowCount).toBe(0);
        expect((await attempt(c, "update api_keys set owner = $1 where owner = $2", [B, A])).ok).toBe(false);
        expect((await attempt(c, "delete from api_keys where owner = $1", [B])).rowCount).toBe(0);
        expect((await attempt(c, "delete from api_keys where owner = $1", [A])).rowCount).toBe(1);
      });
    });
  });

  describe("users", () => {
    it("lets a user read only their own profile (plus their team owner's)", async () => {
      const ids = await asActor(db, asA, async (c) => (await c.query("select id from users")).rows.map((r) => r.id));
      expect(ids).toEqual([A]);
      const mIds = (await asActor(db, asM, async (c) => (await c.query("select id from users order by id")).rows.map((r) => r.id))).sort();
      expect(mIds).toEqual([A, M].sort());
    });

    it("lets a user edit their profile but never grant themselves admin", async () => {
      await asActor(db, asB, async (c) => {
        expect((await attempt(c, "update users set full_name = 'Bee' where id = $1", [B])).rowCount).toBe(1);
        const esc = await attempt(c, "update users set is_admin = true where id = $1", [B]);
        expect(esc.ok).toBe(false);
        expect(esc.code).toBe("42501");
        expect((await attempt(c, "update users set full_name = 'x' where id = $1", [A])).rowCount).toBe(0);
        expect((await attempt(c, "insert into users (id, email) values (gen_random_uuid(), 'new@x.test')")).ok).toBe(false);
      });
    });

    it("shows anon nothing", async () => {
      expect(await count(anon, "select 1 from users")).toBe(0);
    });
  });

  describe("team member (read-only access to the owner's data)", () => {
    it("reads the owner's scans, results and monitored targets", async () => {
      expect(await count(asM, "select 1 from scans where owner = $1", [A])).toBeGreaterThan(0);
      expect(await count(asM, "select 1 from scan_results where scan_id = $1", [SCAN_A])).toBe(1);
      expect(await count(asM, "select 1 from monitored_targets where owner = $1", [A])).toBeGreaterThan(0);
    });

    it("does not read other owners' data or the owner's non-shared tables", async () => {
      expect(await count(asM, "select 1 from scans where owner = $1", [B])).toBe(0);
      expect(await count(asM, "select 1 from subscriptions")).toBe(0);
      expect(await count(asM, "select 1 from api_keys")).toBe(0);
    });

    it("cannot write the owner's scans", async () => {
      await asActor(db, asM, async (c) => {
        expect((await attempt(c, "delete from scans where owner = $1", [A])).rowCount).toBe(0);
        expect((await attempt(c, "insert into scans (owner, target_url) values ($1, 'https://x.test')", [A])).ok).toBe(false);
      });
    });
  });

  describe("public content", () => {
    it("exposes only published blog posts to anon", async () => {
      await db.pool.query("insert into blog_posts (slug, title, excerpt, body, status, published_at) values ('pub', 't', 'e', 'b', 'published', now()), ('draft', 't', 'e', 'b', 'draft', null)");
      const slugs = await asActor(db, anon, async (c) => (await c.query("select slug from blog_posts")).rows.map((r) => r.slug));
      expect(slugs).toEqual(["pub"]);
      const w = await asActor(db, anon, (c) => attempt(c, "insert into blog_posts (slug, title, excerpt, body) values ('x', 't', 'e', 'b')"));
      expect(w.ok).toBe(false);
    });
  });

  describe("queue functions are not a bypass", () => {
    it("claim_scan_job called by a logged-in user cannot claim another owner's job", async () => {
      const claimed = await asActor(db, asA, async (c) => (await c.query("select * from claim_scan_job('rls-test')")).rows);
      expect(claimed.every((r) => r.owner === A)).toBe(true);
      const { rows } = await db.pool.query("select count(*)::int n from scan_jobs where owner = $1 and status <> 'pending'", [B]);
      expect(rows[0].n).toBe(0);
    });

    it("claim_scan_job called by anon claims nothing", async () => {
      const claimed = await asActor(db, anon, async (c) => (await c.query("select * from claim_scan_job('rls-test')")).rows);
      expect(claimed).toEqual([]);
      const { rows } = await db.pool.query("select count(*)::int n from scan_jobs where status <> 'pending'");
      expect(rows[0].n).toBe(0);
    });

    it("reset_stale_scan_jobs called by a client changes nothing", async () => {
      await db.pool.query("update scan_jobs set status = 'running', claimed_at = now() - interval '1 day' where owner = $1", [B]);
      try {
        await asActor(db, asA, (c) => c.query("select reset_stale_scan_jobs()"));
        await asActor(db, anon, (c) => c.query("select reset_stale_scan_jobs()"));
        const { rows } = await db.pool.query("select status from scan_jobs where owner = $1", [B]);
        expect(rows.every((r) => r.status === "running")).toBe(true);
      } finally {
        await db.pool.query("update scan_jobs set status = 'pending', claimed_at = null where owner = $1", [B]);
      }
    });
  });
});
