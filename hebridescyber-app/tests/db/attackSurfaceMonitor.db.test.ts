// Attack-surface alerts (src/lib/attackSurfaceMonitor.ts) against a real
// database through a real PostgREST, via supabase-js. The unit tests use a
// fake that can't confirm PostgREST accepts what the claim-and-release logic
// depends on: `.or()` with `ilike` host patterns, `.range()` paging, an
// update returning the rows it changed (the hostname claim), and an update
// filtered on an exact timestamptz read back from PostgREST (the DNS claim
// and its release).
//
// Needs the PostgREST binary (POSTGREST_BIN); skipped without it.
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));
vi.mock("../../src/lib/email", async (orig) => ({ ...(await orig<typeof import("../../src/lib/email")>()), sendEmail: sendEmailMock }));

import type { SupabaseClient } from "@supabase/supabase-js";
import { DB_TESTS_ENABLED, createTestDb, type TestDb } from "./harness";
import { POSTGREST_BIN, startPostgrest, type Postgrest } from "./postgrest";
import { firstCertificates, sendAttackSurfaceAlerts, sendSweepHostnameAlerts, type DnsResolver } from "../../src/lib/attackSurfaceMonitor";
import type { ReconResult } from "../../src/lib/scanners/recon";

const enabled = DB_TESTS_ENABLED && !!POSTGREST_BIN;

const PORT = 3993;
const OWNER = "aaaaaaaa-0000-0000-0000-0000000000a5";
const SCAN = "22222222-0000-0000-0000-000000000001";
const TARGET = "https://www.shop.example.com";
const NOW = new Date();
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString().slice(0, 19);

const RECON: ReconResult = {
  status: "checked",
  ip: null,
  shodan: null,
  subdomains: [
    { name: "new.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) },
    { name: "old.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(900) },
  ],
};

function resolver(mx: string): DnsResolver {
  return {
    resolveNs: async () => ["ns1.host.example"],
    resolveMx: async () => [{ priority: 10, exchange: mx }],
    resolveTxt: async (name) => (name.startsWith("_dmarc.") ? [["v=DMARC1; p=reject"]] : [["v=spf1 -all"]]),
  };
}

describe.skipIf(!enabled)("attack-surface alerts against real PostgREST + Postgres", () => {
  let db: TestDb;
  let postgrest: Postgrest;
  let client: SupabaseClient;
  const q = (sql: string, params: unknown[] = []) => db.pool.query(sql, params);
  const run = (mx: string, target = TARGET) => sendAttackSurfaceAlerts(client, OWNER, SCAN, target, RECON, { resolver: resolver(mx), now: new Date() });

  beforeAll(async () => {
    db = await createTestDb();
    // Migration 059's handle_new_user() trigger creates the matching
    // public.users row automatically on this insert.
    await q("insert into auth.users (id, email) values ($1, 'owner@example.com')", [OWNER]);
    await q("insert into subscriptions (owner, plan, status) values ($1, 'pro', 'active')", [OWNER]);
    await q("insert into scans (id, owner, target_url, status) values ($1, $2, $3, 'completed')", [SCAN, OWNER, TARGET]);
    // An earlier scan of this exact host, plus look-alikes the host pattern must not mistake for it.
    await q("insert into scans (owner, target_url, status, created_at) values ($1, 'https://www.shop.example.com/', 'completed', now() - interval '2 days')", [OWNER]);
    await q("insert into scans (owner, target_url, status, created_at) values ($1, 'https://www.shop.example.com.evil.example', 'completed', now() - interval '90 days')", [OWNER]);
    postgrest = await startPostgrest(db, PORT);
    client = postgrest.client;
  }, 60_000);

  afterAll(async () => {
    postgrest?.stop();
    await db?.drop();
  });

  beforeEach(async () => {
    sendEmailMock.mockReset();
    sendEmailMock.mockResolvedValue({ ok: true });
    await q("delete from asset_inventory where owner = $1", [OWNER]);
    await q("delete from dns_snapshots where owner = $1", [OWNER]);
    for (const h of ["www.shop.example.com", "new.example.com", "old.example.com"]) {
      await q("insert into asset_inventory (owner, target_url, hostname, kind) values ($1, $2, $3, 'subdomain')", [OWNER, TARGET, h]);
    }
    // A snapshot with a microsecond timestamp, as now() writes: the DNS claim must match it exactly.
    await q(
      "insert into dns_snapshots (owner, target_host, ns, mx, spf, dmarc, known_fields, captured_at) values ($1, 'example.com', '{ns1.host.example}', '{10 mail.example.com}', 'v=spf1 -all', 'v=DMARC1; p=reject', '{ns,mx,spf,dmarc}', now() - interval '1 day')",
      [OWNER]
    );
  });

  const pending = async () => (await q("select hostname from asset_inventory where owner = $1 and notified_at is null order by 1", [OWNER])).rows.map((r) => r.hostname);
  const snapshot = async () => (await q("select mx, captured_at from dns_snapshots where owner = $1", [OWNER])).rows[0];

  it("claims, sends and records a new hostname and a DNS change", async () => {
    const result = await run("mx.attacker.example");
    expect(result.errors).toEqual([]);
    expect(result.reported?.newHostnames.map((h) => h.name)).toEqual(["new.example.com"]);
    expect(result.reported?.dnsChanges).toEqual([{ field: "mx", before: ["10 mail.example.com"], after: ["10 mx.attacker.example"] }]);
    expect(result.silentlyRecorded.sort()).toEqual(["old.example.com", "www.shop.example.com"]);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(await pending()).toEqual([]);
    expect((await snapshot()).mx).toEqual(["10 mx.attacker.example"]);

    expect((await run("mx.attacker.example")).reported).toBeNull();
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
  });

  it("puts everything back when nothing was delivered", async () => {
    const before = await snapshot();
    sendEmailMock.mockResolvedValue({ ok: false, error: "down" });
    const result = await run("mx.attacker.example");
    expect(result.errors).toEqual(["email failed: down"]);
    expect(await pending()).toEqual(["new.example.com"]);
    const after = await snapshot();
    expect(after.mx).toEqual(["10 mail.example.com"]);
    expect(after.captured_at.toISOString()).toBe(before.captured_at.toISOString());
  });

  it("sends each change once when scans of www and the bare domain finish together", async () => {
    const results = await Promise.all([run("mx.attacker.example"), run("mx.attacker.example"), run("mx.attacker.example", "https://shop.example.com")]);
    const sent = results.flatMap((r) => (r.reported ? [...r.reported.newHostnames.map((h) => h.name), ...r.reported.dnsChanges.map((c) => c.field)] : []));
    expect(sent.sort()).toEqual(["mx", "new.example.com"]);
    expect(results.flatMap((r) => r.errors)).toEqual([]);
  });

  it("pages through more unreported hostnames than one request returns", async () => {
    await q(
      "insert into asset_inventory (owner, target_url, hostname, kind) select $1, $2, 'h' || g || '.example.com', 'subdomain' from generate_series(1, 2100) g",
      [OWNER, TARGET]
    );
    const result = await run("mail.example.com");
    expect(result.errors).toEqual([]);
    expect(result.silentlyRecorded).toHaveLength(2102);
    expect(await pending()).toEqual([]);
  });

  describe("the standalone EASM sweep's alert", () => {
    const sweep = () => sendSweepHostnameAlerts(client, OWNER, TARGET, { firstCertificates: firstCertificates(RECON), ctRead: true }, { now: new Date() });

    it("reports hostnames stored under a different URL, which the scan alert never could", async () => {
      // The EASM step used to store https://<domain>; a scan of https://www.<domain> reads by its own exact URL.
      await q("delete from asset_inventory where owner = $1", [OWNER]);
      await q("insert into asset_inventory (owner, target_url, hostname, kind) values ($1, 'https://example.com', 'new.example.com', 'subdomain')", [OWNER]);

      expect((await run("mail.example.com")).reported).toBeNull(); // the scan alert cannot see the row...
      expect(await pending()).toEqual(["new.example.com"]); // ...so it stays pending

      const result = await sweep(); // the sweep reads by owner and domain, through the real .or(ilike) filter
      expect(result.errors).toEqual([]);
      expect(result.reported?.newHostnames.map((h) => h.name)).toEqual(["new.example.com"]);
      expect(await pending()).toEqual([]);
    });

    it("sends each hostname once when a scan and two sweeps finish together", async () => {
      const results = await Promise.all([sweep(), sweep(), run("mail.example.com")]);
      const sent = results.flatMap((r) => (r.reported ? r.reported.newHostnames.map((h) => h.name) : []));
      expect(sent).toEqual(["new.example.com"]);
      expect(results.flatMap((r) => r.errors)).toEqual([]);
      expect(sendEmailMock).toHaveBeenCalledTimes(1);
    });

    it("leaves a hostname pending when crt.sh could not be read", async () => {
      const result = await sendSweepHostnameAlerts(client, OWNER, TARGET, { firstCertificates: new Map(), ctRead: false }, { now: new Date() });
      expect(result).toMatchObject({ hostnamesDeferred: true, delivered: false });
      expect(await pending()).toEqual(["new.example.com", "old.example.com", "www.shop.example.com"]);
      expect(sendEmailMock).not.toHaveBeenCalled();
    });
  });
});
