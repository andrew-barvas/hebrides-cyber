// The cross-site findings loader (src/lib/findingsView.ts) against a real
// database through a real PostgREST, via supabase-js — the same path
// production takes. The unit tests only exercise it against fakes, which can't
// confirm PostgREST accepts the query shapes (`findings:results->findings`,
// `.is("resolved_at", null)`, `.in("scan_id", …)`) or that RLS-bypassing
// service reads return what the loader expects.
//
// Needs the PostgREST binary: set POSTGREST_BIN to its path (the db-tests
// workflow downloads the official release). Skipped without it.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { createHmac } from "node:crypto";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { DB_TESTS_ENABLED, createTestDb, type TestDb } from "./harness";
import { loadFindingsView } from "../../src/lib/findingsView";

// supabase-js builds its realtime client eagerly and throws on Node 20, which
// has no native WebSocket (Node 22+ does). This test never uses realtime.
if (!("WebSocket" in globalThis)) (globalThis as Record<string, unknown>).WebSocket = class {};

const POSTGREST_BIN = process.env.POSTGREST_BIN;
const enabled = DB_TESTS_ENABLED && !!POSTGREST_BIN;

const SECRET = "test-secret-test-secret-test-secret-1234";
const PORT = 3991; // PostgREST
const API_PORT = 3992; // what supabase-js talks to: /rest/v1/* forwarded to PostgREST
const A = "aaaaaaaa-0000-0000-0000-000000000001";
const B = "bbbbbbbb-0000-0000-0000-000000000002";
const SCAN_OLD = "11111111-0000-0000-0000-000000000001";
const SCAN_NEW = "11111111-0000-0000-0000-000000000002";
const SCAN_B = "11111111-0000-0000-0000-000000000003";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function jwt(role: string): string {
  const head = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ role, exp: Math.floor(Date.now() / 1000) + 3600 })}`;
  return `${head}.${createHmac("sha256", SECRET).update(head).digest("base64url")}`;
}

describe.skipIf(!enabled)("loadFindingsView against real PostgREST + Postgres", () => {
  let db: TestDb;
  let server: ChildProcess;
  let proxy: Server;
  let client: SupabaseClient;

  beforeAll(async () => {
    db = await createTestDb();
    const q = (sql: string, params: unknown[] = []) => db.pool.query(sql, params);
    for (const [id, email] of [[A, "a@x.test"], [B, "b@x.test"]]) {
      await q("insert into auth.users (id, email) values ($1, $2)", [id, email]);
      await q("insert into public.users (id, email) values ($1, $2)", [id, email]);
    }
    await q("insert into subscriptions (owner, plan, status) values ($1, 'agency', 'active')", [A]);

    // Owner A: site one.test has an older and a newer completed scan; site two.test only an older failed-then-none.
    await q("insert into scans (id, owner, target_url, status, created_at) values ($1, $2, 'https://one.test', 'completed', now() - interval '2 days')", [SCAN_OLD, A]);
    await q("insert into scans (id, owner, target_url, status, created_at) values ($1, $2, 'https://one.test/', 'completed', now() - interval '1 day')", [SCAN_NEW, A]);
    await q("insert into scans (id, owner, target_url, status) values ($1, $2, 'https://b.test', 'completed')", [SCAN_B, B]);
    const finding = (checkId: string, over: Record<string, unknown> = {}) => ({ checkId, severity: "high", title: `title ${checkId}`, detail: `detail ${checkId}`, ...over });
    await q("insert into scan_results (scan_id, results) values ($1, $2)", [SCAN_OLD, JSON.stringify({ findings: [finding("headers.old-only")] })]);
    await q("insert into scan_results (scan_id, results) values ($1, $2)", [SCAN_NEW, JSON.stringify({
      findings: [
        finding("headers.hsts-missing", { cveIds: [], threatIntel: { knownExploited: true, epss: 0.42 } }),
        finding("recon.shodan-cves", { cveIds: ["CVE-2099-1"] }),
      ],
    })]);
    await q("insert into scan_results (scan_id, results) values ($1, $2)", [SCAN_B, JSON.stringify({ findings: [finding("headers.hsts-missing")] })]);

    const lifecycle = `insert into finding_lifecycle (owner, target_host, check_id, severity, title, first_seen_at, last_seen_at, resolved_at, last_scan_id)
                       values ($1, $2, $3, $4, $5, now() - interval '10 days', now(), $6, $7)`;
    await q(lifecycle, [A, "one.test", "headers.hsts-missing", "high", "HSTS missing", null, SCAN_NEW]);
    await q(lifecycle, [A, "one.test", "recon.shodan-cves", "high", "Known CVEs", null, SCAN_NEW]);
    await q(lifecycle, [A, "one.test", "headers.fixed", "high", "Already fixed", new Date().toISOString(), SCAN_NEW]);
    await q(lifecycle, [A, "two.test", "dns.spf-missing", "medium", "No SPF", null, null]);
    await q(lifecycle, [B, "b.test", "headers.hsts-missing", "high", "HSTS missing", null, SCAN_B]);
    await q("insert into finding_triage (owner, target_host, check_id, state, reason) values ($1, 'one.test', 'recon.shodan-cves', 'accepted_risk', 'documented and accepted')", [A]);
    await q("insert into finding_triage (owner, target_host, check_id, state, reason, expires_at) values ($1, 'two.test', 'dns.spf-missing', 'snoozed', 'snoozed in the past', now() - interval '1 day')", [A]);

    const dir = mkdtempSync(path.join(tmpdir(), "postgrest-"));
    const conf = path.join(dir, "postgrest.conf");
    writeFileSync(conf, [`db-uri = "${db.url}"`, `db-schemas = "public"`, `db-anon-role = "anon"`, `jwt-secret = "${SECRET}"`, `server-port = ${PORT}`, `server-host = "127.0.0.1"`, ""].join("\n"));
    server = spawn(POSTGREST_BIN as string, [conf], { stdio: "ignore" });
    for (let i = 0; i < 60; i++) {
      try {
        if ((await fetch(`http://127.0.0.1:${PORT}/`, { headers: { apikey: jwt("service_role") } })).status < 500) break;
      } catch {
        // not up yet
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    // supabase-js addresses PostgREST at /rest/v1 (as Supabase's gateway does); PostgREST serves at the root.
    proxy = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const upstream = await fetch(`http://127.0.0.1:${PORT}${(req.url ?? "").replace(/^\/rest\/v1/, "")}`, {
          method: req.method,
          headers: Object.fromEntries(Object.entries(req.headers).filter(([k]) => k !== "host" && k !== "content-length") as [string, string][]),
          body: ["GET", "HEAD"].includes(req.method ?? "GET") ? undefined : Buffer.concat(chunks),
        });
        res.writeHead(upstream.status, Object.fromEntries(upstream.headers.entries()));
        res.end(Buffer.from(await upstream.arrayBuffer()));
      });
    }).listen(API_PORT, "127.0.0.1");
    client = createClient(`http://127.0.0.1:${API_PORT}`, jwt("service_role"), { auth: { persistSession: false } });
  }, 60_000);

  afterAll(async () => {
    server?.kill();
    proxy?.close();
    await db?.drop();
  });

  it("lists only the owner's open findings, with detail from each site's latest completed scan", async () => {
    const result = await loadFindingsView(client, A);
    if (!result.ok) throw new Error(result.error);
    const { data } = result;
    expect(data).toMatchObject({ available: true, triageAvailable: true, slaEnabled: true, detailComplete: true, truncated: false });

    const keys = data.rows.map((r) => r.key).sort();
    expect(keys).toEqual(["one.test headers.hsts-missing", "one.test recon.shodan-cves", "two.test dns.spf-missing"]);

    const hsts = data.rows.find((r) => r.checkId === "headers.hsts-missing");
    expect(hsts).toMatchObject({ host: "one.test", knownExploited: true, epss: 0.42, scanId: SCAN_NEW });
    expect(hsts?.detail).toBe("detail headers.hsts-missing"); // from the NEWER scan, the newest completed scan of one.test
    expect(data.rows.find((r) => r.checkId === "recon.shodan-cves")?.cveIds).toEqual(["CVE-2099-1"]);
  });

  it("applies active triage, and treats an expired snooze as no triage", async () => {
    const result = await loadFindingsView(client, A);
    if (!result.ok) throw new Error(result.error);
    expect(result.data.rows.find((r) => r.checkId === "recon.shodan-cves")?.triage).toMatchObject({ state: "accepted_risk" });
    expect(result.data.rows.find((r) => r.checkId === "dns.spf-missing")?.triage).toBeNull();
  });

  it("keeps a finding that no completed scan carries, without detail", async () => {
    const result = await loadFindingsView(client, A);
    if (!result.ok) throw new Error(result.error);
    const spf = result.data.rows.find((r) => r.checkId === "dns.spf-missing");
    expect(spf).toMatchObject({ host: "two.test", knownExploited: false, epss: null });
  });

  it("never returns another owner's findings", async () => {
    const result = await loadFindingsView(client, B);
    if (!result.ok) throw new Error(result.error);
    expect(result.data.rows.map((r) => r.key)).toEqual(["b.test headers.hsts-missing"]);
    expect(result.data.slaEnabled).toBe(false); // B has no subscription
  });
});
