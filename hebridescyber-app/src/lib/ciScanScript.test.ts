// public/ci/hebrides-scan.sh is the scan gate customers run in GitLab,
// Jenkins, Azure DevOps, Bitbucket or GitHub Actions. It runs here for real
// (sh + curl + jq) against a local stand-in for the API, so the gate it
// applies is tested against the same rules as the packaged Action's
// blockingFindings (githubAction.test.ts).
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const SCRIPT = path.resolve(process.cwd(), "public", "ci", "hebrides-scan.sh");
const hasTools = spawnSync("sh", ["-c", "command -v curl && command -v jq"]).status === 0;
// Customers run it under whatever sh their image has: dash, bash, busybox.
const SHELLS = ["dash", "bash", "busybox"].filter((s) => spawnSync("sh", ["-c", `command -v ${s}`]).status === 0);

type Reply = { status: number; body: unknown };
let replies: { post: Reply; gets: Reply[] };
let requests: { method: string; url: string; auth: string | undefined; body: string }[];
let server: Server;
let base: string;
let dir: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", () => {
      requests.push({ method: req.method ?? "", url: req.url ?? "", auth: req.headers.authorization, body });
      const reply = req.method === "POST" ? replies.post : replies.gets.length > 1 ? replies.gets.shift()! : replies.gets[0];
      res.writeHead(reply.status, { "content-type": "application/json" });
      res.end(typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  base = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
});

afterAll(() => {
  server.close();
});

beforeEach(() => {
  requests = [];
  dir = mkdtempSync(path.join(tmpdir(), "hebrides-ci-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

let shell = "sh";

function run(env: Record<string, string>): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(shell, shell === "busybox" ? ["sh", SCRIPT] : [SCRIPT], {
      cwd: dir,
      env: {
        PATH: process.env.PATH ?? "",
        NO_PROXY: "127.0.0.1,localhost",
        no_proxy: "127.0.0.1,localhost",
        HEBRIDES_API_BASE_URL: base,
        HEBRIDES_CYBER_API_KEY: "hc_test_key",
        HEBRIDES_TARGET_URL: "https://staging.example.com",
        HEBRIDES_POLL_SECONDS: "0",
        ...env,
      } as unknown as NodeJS.ProcessEnv,
    });
    let out = "";
    child.stdout.on("data", (d: Buffer) => {
      out += d;
    });
    child.stderr.on("data", (d: Buffer) => {
      out += d;
    });
    child.on("close", (code) => resolve({ code, out }));
  });
}

const SCAN_ID = "b3f1c2d4-0000-4000-8000-000000000001";
const queued: Reply = { status: 202, body: { scan_id: SCAN_ID, status: "queued" } };
const f = (check_id: string, severity: string, extra: Record<string, unknown> = {}) => ({ check_id, severity, title: check_id, status: "new", detail: "d", ...extra });
const done = (findings: unknown[], compared = true): Reply => ({ status: 200, body: { scan_id: SCAN_ID, status: "completed", score: 81, compared_to_previous_scan: compared, findings } });

describe.skipIf(!hasTools).each(SHELLS.length ? SHELLS : ["sh"])("hebrides-scan.sh under %s", (sh) => {
  beforeEach(() => {
    shell = sh;
  });

  it("queues the target, polls until complete, and fails on a new untriaged high finding", async () => {
    replies = { post: queued, gets: [{ status: 200, body: { status: "queued" } }, { status: 200, body: { status: "running" } }, done([f("tls.weak", "high"), f("dns.spf", "low", { status: "unchanged" })])] };
    const { code, out } = await run({});
    expect(code).toBe(1);
    expect(out).toContain("Security score: 81/100");
    expect(out).toContain(`Report: ${base}/dashboard/scans/${SCAN_ID}`);
    expect(out).toContain("NEW [high] tls.weak");
    expect(out).toContain('1 new finding(s) at or above "high"');
    expect(requests[0]).toMatchObject({ method: "POST", url: "/api/v1/scans", auth: "Bearer hc_test_key" });
    expect(JSON.parse(requests[0].body)).toEqual({ target_url: "https://staging.example.com" });
    expect(requests.slice(1).every((r) => r.method === "GET" && r.url === `/api/v1/scans/${SCAN_ID}` && r.auth === "Bearer hc_test_key")).toBe(true);
    expect(requests).toHaveLength(4);
    expect(JSON.parse(readFileSync(path.join(dir, "hebrides-scan.json"), "utf8")).score).toBe(81);
  });

  it("does not count triaged findings, but an expired snooze counts again", async () => {
    const accepted = f("a", "critical", { triage: { state: "accepted_risk", expires_at: null } });
    const snoozed = f("b", "high", { triage: { state: "snoozed", expires_at: "2999-01-01T00:00:00.000Z" } });
    const expired = f("c", "high", { triage: { state: "snoozed", expires_at: "2020-01-01T00:00:00.000Z" } });
    replies = { post: queued, gets: [done([accepted, snoozed])] };
    const ok = await run({});
    expect(ok.code).toBe(0);
    expect(ok.out).toContain("(triaged: accepted_risk, not counted)");
    expect(ok.out).toContain("No untriaged new findings");
    replies = { post: queued, gets: [done([accepted, snoozed, expired])] };
    expect((await run({})).code).toBe(1);
  });

  it("applies the threshold, and never fails with fail-on none", async () => {
    replies = { post: queued, gets: [done([f("m", "medium")])] };
    expect((await run({ HEBRIDES_FAIL_ON: "high" })).code).toBe(0);
    expect((await run({ HEBRIDES_FAIL_ON: "MEDIUM" })).code).toBe(1);
    replies = { post: queued, gets: [done([f("x", "critical")])] };
    const none = await run({ HEBRIDES_FAIL_ON: "none" });
    expect(none.code).toBe(0);
    expect(none.out).toContain("not failing (HEBRIDES_FAIL_ON=none)");
  });

  it("passes the first scan of a target, which has no baseline", async () => {
    replies = { post: queued, gets: [done([f("x", "critical", { status: null })], false)] };
    const { code, out } = await run({});
    expect(code).toBe(0);
    expect(out).toContain("First scan of this target");
  });

  it("writes a JUnit report: failures for blocking findings, skipped for triaged, escaped text", async () => {
    replies = { post: queued, gets: [done([f("xss", "high", { title: 'Reflected <script> & "quotes"' }), f("t", "high", { triage: { state: "false_positive" } }), f("m", "medium")])] };
    const { code } = await run({ HEBRIDES_JUNIT_FILE: "junit.xml" });
    expect(code).toBe(1);
    const xml = readFileSync(path.join(dir, "junit.xml"), "utf8");
    expect(xml).toContain('<testsuite name="Hebrides Cyber security scan" tests="3" failures="1" skipped="1">');
    expect(xml).toContain("Reflected &lt;script&gt; &amp; &quot;quotes&quot; (xss)");
    expect(xml).toContain('<skipped message="Triaged: false_positive"/>');
    expect(xml).toContain('<failure message="New high finding">d</failure>');
    expect(xml).not.toContain("<script>");

    replies = { post: queued, gets: [done([])] };
    await run({ HEBRIDES_JUNIT_FILE: "junit.xml" });
    expect(readFileSync(path.join(dir, "junit.xml"), "utf8")).toContain('name="No new findings since the previous scan"');
  });

  it("annotates for GitHub Actions and Azure DevOps", async () => {
    replies = { post: queued, gets: [done([f("tls.weak", "high")])] };
    expect((await run({ GITHUB_ACTIONS: "true" })).out).toContain("::error::NEW [high] tls.weak");
    expect((await run({ TF_BUILD: "True" })).out).toContain("##vso[task.logissue type=error]NEW [high] tls.weak");
  });

  it("exits 2, never 0, when the scan can't be queued, fails, or times out", async () => {
    replies = { post: { status: 403, body: { error: "Domain not verified: staging.example.com" } }, gets: [] };
    const unverified = await run({});
    expect(unverified.code).toBe(2);
    expect(unverified.out).toContain("HTTP 403");
    expect(unverified.out).toContain("Domain not verified");

    replies = { post: queued, gets: [{ status: 200, body: { status: "failed" } }] };
    expect((await run({})).code).toBe(2);

    replies = { post: queued, gets: [{ status: 200, body: { status: "running" } }] };
    const slow = await run({ HEBRIDES_TIMEOUT_SECONDS: "0" });
    expect(slow.code).toBe(2);
    expect(slow.out).toContain("did not finish within 0 seconds");

    replies = { post: queued, gets: [{ status: 500, body: "oops" }] };
    expect((await run({})).code).toBe(2);

    replies = { post: { status: 202, body: { scan_id: "../../admin" } }, gets: [] };
    expect((await run({})).out).toContain("did not return a scan id");

    expect(existsSync(path.join(dir, "hebrides-scan.json"))).toBe(false);
  });

  it("exits 2 on missing or bad settings, and on an unreachable API", async () => {
    replies = { post: queued, gets: [] };
    expect((await run({ HEBRIDES_CYBER_API_KEY: "" })).out).toContain("HEBRIDES_CYBER_API_KEY is not set");
    expect((await run({ HEBRIDES_TARGET_URL: "" })).code).toBe(2);
    expect((await run({ HEBRIDES_FAIL_ON: "severe" })).out).toContain("must be critical, high, medium, low or none");
    expect((await run({ HEBRIDES_POLL_SECONDS: "1.5" })).code).toBe(2);
    const down = await run({ HEBRIDES_API_BASE_URL: "http://127.0.0.1:9" });
    expect(down.code).toBe(2);
    expect(down.out).toContain("HTTP 000");
    expect(requests).toHaveLength(0);
  });

  it("never puts the API key on curl's command line", () => {
    const script = readFileSync(SCRIPT, "utf8");
    expect(script).not.toMatch(/-H\s+["']Authorization/);
    expect(script).toContain("-H @-");
  });
});
