import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));

import {
  buildThreatAlertEmail,
  channelsFor,
  evidenceSentence,
  lookupCve,
  runEmergingThreatCheck,
  type AlertItem,
  type OwnerContext,
} from "./emergingThreatAlerts";
import { KEV_FEED_URL, resetThreatIntelCache } from "./scanners/threatIntel";

const NOW = new Date("2026-10-01T12:00:00Z");
const SLACK = "https://hooks.slack.com/services/T00/B00/xyz";
const noSleep = () => Promise.resolve();

// ---- External sources (fetch) -------------------------------------------------

const KEV_BODY = {
  vulnerabilities: [
    { cveID: "CVE-2021-41773", vendorProject: "Apache", product: "HTTP Server", vulnerabilityName: "Apache HTTP Server Path Traversal Vulnerability", dateAdded: "2026-09-30", knownRansomwareCampaignUse: "Known" },
    { cveID: "CVE-2010-0001", dateAdded: "2021-11-03" },
  ],
};
const NVD_APACHE = {
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2021-41773",
        configurations: [{ nodes: [{ operator: "OR", cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" }] }] }],
      },
    },
  ],
};

type Route = (url: string, init?: RequestInit) => Response | Promise<Response>;
let nvdRoute: Route;
let osvRoute: Route;
let slackStatus: number;
let fetchMock: ReturnType<typeof vi.fn>;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// ---- Supabase ---------------------------------------------------------------------

type DbError = { code?: string; message: string } | null;
let subs: Array<Record<string, unknown>>;
let admins: Array<{ id: string }>;
let scans: Array<Record<string, unknown>>;
let scanResults: Array<Record<string, unknown>>;
let alreadyNotified: Set<string>;
let upsertError: DbError;
let stampError: DbError;
let upserts: Array<{ rows: Array<Record<string, unknown>>; options: unknown }>;
let stamps: Array<{ values: Record<string, unknown>; ids: string[] }>;

function makeClient() {
  return {
    from: (table: string) => {
      const filters: unknown[][] = [];
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "gte", "order", "limit", "in"]) {
        b[m] = (...args: unknown[]) => {
          filters.push([m, ...args]);
          return b;
        };
      }
      const has = (m: string, col: string) => filters.some((f) => f[0] === m && f[1] === col);
      const resolveRead = () => {
        if (table === "subscriptions") return { data: has("in", "owner") ? [] : subs, error: null };
        if (table === "users") return has("eq", "is_admin") ? { data: admins, error: null } : { data: { email: "owner@shop.example" }, error: null };
        if (table === "scans") return { data: scans, error: null };
        if (table === "scan_results") return { data: scanResults, error: null };
        return { data: null, error: null };
      };
      b.maybeSingle = () => Promise.resolve(resolveRead());
      b.then = (resolve: (v: unknown) => unknown, reject?: (e: unknown) => unknown) => Promise.resolve(resolveRead()).then(resolve, reject);
      b.upsert = (rows: Array<Record<string, unknown>>, options: unknown) => {
        upserts.push({ rows, options });
        return {
          select: () =>
            Promise.resolve(
              upsertError
                ? { data: null, error: upsertError }
                : {
                    data: rows.map((r) => {
                      const key = `${r.target_host}|${r.cve_id}`;
                      return { id: `id:${key}`, target_host: r.target_host, cve_id: r.cve_id, notified_at: alreadyNotified.has(key) ? "2026-09-30T18:00:00Z" : null };
                    }),
                    error: null,
                  }
            ),
        };
      };
      b.update = (values: Record<string, unknown>) => ({
        in: (_col: string, ids: string[]) => {
          stamps.push({ values, ids });
          return Promise.resolve({ error: stampError });
        },
      });
      return b;
    },
  } as never;
}

const apacheScan = (fingerprintVersion: string | null, packagedBy?: string) => ({
  scan_id: "scan-shop",
  results: {
    fingerprint: {
      status: "checked",
      riskySoftware: [],
      technologies: [{ name: "Apache", category: "Web server", version: fingerprintVersion, confidence: "high", source: "header", ...(packagedBy ? { packagedBy } : {}) }],
    },
  },
});

beforeEach(() => {
  resetThreatIntelCache();
  sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  nvdRoute = () => json(NVD_APACHE);
  osvRoute = () => new Response("not found", { status: 404 });
  slackStatus = 200;
  fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === KEV_FEED_URL) return json(KEV_BODY);
    if (url.startsWith("https://services.nvd.nist.gov/")) return nvdRoute(url, init);
    if (url.startsWith("https://api.osv.dev/")) return osvRoute(url, init);
    if (url.startsWith("https://hooks.slack.com/")) return new Response("", { status: slackStatus });
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);

  subs = [{ owner: "o1", plan: "pro", status: "active", slack_webhook_url: SLACK, ms_teams_webhook_url: null }];
  admins = [];
  scans = [
    { id: "scan-shop", target_url: "https://shop.example/", created_at: "2026-09-29T03:00:00Z" },
    { id: "scan-shop-old", target_url: "https://shop.example/", created_at: "2026-09-20T03:00:00Z" },
  ];
  scanResults = [apacheScan("2.4.49")];
  alreadyNotified = new Set();
  upsertError = null;
  stampError = null;
  upserts = [];
  stamps = [];
});
afterEach(() => {
  vi.unstubAllGlobals();
  resetThreatIntelCache();
});

const run = (opts: Parameters<typeof runEmergingThreatCheck>[1] = {}) => runEmergingThreatCheck(makeClient(), { now: NOW, sleep: noSleep, siteUrl: "https://www.hebridescyber.co.uk", ...opts });
const slackCalls = () => fetchMock.mock.calls.filter((c) => String(c[0]).startsWith("https://hooks.slack.com/"));

describe("runEmergingThreatCheck", () => {
  it("dry run: reports matches but writes and sends nothing", async () => {
    const summary = await run({ dryRun: true });
    expect(summary.kevAdditions).toBe(1); // the 2021 entry is outside the 3-day window
    expect(summary.matches).toHaveLength(1);
    expect(summary.matches[0]).toMatchObject({ ownerId: "o1", host: "shop.example", scanId: "scan-shop", match: { tier: "affected", detectedVersion: "2.4.49" } });
    expect(upserts).toEqual([]);
    expect(stamps).toEqual([]);
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(slackCalls()).toHaveLength(0);
  });

  it("records the match, alerts by email and Slack, then stamps notified_at", async () => {
    const summary = await run();
    expect(upserts).toHaveLength(1);
    expect(upserts[0].options).toEqual({ onConflict: "owner,target_host,cve_id" });
    expect(upserts[0].rows).toEqual([
      {
        owner: "o1", target_host: "shop.example", cve_id: "CVE-2021-41773", confidence: "affected",
        product: "Apache HTTP Server", detected_version: "2.4.49", kev_date_added: "2026-09-30", scan_id: "scan-shop",
      },
    ]);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sendEmailMock.mock.calls[0][0].subject).toBe("Actively exploited: CVE-2021-41773 affects Apache HTTP Server on shop.example");
    expect(slackCalls()).toHaveLength(1);
    expect(stamps).toEqual([{ values: { notified_at: NOW.toISOString() }, ids: ["id:shop.example|CVE-2021-41773"] }]);
    expect(summary).toMatchObject({ notified: 1, errors: [] });
  });

  it("never re-sends a row that was already delivered", async () => {
    alreadyNotified.add("shop.example|CVE-2021-41773");
    const summary = await run();
    expect(upserts).toHaveLength(1);
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(stamps).toEqual([]);
    expect(summary.notified).toBe(0);
  });

  it("leaves the row unstamped when nothing was delivered, so the next run retries", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "Resend responded 500" });
    slackStatus = 500;
    const summary = await run();
    expect(stamps).toEqual([]);
    expect(summary.notified).toBe(0);
    expect(summary.errors).toEqual([
      "email to owner o1 failed: Resend responded 500",
      "Slack alert for owner o1 failed: Slack responded 500",
    ]);
  });

  it("stamps when one channel delivered, and reports the one that failed", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "down" });
    const summary = await run();
    expect(stamps).toHaveLength(1);
    expect(summary.errors).toEqual(["email to owner o1 failed: down"]);
  });

  it("keeps Slack/Teams to Pro and Agency — Basic gets email only", async () => {
    subs[0].plan = "basic";
    await run();
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(slackCalls()).toHaveLength(0);
  });

  it("includes admins without a paid plan", async () => {
    subs = [];
    admins = [{ id: "admin-1" }];
    const summary = await run({ dryRun: true });
    expect(summary.matches.map((m) => m.ownerId)).toEqual(["admin-1"]);
  });

  it("is a quiet no-op before migration 045", async () => {
    upsertError = { code: "PGRST205", message: "Could not find the table" };
    const summary = await run();
    expect(summary.migrationPending).toBe(true);
    expect(summary.errors).toEqual([]);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("reports a ledger write failure without sending", async () => {
    upsertError = { code: "500", message: "boom" };
    const summary = await run();
    expect(summary.errors).toEqual(["owner o1: could not record matches: boom"]);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("reports when delivered alerts can't be stamped", async () => {
    stampError = { message: "stamp failed" };
    const summary = await run();
    expect(summary.notified).toBe(0);
    expect(summary.errors).toEqual(["owner o1: delivered but could not mark as notified: stamp failed"]);
  });

  it("only uses the latest scan of each host — an upgraded site isn't matched", async () => {
    scanResults = [{ ...apacheScan("2.4.51") }];
    const summary = await run({ dryRun: true });
    expect(summary.matches).toEqual([]);
    expect(summary.hostsChecked).toBe(1);
  });

  it("marks a distribution-packaged version possibly affected", async () => {
    scanResults = [apacheScan("2.4.49", "Ubuntu")];
    const summary = await run({ dryRun: true });
    expect(summary.matches[0].match).toMatchObject({ tier: "possibly_affected", reason: "distro_packaged" });
  });

  it("fails loudly when the KEV feed can't be read", async () => {
    fetchMock.mockImplementation(async () => new Response("", { status: 503 }));
    await expect(run()).rejects.toThrow(/KEV feed could not be read/);
  });

  it("skips a CVE whose NVD lookup failed and reports it — never 'not affected'", async () => {
    nvdRoute = () => new Response("", { status: 500 });
    const summary = await run();
    expect(summary.cvesEvaluated).toEqual([]);
    expect(summary.errors).toEqual(["NVD responded 500 for CVE-2021-41773"]);
    expect(upserts).toEqual([]);
  });

  it("skips a CVE whose OSV lookup failed", async () => {
    osvRoute = () => new Response("", { status: 502 });
    const summary = await run();
    expect(summary.errors).toEqual(["OSV responded 502 for CVE-2021-41773"]);
    expect(summary.matches).toEqual([]);
  });

  it("treats a CVE NVD hasn't analysed yet as pending, not an error", async () => {
    nvdRoute = () => json({ vulnerabilities: [{ cve: { id: "CVE-2021-41773", vulnStatus: "Awaiting Analysis" } }] });
    const summary = await run();
    expect(summary.cvesPending).toEqual(["CVE-2021-41773"]);
    expect(summary.errors).toEqual([]);
  });
});

describe("lookupCve", () => {
  it("retries once after NVD's rate limiter, sending the API key", async () => {
    const sleep = vi.fn(noSleep);
    let calls = 0;
    nvdRoute = () => (++calls === 1 ? new Response("", { status: 429 }) : json(NVD_APACHE));
    const result = await lookupCve("CVE-2021-41773", "key-123", sleep);
    expect(result.status).toBe("ok");
    expect(sleep).toHaveBeenCalledTimes(1);
    const nvdCall = fetchMock.mock.calls.find((c) => String(c[0]).startsWith("https://services.nvd.nist.gov/"))!;
    expect((nvdCall[1] as RequestInit).headers).toMatchObject({ apiKey: "key-123" });
    expect((nvdCall[1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
  });

  it("follows the CVE's GHSA alias for npm ranges", async () => {
    nvdRoute = () => json({ vulnerabilities: [{ cve: { id: "CVE-2020-11022" } }] });
    osvRoute = (url) =>
      url.endsWith("/CVE-2020-11022")
        ? json({ id: "CVE-2020-11022", aliases: ["BIT-drupal-2020-11022", "GHSA-gxr4-xjj5-5px2"] })
        : json({
            id: "GHSA-gxr4-xjj5-5px2",
            affected: [{ package: { name: "jquery", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.12.0" }, { fixed: "3.5.0" }] }] }],
          });
    const result = await lookupCve("CVE-2020-11022", undefined, noSleep);
    expect(result.status).toBe("ok");
    if (result.status === "ok") expect(result.ranges.byTech.get("jQuery")).toEqual([{ source: "osv", startIncluding: "1.12.0", endExcluding: "3.5.0" }]);
    expect(fetchMock.mock.calls.map((c) => String(c[0])).filter((u) => u.includes("osv.dev"))).toEqual([
      "https://api.osv.dev/v1/vulns/CVE-2020-11022",
      "https://api.osv.dev/v1/vulns/GHSA-gxr4-xjj5-5px2",
    ]);
  });

  it("reports a network failure as an error", async () => {
    nvdRoute = () => {
      throw new Error("socket hang up");
    };
    expect(await lookupCve("CVE-2021-41773", undefined, noSleep)).toEqual({ status: "error", note: "NVD lookup for CVE-2021-41773 failed: socket hang up" });
  });
});

describe("alert copy", () => {
  const item = (over: Partial<AlertItem["match"]> = {}): AlertItem => ({
    host: "shop.example",
    scanId: "scan-shop",
    scannedAt: "2026-09-29T03:00:00Z",
    kev: { cveId: "CVE-2021-41773", vendorProject: "Apache", product: "HTTP Server", vulnerabilityName: "Path <Traversal>", dateAdded: "2026-09-30", ransomware: true },
    match: { cveId: "CVE-2021-41773", tech: "Apache", product: "Apache HTTP Server", detectedVersion: "2.4.49", packagedBy: null, tier: "affected", reason: "version_in_range", ...over },
  });

  it("is specific: CVE, product, version, why it matters, what to do, report link", () => {
    const { html } = buildThreatAlertEmail([item()], "https://www.hebridescyber.co.uk");
    expect(html).toContain("CVE-2021-41773: Path &lt;Traversal&gt;");
    expect(html).toContain("saw Apache HTTP Server 2.4.49, which is inside the version range listed as vulnerable");
    expect(html).toContain("actively exploiting it now, including in ransomware campaigns.");
    expect(html).toContain("Upgrade Apache HTTP Server to a release that fixes this vulnerability");
    expect(html).toContain('href="https://www.hebridescyber.co.uk/dashboard/scans/scan-shop"');
    expect(html).not.toContain("<Traversal>");
  });

  it("uses softer wording when we can't see the version", () => {
    const soft = item({ detectedVersion: null, tier: "possibly_affected", reason: "version_unknown" });
    expect(evidenceSentence(soft)).toContain("we can't see which version it runs");
    const { subject, html } = buildThreatAlertEmail([soft], "https://x.example");
    expect(subject).toBe("Check Apache HTTP Server on shop.example: CVE-2021-41773 is being actively exploited");
    expect(html).toContain("Possibly affected");
  });

  it("explains partial, distribution and platform-specific evidence", () => {
    expect(evidenceSentence(item({ detectedVersion: "2.4", tier: "possibly_affected", reason: "partial_version" }))).toContain("some 2.4.x releases are affected");
    expect(evidenceSentence(item({ packagedBy: "Ubuntu", tier: "possibly_affected", reason: "distro_packaged" }))).toContain("Ubuntu's packages");
    expect(evidenceSentence(item({ tier: "possibly_affected", reason: "platform_specific" }))).toContain("only affects particular setups");
  });

  it("summarises several alerts in one email", () => {
    expect(buildThreatAlertEmail([item(), item()], "https://x.example").subject).toBe("2 newly exploited vulnerabilities may affect your sites");
  });
});

describe("channelsFor", () => {
  const owner = (over: Partial<OwnerContext>): OwnerContext => ({
    ownerId: "o", plan: "pro", status: "active", isAdmin: false, slackWebhookUrl: SLACK, teamsWebhookUrl: "https://example.webhook.office.com/x", ...over,
  });
  it("gates chat channels to active Pro/Agency, admins exempt, and needs a webhook", () => {
    expect(channelsFor(owner({}))).toEqual({ slack: true, teams: true });
    expect(channelsFor(owner({ plan: "basic" }))).toEqual({ slack: false, teams: false });
    expect(channelsFor(owner({ plan: null, status: null, isAdmin: true }))).toEqual({ slack: true, teams: true });
    expect(channelsFor(owner({ teamsWebhookUrl: null }))).toEqual({ slack: true, teams: false });
  });
});
