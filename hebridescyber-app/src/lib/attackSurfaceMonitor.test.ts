import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { sendEmailMock, resolverOptions } = vi.hoisted(() => ({ sendEmailMock: vi.fn(), resolverOptions: [] as unknown[] }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));
// Only reached when a test passes no resolver: the module's system resolver.
vi.mock("node:dns/promises", () => {
  class Resolver {
    constructor(options: unknown) {
      resolverOptions.push(options);
    }
    resolveNs = () => Promise.reject(Object.assign(new Error("servfail"), { code: "ESERVFAIL" }));
    resolveMx = this.resolveNs;
    resolveTxt = this.resolveNs;
  }
  return { Resolver, default: { Resolver } };
});

import {
  MAX_LISTED_HOSTNAMES,
  buildAttackSurfaceEmail,
  classifyHostnames,
  describeDnsChange,
  diffDns,
  firstCertificates,
  monitoredDomain,
  noticeLines,
  noticeTitle,
  observeDns,
  sendAttackSurfaceAlerts,
  sendSweepHostnameAlerts,
  type DnsResolver,
  type DnsSnapshot,
  type DnsValues,
  type NewHostname,
} from "./attackSurfaceMonitor";
import type { ReconResult } from "./scanners/recon";

const NOW = new Date("2026-10-06T12:00:00Z");
const OWNER = "owner-1";
const SCAN = "scan-new";
const TARGET = "https://www.shop.example.com";
const SLACK = "https://hooks.slack.com/services/T00/B00/xyz";
const TEAMS = "https://mytenant.webhook.office.com/webhookb2/abc";
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString().slice(0, 19); // crt.sh style, no zone

// ---- DNS ------------------------------------------------------------------------

const dnsError = (code: string) => Object.assign(new Error(`query failed: ${code}`), { code });

type Answer<T> = T | Error;
type Zone = { ns?: Answer<string[]>; mx?: Answer<Array<{ priority: number; exchange: string }>>; txt?: Answer<string[][]>; dmarc?: Answer<string[][]> };

function resolverFor(zone: Zone): DnsResolver & { calls: string[] } {
  const calls: string[] = [];
  const answer = <T,>(a: Answer<T> | undefined, empty: T) => (a instanceof Error ? Promise.reject(a) : Promise.resolve(a ?? empty));
  return {
    calls,
    resolveNs: (name) => (calls.push(`NS ${name}`), answer(zone.ns, [])),
    resolveMx: (name) => (calls.push(`MX ${name}`), answer(zone.mx, [])),
    resolveTxt: (name) => {
      calls.push(`TXT ${name}`);
      return name.startsWith("_dmarc.") ? answer(zone.dmarc, []) : answer(zone.txt, []);
    },
  };
}

const ZONE: Zone = {
  ns: ["NS2.Host.example.", "ns1.host.example."],
  mx: [{ priority: 10, exchange: "Mail.shop.example.com." }],
  txt: [["v=spf1 include:_spf.mail.example ", "-all"], ["google-site-verification=abc"]],
  dmarc: [["v=DMARC1; p=reject; rua=mailto:d@shop.example.com"]],
};
const ZONE_VALUES: DnsValues = {
  ns: ["ns1.host.example", "ns2.host.example"],
  mx: ["10 mail.shop.example.com"],
  spf: "v=spf1 include:_spf.mail.example -all",
  dmarc: "v=DMARC1; p=reject; rua=mailto:d@shop.example.com",
};
const ALL_KNOWN: DnsSnapshot["known"] = ["ns", "mx", "spf", "dmarc"];

describe("monitoredDomain", () => {
  it("uses the full Public Suffix List, private suffixes included", () => {
    expect(monitoredDomain("www.shop.example.com")).toBe("example.com");
    expect(monitoredDomain("www.shop.example.co.uk")).toBe("example.co.uk");
    expect(monitoredDomain("www.stmarys.herts.sch.uk")).toBe("stmarys.herts.sch.uk");
    expect(monitoredDomain("mysite.github.io")).toBe("mysite.github.io");
    expect(monitoredDomain("10.0.0.5")).toBeNull();
    expect(monitoredDomain("localhost")).toBeNull();
  });
});

describe("observeDns", () => {
  it("normalises what the domain publishes", async () => {
    const r = resolverFor(ZONE);
    expect(await observeDns("example.com", r)).toEqual(ZONE_VALUES);
    expect(r.calls.sort()).toEqual(["MX example.com", "NS example.com", "TXT _dmarc.example.com", "TXT example.com"]);
  });

  it("treats no data and no such domain as 'no record'", async () => {
    const r = resolverFor({ ns: dnsError("ENOTFOUND"), mx: dnsError("ENODATA"), txt: dnsError("ENODATA"), dmarc: dnsError("ENOTFOUND") });
    expect(await observeDns("gone.example", r)).toEqual({ ns: null, mx: null, spf: null, dmarc: null });
  });

  it("treats any other failure as unknown, never as 'no record'", async () => {
    const r = resolverFor({ ...ZONE, ns: dnsError("ESERVFAIL"), mx: dnsError("ETIMEOUT"), dmarc: new Error("no code") });
    expect(await observeDns("example.com", r)).toEqual({ ns: undefined, mx: undefined, spf: ZONE_VALUES.spf, dmarc: undefined });
  });

  it("returns null for empty answers and TXT records that aren't SPF or DMARC", async () => {
    const r = resolverFor({ ns: [], mx: [], txt: [["v=spf10 not-spf"], ["hello"]], dmarc: [["v=DMARC10"]] });
    expect(await observeDns("example.com", r)).toEqual({ ns: null, mx: null, spf: null, dmarc: null });
  });

  it("keeps every SPF record when a domain (wrongly) publishes two, and handles a null MX", async () => {
    const r = resolverFor({ ...ZONE, mx: [{ priority: 0, exchange: "" }], txt: [["v=spf1 -all"], ["V=SPF1   a  -all"]], dmarc: [["v=DMARC1;p=none"]] });
    const seen = await observeDns("example.com", r);
    expect(seen.mx).toEqual(["0 ."]);
    expect(seen.spf).toBe("V=SPF1 a -all | v=spf1 -all");
    expect(seen.dmarc).toBe("v=DMARC1;p=none");
  });
});

describe("diffDns", () => {
  it("takes each answered field as its baseline without reporting it", () => {
    expect(diffDns(null, ZONE_VALUES)).toEqual({ changes: [], next: { values: ZONE_VALUES, known: ALL_KNOWN }, unanswered: [] });
    expect(diffDns(null, { ...ZONE_VALUES, mx: undefined })).toEqual({
      changes: [],
      next: { values: { ...ZONE_VALUES, mx: null }, known: ["ns", "spf", "dmarc"] },
      unanswered: ["mx"],
    });
    expect(diffDns(null, { ns: undefined, mx: undefined, spf: undefined, dmarc: undefined }).next).toBeNull();
  });

  it("baselines a field that answers for the first time instead of reporting it as added", () => {
    const previous: DnsSnapshot = { values: { ...ZONE_VALUES, dmarc: null }, known: ["ns", "mx", "spf"] };
    expect(diffDns(previous, ZONE_VALUES)).toEqual({ changes: [], next: { values: ZONE_VALUES, known: ALL_KNOWN }, unanswered: [] });
  });

  it("reports added, removed and changed records", () => {
    const { changes, next } = diffDns(
      { values: { ...ZONE_VALUES, dmarc: null }, known: ALL_KNOWN },
      { ns: ["ns1.evil.example"], mx: ZONE_VALUES.mx, spf: null, dmarc: "v=DMARC1; p=none" }
    );
    expect(changes).toEqual([
      { field: "ns", before: ZONE_VALUES.ns, after: ["ns1.evil.example"] },
      { field: "spf", before: ZONE_VALUES.spf, after: null },
      { field: "dmarc", before: null, after: "v=DMARC1; p=none" },
    ]);
    expect(next?.values).toEqual({ ns: ["ns1.evil.example"], mx: ZONE_VALUES.mx, spf: null, dmarc: "v=DMARC1; p=none" });
  });

  it("keeps the stored value for a field it couldn't look up", () => {
    const previous = { values: ZONE_VALUES, known: ALL_KNOWN };
    expect(diffDns(previous, { ns: undefined, mx: undefined, spf: undefined, dmarc: undefined })).toEqual({
      changes: [],
      next: previous,
      unanswered: ["ns", "mx", "spf", "dmarc"],
    });
  });
});

describe("new hostnames", () => {
  const recon = (subdomains: Array<{ name: string; first?: string }>): ReconResult => ({
    status: "checked",
    ip: null,
    shodan: null,
    subdomains: subdomains.map((s) => ({ name: s.name, issuer: "R11", notBefore: s.first ?? "", ...(s.first ? { firstNotBefore: s.first } : {}) })),
  });

  it("reads each name's earliest certificate, ignoring undated names and failed lookups", () => {
    expect(firstCertificates(recon([{ name: "A.example.com", first: "2026-10-01T00:00:00" }, { name: "b.example.com" }, { name: "c.example.com", first: "garbage" }]))).toEqual(
      new Map([["a.example.com", "2026-10-01T00:00:00"]])
    );
    expect(firstCertificates({ status: "error", note: "x" }).size).toBe(0);
    expect(firstCertificates(undefined).size).toBe(0);
  });

  it("reports only names in the domain, first certified after the cut-off, other than the scanned site", () => {
    const firsts = new Map([
      ["dev.example.com", daysAgo(2)],
      ["new2.example.com", `${daysAgo(1)}Z`],
      ["old.example.com", daysAgo(400)],
      ["www.shop.example.com", daysAgo(1)],
      ["evil.other.com", daysAgo(1)],
    ]);
    const seenNow = (name: string) => ({ name, firstSeenAt: NOW.toISOString() });
    const pending = ["dev.example.com", "new2.example.com", "old.example.com", "www.shop.example.com", "evil.other.com", "subfinder-only.example.com"].map(seenNow);
    const { report, known } = classifyHostnames(pending, firsts, "example.com", "www.shop.example.com", new Date(NOW.getTime() - 14 * 86_400_000));
    expect(report.map((h) => h.name)).toEqual(["new2.example.com", "dev.example.com"]); // newest first
    expect(known).toEqual(["old.example.com", "www.shop.example.com", "evil.other.com", "subfinder-only.example.com"]);
    expect(classifyHostnames([seenNow("dev.example.com")], firsts, null, "x", new Date(0)).report).toEqual([]);
  });

  it("judges a row left pending against when it was first seen, so a retried alert doesn't age out", () => {
    const firsts = new Map([["shop.example.com", daysAgo(19)]]);
    const since = new Date(NOW.getTime() - 14 * 86_400_000);
    const seenAWeekAgo = { name: "shop.example.com", firstSeenAt: new Date(NOW.getTime() - 7 * 86_400_000).toISOString() };
    expect(classifyHostnames([seenAWeekAgo], firsts, "example.com", "www.example.com", since).report).toHaveLength(1);
    expect(classifyHostnames([{ ...seenAWeekAgo, firstSeenAt: NOW.toISOString() }], firsts, "example.com", "www.example.com", since).report).toEqual([]);
    expect(classifyHostnames([{ ...seenAWeekAgo, firstSeenAt: "not a date" }], firsts, "example.com", "www.example.com", since).report).toEqual([]);
  });
});

describe("messages", () => {
  const h = (name: string): NewHostname => ({ name, firstCertificate: "2026-10-03T08:00:00" });

  it("describes each kind of DNS change in plain words", () => {
    expect(describeDnsChange({ field: "mx", before: ["10 a.example"], after: ["10 b.example", "20 c.example"] })).toBe(
      "Mail servers (MX) changed from 10 a.example to 10 b.example, 20 c.example"
    );
    expect(describeDnsChange({ field: "dmarc", before: null, after: "v=DMARC1; p=none" })).toBe("DMARC record added: v=DMARC1; p=none");
    expect(describeDnsChange({ field: "spf", before: "v=spf1 -all", after: null })).toBe("SPF record removed (was v=spf1 -all)");
    expect(describeDnsChange({ field: "ns", before: ["ns1.a"], after: null })).toMatch(/^Name servers \(NS\) no longer found \(was ns1\.a\): the domain may have expired/);
  });

  it("titles the alert by what changed", () => {
    const dns = [{ field: "mx" as const, before: null, after: ["10 m"] }];
    expect(noticeTitle({ site: "example.com", newHostnames: [h("a.example.com")], dnsChanges: [] })).toBe("1 new hostname found for example.com");
    expect(noticeTitle({ site: "example.com", newHostnames: [h("a"), h("b")], dnsChanges: [] })).toBe("2 new hostnames found for example.com");
    expect(noticeTitle({ site: "example.com", newHostnames: [], dnsChanges: dns })).toBe("DNS records changed for example.com");
    expect(noticeTitle({ site: "example.com", newHostnames: [h("a")], dnsChanges: dns })).toBe("New hostnames and DNS changes for example.com");
  });

  it(`lists at most ${MAX_LISTED_HOSTNAMES} hostnames with their first certificate date, and counts the rest`, () => {
    const hosts = Array.from({ length: 23 }, (_, i) => h(`h${i}.example.com`));
    const lines = noticeLines({ site: "example.com", newHostnames: hosts, dnsChanges: [] });
    expect(lines[0]).toMatch(/^New hostnames: h0\.example\.com \(first certificate 3 October 2026\), h1\.example\.com/);
    expect(lines[0]).not.toContain("h20.");
    expect(lines[1]).toBe("…and 3 more on the Assets page");
    const email = buildAttackSurfaceEmail({ site: "example.com", newHostnames: hosts, dnsChanges: [] }, "https://app.example");
    expect(email.html).toContain("<li>h0.example.com (first certificate 3 October 2026)</li>");
    expect(email.html).toContain("…and 3 more, listed on the Assets page.");
    expect(email.html).not.toContain("h20.example.com");
    expect(noticeLines({ site: "s", newHostnames: [h("one.s")], dnsChanges: [] })[0]).toBe("New hostname: one.s (first certificate 3 October 2026)");
  });

  it("escapes everything a DNS record or hostname could carry into the email", () => {
    const email = buildAttackSurfaceEmail(
      { site: "example.com", newHostnames: [h("<b>x</b>.example.com")], dnsChanges: [{ field: "spf", before: null, after: 'v=spf1 <img src=x onerror="1">' }] },
      "https://app.example"
    );
    expect(email.subject).toBe("New hostnames and DNS changes for example.com");
    expect(email.html).not.toMatch(/<img|<b>x/);
    expect(email.html).toContain("&lt;img");
    expect(email.html).toContain('href="https://app.example/dashboard/assets"');
  });
});

// ---- Supabase (in-memory, PostgREST-shaped) ---------------------------------------------

type Row = Record<string, unknown>;
type DbError = { code?: string; message: string };
let db: Record<string, Row[]>;
/** `${table}:${op}` → error that kind of call returns. */
let dbErrors: Record<string, DbError>;
let updateCalls: Array<{ table: string; values: Row; inValues: unknown[] }>;
let upsertCalls: Array<{ table: string; row: Row; options: unknown }>;

const likeToRegex = (pattern: string) => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/[*%]/g, ".*")}$`, "i");

function makeClient() {
  return {
    from: (table: string) => {
      const filters: Array<(r: Row) => boolean> = [];
      let op: "select" | "update" = "select";
      let values: Row = {};
      let returning = false;
      let range: [number, number] | null = null;
      let limit = Infinity;
      let sort: { col: string; asc: boolean } | null = null;
      let inValues: unknown[] = [];
      const run = async () => {
        const err = dbErrors[`${table}:${op}`];
        if (err) return { data: null, error: err };
        let rows = (db[table] ?? []).filter((r) => filters.every((f) => f(r)));
        if (op === "update") {
          updateCalls.push({ table, values, inValues });
          for (const r of rows) Object.assign(r, values);
          return { data: returning ? rows.map((r) => ({ ...r })) : null, error: null };
        }
        if (sort) {
          const { col, asc } = sort;
          rows = [...rows].sort((a, b) => String(a[col]).localeCompare(String(b[col])) * (asc ? 1 : -1));
        }
        if (range) rows = rows.slice(range[0], range[1] + 1);
        return { data: rows.slice(0, limit).map((r) => ({ ...r })), error: null };
      };
      const b: Record<string, unknown> = {
        select: () => ((returning = op === "update"), b),
        order: (col: string, o?: { ascending?: boolean }) => ((sort = { col, asc: o?.ascending !== false }), b),
        limit: (n: number) => ((limit = n), b),
        range: (from: number, to: number) => ((range = [from, to]), b),
        eq: (c: string, v: unknown) => (filters.push((r) => r[c] === v), b),
        neq: (c: string, v: unknown) => (filters.push((r) => r[c] !== v), b),
        is: (c: string, v: unknown) => (filters.push((r) => (r[c] ?? null) === v), b),
        in: (c: string, vs: unknown[]) => ((inValues = vs), filters.push((r) => vs.includes(r[c])), b),
        or: (expr: string) => {
          const alternatives = expr.split(",").map((part) => {
            const [col, operator, ...rest] = part.split(".");
            if (operator !== "ilike") throw new Error(`fake supports ilike only, got ${operator}`);
            return { col, re: likeToRegex(rest.join(".")) };
          });
          filters.push((r) => alternatives.some((a) => a.re.test(String(r[a.col]))));
          return b;
        },
        update: (v: Row) => ((op = "update"), (values = v), b),
        upsert: (row: Row, options: unknown) => {
          upsertCalls.push({ table, row, options });
          const err = dbErrors[`${table}:upsert`];
          if (err) return Promise.resolve({ error: err });
          db[table] = (db[table] ?? []).filter((r) => !(r.owner === row.owner && r.target_host === row.target_host));
          db[table].push({ ...row });
          return Promise.resolve({ error: null });
        },
        maybeSingle: () => run().then((r) => ({ data: (r.data as Row[] | null)?.[0] ?? null, error: r.error })),
        then: (resolve: (v: unknown) => unknown, reject?: (e: unknown) => unknown) => run().then(resolve, reject),
      };
      return b;
    },
  } as never;
}

const asset = (hostname: string, notified: boolean, target = TARGET): Row => ({
  owner: OWNER,
  target_url: target,
  hostname,
  first_seen_at: "2026-10-06T11:59:00Z",
  notified_at: notified ? "2026-09-01T00:00:00Z" : null,
});

/** This scan's crt.sh data: dev and api are new, staging is years old. */
const RECON: ReconResult = {
  status: "checked",
  ip: null,
  shodan: null,
  subdomains: [
    { name: "api.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) },
    { name: "dev.example.com", issuer: "R11", notBefore: daysAgo(3), firstNotBefore: daysAgo(3) },
    { name: "staging.example.com", issuer: "R11", notBefore: daysAgo(2), firstNotBefore: daysAgo(900) },
    { name: "www.shop.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(5) },
  ],
};
const SNAPSHOT_AT = "2026-10-01T00:00:00.123456+00:00";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  db = {
    asset_inventory: [
      asset("www.shop.example.com", false),
      asset("old.example.com", true),
      asset("api.example.com", false),
      asset("dev.example.com", false),
      asset("staging.example.com", false),
      asset("subfinder-only.example.com", false),
    ],
    dns_snapshots: [{ owner: OWNER, target_host: "example.com", ...ZONE_VALUES, known_fields: ALL_KNOWN, captured_at: SNAPSHOT_AT }],
    scans: [
      { id: SCAN, owner: OWNER, target_url: TARGET, status: "completed", created_at: NOW.toISOString() },
      { id: "scan-old", owner: OWNER, target_url: "https://WWW.shop.example.com/", status: "completed", created_at: "2026-10-05T12:00:00Z" },
    ],
    subscriptions: [{ owner: OWNER, plan: "pro", status: "active", slack_webhook_url: null, ms_teams_webhook_url: null }],
    users: [{ id: OWNER, email: "owner@shop.example.com", is_admin: false }],
  };
  dbErrors = {};
  updateCalls = [];
  upsertCalls = [];
  sendEmailMock.mockReset();
  sendEmailMock.mockResolvedValue({ ok: true });
  fetchMock = vi.fn(async () => new Response(null, { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const run = (zone: Zone = ZONE, target = TARGET, recon: ReconResult | undefined = RECON) =>
  sendAttackSurfaceAlerts(makeClient(), OWNER, SCAN, target, recon, { resolver: resolverFor(zone), now: NOW, siteUrl: "https://app.example" });

const notifiedAt = (hostname: string) => db.asset_inventory.find((r) => r.hostname === hostname)?.notified_at;
const pending = () => db.asset_inventory.filter((r) => r.notified_at === null).map((r) => r.hostname);
const snapshot = () => db.dns_snapshots.find((r) => r.owner === OWNER && r.target_host === "example.com");

describe("sendAttackSurfaceAlerts", () => {
  it("reports hostnames with evidence they are new, once, and records the rest as known", async () => {
    const result = await run();
    expect(result).toMatchObject({ delivered: true, migrationPending: false, errors: [], unanswered: [] });
    expect(result.reported).toEqual({
      site: "example.com",
      newHostnames: [
        { name: "api.example.com", firstCertificate: daysAgo(1) },
        { name: "dev.example.com", firstCertificate: daysAgo(3) },
      ],
      dnsChanges: [],
    });
    expect(result.silentlyRecorded).toEqual(["staging.example.com", "subfinder-only.example.com", "www.shop.example.com"]);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sendEmailMock.mock.calls[0][0]).toMatchObject({ to: "owner@shop.example.com", subject: "2 new hostnames found for example.com" });
    expect(pending()).toEqual([]);
    expect(notifiedAt("api.example.com")).toBe(NOW.toISOString());
    expect(upsertCalls).toEqual([]); // DNS unchanged: the snapshot isn't rewritten

    sendEmailMock.mockClear();
    expect((await run()).reported).toBeNull();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("looks back to the previous scan when it was more than 14 days ago", async () => {
    db.scans[1].created_at = "2026-08-01T00:00:00Z";
    db.asset_inventory = [asset("month.example.com", false)];
    const recon: ReconResult = { ...RECON, subdomains: [{ name: "month.example.com", issuer: "R11", notBefore: daysAgo(30), firstNotBefore: daysAgo(30) }] } as ReconResult;
    expect((await run(ZONE, TARGET, recon)).reported?.newHostnames.map((h) => h.name)).toEqual(["month.example.com"]);
  });

  it("uses the 14-day window when the previous scan was recent or there is none", async () => {
    const recon: ReconResult = { ...RECON, subdomains: [{ name: "month.example.com", issuer: "R11", notBefore: daysAgo(20), firstNotBefore: daysAgo(20) }] } as ReconResult;
    db.asset_inventory = [asset("month.example.com", false)];
    expect((await run(ZONE, TARGET, recon)).silentlyRecorded).toEqual(["month.example.com"]);

    db.scans = [db.scans[0]];
    db.asset_inventory = [asset("fresh.example.com", false)];
    const fresh: ReconResult = { ...RECON, subdomains: [{ name: "fresh.example.com", issuer: "R11", notBefore: daysAgo(2), firstNotBefore: daysAgo(2) }] } as ReconResult;
    expect((await run(ZONE, TARGET, fresh)).reported?.newHostnames.map((h) => h.name)).toEqual(["fresh.example.com"]);
  });

  it("only counts completed scans of exactly this host as the previous scan", async () => {
    db.scans = [
      db.scans[0],
      { id: "a", owner: OWNER, target_url: "https://www.shop.example.com.evil.example", status: "completed", created_at: "2026-01-01T00:00:00Z" },
      { id: "b", owner: OWNER, target_url: TARGET, status: "failed", created_at: "2026-01-01T00:00:00Z" },
      { id: "c", owner: "someone-else", target_url: TARGET, status: "completed", created_at: "2026-01-01T00:00:00Z" },
      { id: "d", owner: OWNER, target_url: "ftp://www.shop.example.com:99999", status: "completed", created_at: "2026-01-01T00:00:00Z" },
    ];
    db.asset_inventory = [asset("month.example.com", false)];
    const recon: ReconResult = { ...RECON, subdomains: [{ name: "month.example.com", issuer: "R11", notBefore: daysAgo(30), firstNotBefore: daysAgo(30) }] } as ReconResult;
    expect((await run(ZONE, TARGET, recon)).silentlyRecorded).toEqual(["month.example.com"]); // window stays 14 days
  });

  it("leaves hostnames pending when crt.sh couldn't be read: no evidence either way", async () => {
    const before = pending();
    for (const recon of [{ status: "checked", ip: null, shodan: null, subdomains: [], ctLookupFailed: true } as ReconResult, { status: "error", note: "x" } as ReconResult, undefined]) {
      // Called directly: run()'s default would replace an undefined recon.
      const result = await sendAttackSurfaceAlerts(makeClient(), OWNER, SCAN, TARGET, recon, {
        resolver: resolverFor({ ...ZONE, mx: [{ priority: 10, exchange: "mx.attacker.example" }] }),
        now: NOW,
      });
      expect(result).toMatchObject({ hostnamesDeferred: true, silentlyRecorded: [] });
      expect(pending()).toEqual(before);
    }
    expect(sendEmailMock).toHaveBeenCalledTimes(1); // the DNS change still went out, once
    expect(sendEmailMock.mock.calls[0][0].subject).toBe("DNS records changed for example.com");

    const later = await run(); // a scan whose crt.sh data was read decides them
    expect(later).toMatchObject({ hostnamesDeferred: false });
    expect(later.reported?.newHostnames.map((h) => h.name)).toEqual(["api.example.com", "dev.example.com"]);
  });

  it("still records hostnames as known for an owner without an alerting plan when crt.sh failed", async () => {
    db.subscriptions = [];
    const result = await run(ZONE, TARGET, { status: "error", note: "x" });
    expect(result).toMatchObject({ hostnamesDeferred: false });
    expect(pending()).toEqual([]);
  });

  it("watches the site's own zone and never reports a neighbour's hostnames", async () => {
    const target = "https://www.stmarys.herts.sch.uk";
    db.asset_inventory = [asset("other-school.herts.sch.uk", false, target), asset("portal.stmarys.herts.sch.uk", false, target)];
    db.scans.push({ id: "s-old", owner: OWNER, target_url: target, status: "completed", created_at: "2026-10-05T00:00:00Z" });
    const recon: ReconResult = {
      status: "checked",
      ip: null,
      shodan: null,
      subdomains: [
        { name: "other-school.herts.sch.uk", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) },
        { name: "portal.stmarys.herts.sch.uk", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) },
      ],
    };
    const resolver = resolverFor(ZONE);
    const result = await sendAttackSurfaceAlerts(makeClient(), OWNER, SCAN, target, recon, { resolver, now: NOW });
    expect(result.reported?.newHostnames.map((h) => h.name)).toEqual(["portal.stmarys.herts.sch.uk"]);
    expect(result.reported?.site).toBe("stmarys.herts.sch.uk");
    expect(result.silentlyRecorded).toEqual(["other-school.herts.sch.uk"]);
    expect(resolver.calls).toContain("NS stmarys.herts.sch.uk");
    expect(db.dns_snapshots.map((r) => r.target_host)).toContain("stmarys.herts.sch.uk"); // baseline for the new zone
  });

  it("reports a DNS change and advances the snapshot", async () => {
    db.asset_inventory = [];
    const result = await run({ ...ZONE, mx: [{ priority: 10, exchange: "mx.attacker.example" }] });
    expect(result.reported?.dnsChanges).toEqual([{ field: "mx", before: ["10 mail.shop.example.com"], after: ["10 mx.attacker.example"] }]);
    expect(sendEmailMock.mock.calls[0][0].subject).toBe("DNS records changed for example.com");
    expect(sendEmailMock.mock.calls[0][0].html).toContain("Mail servers (MX) changed from 10 mail.shop.example.com to 10 mx.attacker.example");
    expect(snapshot()).toMatchObject({ mx: ["10 mx.attacker.example"], captured_at: NOW.toISOString(), known_fields: ALL_KNOWN });
  });

  it("never reports a record it couldn't look up, and keeps the stored value", async () => {
    db.asset_inventory = [];
    const result = await run({ ...ZONE, ns: dnsError("ESERVFAIL"), mx: dnsError("ETIMEOUT") });
    expect(result).toMatchObject({ reported: null, unanswered: ["ns", "mx"] });
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(snapshot()).toMatchObject({ ns: ZONE_VALUES.ns, mx: ZONE_VALUES.mx, captured_at: SNAPSHOT_AT });
    expect(upsertCalls).toEqual([]);
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("no answer for ns, mx"));
  });

  it("reports a domain whose name servers vanished", async () => {
    db.asset_inventory = [];
    const result = await run({ ns: dnsError("ENOTFOUND"), mx: dnsError("ENOTFOUND"), txt: dnsError("ENOTFOUND"), dmarc: dnsError("ENOTFOUND") });
    expect(result.reported?.dnsChanges.map((c) => c.field)).toEqual(["ns", "mx", "spf", "dmarc"]);
    expect(sendEmailMock.mock.calls[0][0].html).toContain("the domain may have expired or been deleted");
  });

  it("builds the baseline field by field, so one unreadable record doesn't switch monitoring off", async () => {
    db.dns_snapshots = [];
    db.asset_inventory = [];
    await run({ ...ZONE, dmarc: dnsError("ESERVFAIL") });
    expect(snapshot()).toMatchObject({ known_fields: ["ns", "mx", "spf"], ns: ZONE_VALUES.ns, dmarc: null });
    expect(sendEmailMock).not.toHaveBeenCalled();

    await run({ ...ZONE, ns: ["ns1.evil.example"], dmarc: dnsError("ESERVFAIL") });
    expect(sendEmailMock).toHaveBeenCalledTimes(1); // NS is monitored even though DMARC never answered

    sendEmailMock.mockClear();
    await run({ ...ZONE, ns: ["ns1.evil.example"] });
    expect(sendEmailMock).not.toHaveBeenCalled(); // DMARC's first answer is its baseline, not "added"
    expect(snapshot()?.known_fields).toEqual(ALL_KNOWN);
  });

  it("sends nothing to an owner without an alerting plan but keeps their baselines current", async () => {
    db.subscriptions = [];
    const result = await run({ ...ZONE, mx: [{ priority: 5, exchange: "new.example" }] });
    expect(result).toMatchObject({ delivered: false, reported: null });
    expect(result.silentlyRecorded).toHaveLength(5);
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(pending()).toEqual([]);
    expect(snapshot()?.mx).toEqual(["5 new.example"]);
  });

  it("alerts a Tier A owner, who is on a paid plan like any other", async () => {
    db.subscriptions[0].plan = "tier_a";
    db.asset_inventory.push(asset("new.example.com", false));
    const recon = { ...RECON, subdomains: [{ name: "new.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) }] } as ReconResult;
    expect((await run(ZONE, TARGET, recon)).delivered).toBe(true);
  });

  it("treats a cancelled subscription as no alerting plan, and alerts an admin without one", async () => {
    db.subscriptions[0].status = "canceled";
    await run();
    expect(sendEmailMock).not.toHaveBeenCalled();

    db.asset_inventory.push(asset("new.example.com", false));
    db.subscriptions = [];
    db.users[0].is_admin = true;
    const recon = { ...RECON, subdomains: [{ name: "new.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) }] } as ReconResult;
    expect((await run(ZONE, TARGET, recon)).delivered).toBe(true);
  });

  it("posts to Slack and Teams on Pro, but only emails on Basic", async () => {
    db.subscriptions[0].slack_webhook_url = SLACK;
    db.subscriptions[0].ms_teams_webhook_url = TEAMS;
    await run();
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([SLACK, TEAMS]);
    const slackBody = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(slackBody.text).toContain("dev.example.com (first certificate");
    expect(slackBody.blocks[2].elements[0].url).toBe("https://app.example/dashboard/assets");

    fetchMock.mockClear();
    db.asset_inventory.push(asset("new.example.com", false));
    db.subscriptions[0].plan = "basic";
    const recon = { ...RECON, subdomains: [{ name: "new.example.com", issuer: "R11", notBefore: daysAgo(1), firstNotBefore: daysAgo(1) }] } as ReconResult;
    await run(ZONE, TARGET, recon);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(sendEmailMock).toHaveBeenCalledTimes(2);
  });

  it("releases its claims when no channel delivered, so the next scan retries", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "RESEND_API_KEY not configured" });
    const result = await run({ ...ZONE, mx: [{ priority: 10, exchange: "other.example" }] });
    expect(result.delivered).toBe(false);
    expect(result.errors).toEqual(["email failed: RESEND_API_KEY not configured"]);
    expect(pending()).toEqual(["api.example.com", "dev.example.com"]); // the evidence-free ones stay known
    expect(snapshot()).toMatchObject({ mx: ZONE_VALUES.mx, captured_at: SNAPSHOT_AT });

    sendEmailMock.mockResolvedValue({ ok: true });
    const retry = await run({ ...ZONE, mx: [{ priority: 10, exchange: "other.example" }] });
    expect(retry.reported?.newHostnames).toHaveLength(2);
    expect(retry.reported?.dnsChanges).toHaveLength(1);
  });

  it("retries a released hostname a week later even though its certificate is now older than 14 days", async () => {
    db.asset_inventory = [asset("shop.example.com", false)];
    const recon = { ...RECON, subdomains: [{ name: "shop.example.com", issuer: "R11", notBefore: daysAgo(12), firstNotBefore: daysAgo(12) }] } as ReconResult;
    sendEmailMock.mockResolvedValue({ ok: false, error: "down" });
    expect((await run(ZONE, TARGET, recon)).delivered).toBe(false);

    sendEmailMock.mockResolvedValue({ ok: true });
    db.scans.push({ id: "scan-day0", owner: OWNER, target_url: TARGET, status: "completed", created_at: NOW.toISOString() });
    const weekLater = new Date(NOW.getTime() + 7 * 86_400_000);
    const result = await sendAttackSurfaceAlerts(makeClient(), OWNER, "scan-day7", TARGET, recon, { resolver: resolverFor(ZONE), now: weekLater });
    expect(result.reported?.newHostnames.map((h) => h.name)).toEqual(["shop.example.com"]);
  });

  it("counts a chat delivery when email fails, and reports the failures", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "bounced" });
    db.subscriptions[0].slack_webhook_url = SLACK;
    db.subscriptions[0].ms_teams_webhook_url = TEAMS;
    fetchMock.mockImplementation(async (url: string) => new Response(null, { status: url === TEAMS ? 500 : 200 }));
    const result = await run();
    expect(result.delivered).toBe(true);
    expect(result.errors).toEqual(["email failed: bounced", "Teams failed: Teams responded 500"]);
    expect(pending()).toEqual([]);
  });

  it("records an owner with no email address as an error", async () => {
    db.users[0].email = null;
    const result = await run();
    expect(result.delivered).toBe(false);
    expect(result.errors).toEqual(["no email address on file"]);
  });

  it("sends each change once when two scans of the same domain finish together", async () => {
    const zone = { ...ZONE, mx: [{ priority: 10, exchange: "mx.attacker.example" }] };
    const results = await Promise.all([run(zone), run(zone), run(zone, "https://shop.example.com")]);
    const sent = results.flatMap((r) => (r.reported ? [...r.reported.newHostnames.map((h) => h.name), ...r.reported.dnsChanges.map((c) => c.field)] : []));
    expect(sent.sort()).toEqual(["api.example.com", "dev.example.com", "mx"]);
    expect(snapshot()?.mx).toEqual(["10 mx.attacker.example"]);
  });

  it("reads every unreported hostname, page by page, and marks them in batches", async () => {
    db.asset_inventory = Array.from({ length: 2_500 }, (_, i) => asset(`h${String(i).padStart(4, "0")}.example.com`, false));
    const result = await run();
    expect(result.silentlyRecorded).toHaveLength(2_500);
    expect(pending()).toEqual([]);
    expect(updateCalls.filter((c) => c.table === "asset_inventory").map((c) => c.inValues.length)).toEqual(Array(25).fill(100));
  });

  it("does nothing before migration 049", async () => {
    dbErrors["asset_inventory:select"] = { code: "42703", message: "column asset_inventory.notified_at does not exist" };
    expect(await run()).toMatchObject({ migrationPending: true, errors: [], delivered: false });
    dbErrors = { "dns_snapshots:select": { code: "PGRST205", message: "no table" } };
    expect(await run()).toMatchObject({ migrationPending: true, errors: [] });
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(updateCalls).toEqual([]);
  });

  it("stops without sending or recording when a read fails", async () => {
    for (const key of ["asset_inventory:select", "dns_snapshots:select", "subscriptions:select", "users:select", "scans:select"]) {
      dbErrors = { [key]: { code: "57014", message: "timeout" } };
      const result = await run();
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toMatch(/timeout/);
      expect(result.delivered).toBe(false);
    }
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(updateCalls).toEqual([]);
    expect(upsertCalls).toEqual([]);
  });

  it("sends nothing it couldn't claim", async () => {
    dbErrors = { "asset_inventory:update": { message: "update failed" }, "dns_snapshots:update": { message: "claim failed" } };
    const result = await run({ ...ZONE, mx: [{ priority: 1, exchange: "x.example" }] });
    expect(result.delivered).toBe(false);
    expect(result.errors).toEqual(["could not mark hostnames as known: update failed", "could not claim new hostnames: update failed", "could not claim the DNS change: claim failed"]);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("reports a failed release and a failed snapshot write", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "down" });
    let updates = 0;
    const client = makeClient() as { from: (t: string) => Record<string, unknown> };
    const wrapped = {
      from: (t: string) => {
        const q = client.from(t);
        const update = q.update as (v: Row) => unknown;
        q.update = (v: Row) => {
          updates++;
          if (v.notified_at === null || (t === "dns_snapshots" && v.captured_at === SNAPSHOT_AT)) dbErrors[`${t}:update`] = { message: "release failed" };
          return update(v);
        };
        return q;
      },
    } as never;
    const result = await sendAttackSurfaceAlerts(wrapped, OWNER, SCAN, TARGET, RECON, { resolver: resolverFor({ ...ZONE, mx: [{ priority: 1, exchange: "x.example" }] }), now: NOW });
    expect(updates).toBeGreaterThan(0);
    expect(result.errors).toEqual(["email failed: down", "could not release new hostnames for a retry: release failed", "could not release the DNS change for a retry: release failed"]);

    dbErrors = { "dns_snapshots:upsert": { message: "upsert failed" } };
    db.dns_snapshots = [];
    db.asset_inventory = [];
    expect((await run()).errors).toEqual(["could not save the DNS snapshot: upsert failed"]);
  });

  it("skips DNS and reports no hostnames for a target without a registrable domain", async () => {
    const resolver = resolverFor(ZONE);
    db.asset_inventory = [asset("x.internal", false, "https://10.0.0.5")];
    const result = await sendAttackSurfaceAlerts(makeClient(), OWNER, SCAN, "https://10.0.0.5", RECON, { resolver, now: NOW });
    expect(resolver.calls).toEqual([]);
    expect(result).toMatchObject({ reported: null, silentlyRecorded: ["x.internal"] });
  });

  it("looks DNS up with the system resolver, with short timeouts, when none is given", async () => {
    db.asset_inventory = [];
    const result = await sendAttackSurfaceAlerts(makeClient(), OWNER, SCAN, TARGET, RECON, { now: NOW });
    expect(resolverOptions).toEqual([{ timeout: 5_000, tries: 2 }]);
    expect(result).toMatchObject({ reported: null, errors: [], unanswered: ["ns", "mx", "spf", "dmarc"] });
    expect(snapshot()).toMatchObject({ ...ZONE_VALUES, captured_at: SNAPSHOT_AT });
  });

  it("never throws", async () => {
    expect((await run(ZONE, "not a url")).errors[0]).toMatch(/Invalid URL/);
    const broken = { from: () => { throw new Error("client exploded"); } } as never;
    const result = await sendAttackSurfaceAlerts(broken, OWNER, SCAN, TARGET, RECON, { resolver: resolverFor(ZONE) });
    expect(result.errors).toEqual(["client exploded"]);
  });
});

// ---- The standalone EASM sweep's alert ---------------------------------------------------------

describe("sendSweepHostnameAlerts", () => {
  /** What the sweep's own crt.sh read yields for the fixture: api and dev are new, staging is years old. */
  const EVIDENCE = { firstCertificates: firstCertificates(RECON), ctRead: true };
  const sweep = (evidence: { firstCertificates: Map<string, string>; ctRead: boolean } = EVIDENCE, target = TARGET) =>
    sendSweepHostnameAlerts(makeClient(), OWNER, target, evidence, { now: NOW, siteUrl: "https://app.example" });

  it("reports hostnames with certificate evidence they are new, and records the rest as known", async () => {
    const result = await sweep();

    expect(result).toMatchObject({ delivered: true, hostnamesDeferred: false, migrationPending: false, errors: [] });
    expect(result.reported).toEqual({
      site: "example.com",
      newHostnames: [
        { name: "api.example.com", firstCertificate: daysAgo(1) },
        { name: "dev.example.com", firstCertificate: daysAgo(3) },
      ],
      dnsChanges: [],
      source: "sweep",
    });
    // Same evidence rules as the scan path: the scanned host itself, old certificates and names with no certificate date are known, not new.
    expect(result.silentlyRecorded).toEqual(["staging.example.com", "subfinder-only.example.com", "www.shop.example.com"]);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sendEmailMock.mock.calls[0][0]).toMatchObject({ to: "owner@shop.example.com", subject: "2 new hostnames found for example.com" });
    expect(pending()).toEqual([]);
    expect(notifiedAt("api.example.com")).toBe(NOW.toISOString());
    expect(upsertCalls).toEqual([]); // a sweep never touches the DNS snapshot
  });

  it("words the email as the sweep's own check, not as the result of a scan the owner did not just run", async () => {
    await sweep();
    const html = sendEmailMock.mock.calls[0][0].html as string;
    expect(html).toContain("Our regular check of public certificate logs for example.com found these changes.");
    expect(html).not.toContain("Your latest scan");
    expect(html).not.toContain("DNS changes");
  });

  it("tells the owner once, however many sweeps run", async () => {
    await sweep();
    sendEmailMock.mockClear();

    expect((await sweep()).reported).toBeNull();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does not repeat what a scan already reported", async () => {
    await run(); // the scan's own alert goes first
    sendEmailMock.mockClear();

    expect((await sweep()).reported).toBeNull();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  describe("rows stored under a different URL than the monitored site", () => {
    // The EASM step used to store https://<domain> for every hostname it found, while a scan
    // of https://www.<domain> reads pending rows by its own exact URL. Those rows were never
    // reported and never marked known.
    beforeEach(() => {
      db.asset_inventory = [asset("api.example.com", false, "https://example.com")];
    });

    it("the scan alert cannot see them (the defect)", async () => {
      expect((await run()).reported).toBeNull();
      expect(pending()).toEqual(["api.example.com"]); // stuck pending forever
    });

    it("the sweep finds them by owner and domain, so they are finally reported", async () => {
      const result = await sweep();
      expect(result.reported?.newHostnames.map((h) => h.name)).toEqual(["api.example.com"]);
      expect(pending()).toEqual([]);
    });
  });

  it("leaves other domains and other owners' rows alone", async () => {
    db.asset_inventory = [
      asset("api.example.com", false),
      asset("api.other.net", false, "https://other.net"),
      asset("notexample.com", false, "https://notexample.com"), // ends with the same letters, is not in the domain
      { ...asset("dev.example.com", false), owner: "someone-else" },
    ];
    const evidence = {
      ctRead: true,
      firstCertificates: new Map([
        ["api.example.com", daysAgo(1)],
        ["api.other.net", daysAgo(1)],
        ["notexample.com", daysAgo(1)],
        ["dev.example.com", daysAgo(1)],
      ]),
    };

    const result = await sweep(evidence);

    expect(result.reported?.newHostnames.map((h) => h.name)).toEqual(["api.example.com"]);
    expect(pending()).toEqual(["api.other.net", "notexample.com", "dev.example.com"]);
  });

  it("decides nothing when crt.sh could not be read: no email, nothing marked, rows stay pending", async () => {
    const before = pending();
    const result = await sweep({ firstCertificates: new Map(), ctRead: false });

    expect(result).toMatchObject({ hostnamesDeferred: true, delivered: false, reported: null, silentlyRecorded: [] });
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(updateCalls).toEqual([]);
    expect(pending()).toEqual(before);
  });

  it("looks back to the previous scan when it was more than 14 days ago", async () => {
    // A sweep has no scan in progress, so unlike the scan path's fixture there is no "current" scan row
    // to exclude: the only scan is the old one, taken a month and more ago.
    db.scans = [{ ...db.scans[1], created_at: "2026-08-01T00:00:00Z" }];
    db.asset_inventory = [asset("month.example.com", false)];
    const evidence = { ctRead: true, firstCertificates: new Map([["month.example.com", daysAgo(30)]]) };
    expect((await sweep(evidence)).reported?.newHostnames.map((h) => h.name)).toEqual(["month.example.com"]);
  });

  it("does not look back past a recent scan: a hostname that scan already evaluated is not pending", async () => {
    // The fixture's latest scan is recent (the scan row for NOW), so the window stays at 14 days
    // and a 30-day-old certificate is not new.
    db.asset_inventory = [asset("month.example.com", false)];
    const evidence = { ctRead: true, firstCertificates: new Map([["month.example.com", daysAgo(30)]]) };
    expect((await sweep(evidence)).silentlyRecorded).toEqual(["month.example.com"]);
  });

  it("uses the 14-day window when the previous scan was recent", async () => {
    db.asset_inventory = [asset("month.example.com", false)];
    const evidence = { ctRead: true, firstCertificates: new Map([["month.example.com", daysAgo(20)]]) };
    expect((await sweep(evidence)).silentlyRecorded).toEqual(["month.example.com"]);
  });

  it("records everything as known for an owner without an alerting plan, so upgrading doesn't replay old hostnames", async () => {
    db.subscriptions[0].status = "cancelled";
    const result = await sweep({ firstCertificates: new Map(), ctRead: false }); // even with no certificate evidence

    expect(result.silentlyRecorded).toHaveLength(5);
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(pending()).toEqual([]);
  });

  it("releases its claims when nothing was delivered, and the next sweep retries and succeeds", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "RESEND_API_KEY not configured" });

    const failed = await sweep();
    expect(failed).toMatchObject({ delivered: false, reported: null });
    expect(failed.errors).toContain("email failed: RESEND_API_KEY not configured");
    // The two reportable hostnames are pending again; the ones recorded as known stay known.
    expect(pending()).toEqual(["api.example.com", "dev.example.com"]);

    sendEmailMock.mockResolvedValue({ ok: true });
    expect((await sweep()).reported?.newHostnames.map((h) => h.name)).toEqual(["api.example.com", "dev.example.com"]);
    expect(pending()).toEqual([]);
  });

  it("also tells the owner's Slack channel, like the scan alert does", async () => {
    db.subscriptions[0].slack_webhook_url = SLACK;
    await sweep();
    expect(fetchMock.mock.calls.map((c) => c[0])).toContain(SLACK);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
  });

  it("does nothing before the schema change is applied, instead of failing", async () => {
    dbErrors["asset_inventory:select"] = { code: "42703", message: "column asset_inventory.notified_at does not exist" };
    expect(await sweep()).toMatchObject({ migrationPending: true, errors: [], delivered: false });
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does nothing for a site with no registrable domain", async () => {
    const result = await sweep(EVIDENCE, "https://localhost");
    expect(result).toMatchObject({ reported: null, delivered: false, errors: [] });
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("never throws: a database error is returned, not raised", async () => {
    dbErrors["asset_inventory:select"] = { code: "XX000", message: "connection reset" };
    const result = await sweep();
    expect(result.errors).toEqual(["could not load unreported hostnames: connection reset"]);
    expect(result.delivered).toBe(false);
  });
});
