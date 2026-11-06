import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { FindingRow, HostDetail } from "./findingsView";
import {
  buildHostSignals,
  buildTargetContexts,
  CRITICALITY_MULTIPLIER,
  DEFAULT_TARGET_CONTEXT,
  explainFactors,
  loadTargetContexts,
  rankFindings,
  scoreFinding,
  type HostSignals,
  type TargetContext,
} from "./estatePriority";

const row = (over: Partial<FindingRow> = {}): FindingRow => ({
  key: "a.example headers.hsts", host: "a.example", checkId: "headers.hsts", checkBase: "headers.hsts", category: "headers",
  severity: "medium", title: "Missing HSTS", detail: null, firstSeenAt: "2026-09-01T00:00:00Z", ageDays: 30, slaState: null, slaDueAt: null,
  knownExploited: false, ransomware: false, epss: null, cvssScore: null, cveIds: [], scanId: "s1", triage: null, exploitabilityAssessment: null, ...over,
});

const noSignals: HostSignals = { live: false, waf: null };
const ctx = (over: Partial<TargetContext> = {}): TargetContext => ({ ...DEFAULT_TARGET_CONTEXT, ...over });
const labels = (r: ReturnType<typeof scoreFinding>) => r.factors.map((f) => f.key);

describe("scoreFinding", () => {
  it("is riskScore's penalty alone for a normal, unknown-signal site", () => {
    const r = scoreFinding(row({ severity: "high" }), DEFAULT_TARGET_CONTEXT, undefined);
    expect(r).toMatchObject({ base: 15, score: 15 });
    expect(labels(r)).toEqual(["severity"]);
  });

  it("weights by criticality both ways", () => {
    expect(scoreFinding(row({ severity: "high" }), ctx({ criticality: "high" }), noSignals).score).toBe(15 * CRITICALITY_MULTIPLIER.high);
    expect(scoreFinding(row({ severity: "high" }), ctx({ criticality: "low" }), noSignals).score).toBe(9);
  });

  it("explains KEV and criticality in plain English", () => {
    const r = scoreFinding(row({ severity: "high", knownExploited: true }), ctx({ criticality: "high" }), noSignals);
    expect(explainFactors(r.factors)).toBe("High severity, KEV listed, on a high-criticality site");
    expect(r.base).toBe(22.5);
    expect(r.score).toBe(33.8);
  });

  it("names ransomware use and EPSS, and EPSS only when not KEV", () => {
    expect(explainFactors(scoreFinding(row({ severity: "critical", knownExploited: true, ransomware: true, epss: 0.9 }), DEFAULT_TARGET_CONTEXT, undefined).factors)).toBe(
      "Critical severity, KEV listed and used in ransomware"
    );
    expect(explainFactors(scoreFinding(row({ epss: 0.62 }), DEFAULT_TARGET_CONTEXT, undefined).factors)).toBe(
      "Medium severity, 62% chance of exploitation (EPSS)"
    );
    // Below 10% EPSS is not worth a clause.
    expect(labels(scoreFinding(row({ epss: 0.05 }), DEFAULT_TARGET_CONTEXT, undefined))).toEqual(["severity"]);
  });

  it("mentions CVSS only when it outranks the stated severity", () => {
    expect(explainFactors(scoreFinding(row({ cvssScore: 9.8 }), DEFAULT_TARGET_CONTEXT, undefined).factors)).toBe("Medium severity, CVSS 9.8");
    expect(scoreFinding(row({ cvssScore: 9.8 }), DEFAULT_TARGET_CONTEXT, undefined).base).toBe(30);
    expect(labels(scoreFinding(row({ severity: "high", cvssScore: 7.5 }), DEFAULT_TARGET_CONTEXT, undefined))).toEqual(["severity"]);
  });

  it("raises an internet-facing service and names its port", () => {
    const r = scoreFinding(
      row({ checkId: "network-exposure.open-port:3389", checkBase: "network-exposure.open-port", category: "network-exposure", severity: "high" }),
      DEFAULT_TARGET_CONTEXT,
      undefined
    );
    expect(r.score).toBe(19.5);
    expect(explainFactors(r.factors)).toBe("High severity, on an internet-facing service (port 3389)");
    const shodan = scoreFinding(row({ checkId: "recon.shodan-cves", checkBase: "recon.shodan-cves", category: "recon" }), DEFAULT_TARGET_CONTEXT, undefined);
    expect(shodan.factors.find((f) => f.key === "internet_facing")?.label).toBe("on an internet-facing service");
  });

  it("lowers non-production sites but leaves production and unstated alone", () => {
    expect(explainFactors(scoreFinding(row(), ctx({ environment: "staging" }), undefined).factors)).toBe("Medium severity, on a staging site");
    expect(scoreFinding(row(), ctx({ environment: "staging" }), undefined).score).toBe(5.6);
    expect(scoreFinding(row(), ctx({ environment: "production" }), undefined).score).toBe(7);
    expect(scoreFinding(row(), ctx({ environment: null }), undefined).score).toBe(7);
  });

  it("raises a confirmed-live host and never lowers an unconfirmed one", () => {
    expect(scoreFinding(row(), DEFAULT_TARGET_CONTEXT, { live: true, waf: null }).score).toBe(7.7);
    expect(scoreFinding(row(), DEFAULT_TARGET_CONTEXT, { live: false, waf: null }).score).toBe(7);
  });

  it("discounts web-attack findings behind a WAF, but not KEV and not header findings", () => {
    const xss = row({ checkId: "zap.xss:1", checkBase: "zap.xss", category: "zap", severity: "critical" });
    const waf: HostSignals = { live: false, waf: "Cloudflare" };
    const r = scoreFinding(xss, DEFAULT_TARGET_CONTEXT, waf);
    expect(r.score).toBe(25.5);
    expect(explainFactors(r.factors)).toBe("Critical severity, behind a WAF (Cloudflare)");
    expect(labels(scoreFinding({ ...xss, knownExploited: true }, DEFAULT_TARGET_CONTEXT, waf))).not.toContain("waf");
    expect(labels(scoreFinding(row(), DEFAULT_TARGET_CONTEXT, waf))).not.toContain("waf");
  });

  it("scores info findings zero (nothing to fix)", () => {
    expect(scoreFinding(row({ severity: "info" }), ctx({ criticality: "high" }), { live: true, waf: null }).score).toBe(0);
  });
});

describe("rankFindings", () => {
  it("ranks a high-criticality medium above a normal-criticality one, and drops triaged and info", () => {
    const rows = [
      row({ key: "a h", host: "a.example" }),
      row({ key: "b h", host: "b.example" }),
      row({ key: "c h", host: "c.example", severity: "critical", triage: { state: "accepted_risk", reason: "x", expiresAt: null } }),
      row({ key: "d h", host: "d.example", severity: "info" }),
    ];
    const ranked = rankFindings(rows, new Map([["b.example", ctx({ criticality: "high" })]]), new Map());
    expect(ranked.map((r) => [r.host, r.priority.rank])).toEqual([
      ["b.example", 1],
      ["a.example", 2],
    ]);
    expect(ranked[0].priority.reason).toBe("Medium severity, on a high-criticality site");
  });

  it("lets a KEV high on an important site beat a plain critical on a low one", () => {
    const ranked = rankFindings(
      [
        row({ key: "x", host: "brochure.example", severity: "critical" }),
        row({ key: "y", host: "shop.example", severity: "high", knownExploited: true }),
      ],
      new Map([
        ["brochure.example", ctx({ criticality: "low" })],
        ["shop.example", ctx({ criticality: "high" })],
      ]),
      new Map()
    );
    expect(ranked.map((r) => r.host)).toEqual(["shop.example", "brochure.example"]);
    expect(ranked[1].priority).toMatchObject({ score: 18, base: 30 });
  });

  it("breaks score ties with the usual severity/age order, so the list is stable", () => {
    const ranked = rankFindings(
      [row({ key: "young", host: "a.example", ageDays: 1 }), row({ key: "old", host: "b.example", ageDays: 90 })],
      new Map(),
      new Map()
    );
    expect(ranked.map((r) => r.key)).toEqual(["old", "young"]);
  });

  it("keeps every findingsView field on the ranked rows", () => {
    const [r] = rankFindings([row({ scanId: "scan-9" })], new Map(), new Map());
    expect(r).toMatchObject({ scanId: "scan-9", checkId: "headers.hsts", priority: { rank: 1 } });
  });
});

describe("buildHostSignals", () => {
  const detail = (findings: HostDetail["findings"]): HostDetail => ({ scanId: "s", findings });

  it("reads the WAF name and HTTP evidence from a host's latest scan", () => {
    const s = buildHostSignals(
      new Map([
        ["a.example", detail([{ checkId: "whatwaf.waf-detected", title: "[WhatWaf] WAF detected: Cloudflare" }, { checkId: "headers.hsts-missing" }])],
        ["b.example", detail([{ checkId: "whatwaf.no-waf", title: "[WhatWaf] No Web Application Firewall detected" }, { checkId: "dns.spf-missing" }])],
      ])
    );
    expect(s.get("a.example")).toEqual({ live: true, waf: "Cloudflare" });
    // No WAF and no HTTP evidence: unknown, so nothing to boost or discount.
    expect(s.get("b.example")).toEqual({ live: false, waf: null });
  });

  it("marks a sibling host live from another scan's httpx finding", () => {
    const s = buildHostSignals(new Map([["example.com", detail([{ checkId: "http-probe.live:Admin.Example.com" }])]]));
    expect(s.get("admin.example.com")).toEqual({ live: true, waf: null });
    expect(s.get("example.com")).toEqual({ live: false, waf: null });
  });

  it("tolerates a WAF finding without a name and findings without a checkId", () => {
    const s = buildHostSignals(new Map([["a.example", detail([{ checkId: "whatwaf.waf-detected" }, { title: "untagged" }])]]));
    expect(s.get("a.example")?.waf).toBe("detected");
  });
});

describe("buildTargetContexts", () => {
  it("maps target URLs to hosts and sanitises unknown values to the defaults", () => {
    const m = buildTargetContexts([
      { target_url: "https://Shop.Example/", criticality: "high", environment: "production" },
      { target_url: "https://dev.example", criticality: "extreme", environment: "prod" },
      { target_url: "not a url", criticality: "high" },
      { target_url: "https://old.example" },
    ]);
    expect(m.get("shop.example")).toEqual({ criticality: "high", environment: "production" });
    expect(m.get("dev.example")).toEqual({ criticality: "normal", environment: null });
    expect(m.get("old.example")).toEqual(DEFAULT_TARGET_CONTEXT);
    expect(m.size).toBe(3);
  });

  it("takes the higher criticality when two rows share a host", () => {
    const m = buildTargetContexts([
      { target_url: "http://a.example", criticality: "high", environment: "staging" },
      { target_url: "https://a.example", criticality: "low" },
      { target_url: "https://b.example", criticality: "low" },
      { target_url: "http://b.example", criticality: "normal" },
    ]);
    expect(m.get("a.example")).toEqual({ criticality: "high", environment: "staging" });
    expect(m.get("b.example")?.criticality).toBe("normal");
  });
});

describe("loadTargetContexts", () => {
  const client = (result: { data: unknown; error: unknown }) => {
    const eq = vi.fn().mockResolvedValue(result);
    const select = vi.fn(() => ({ eq }));
    return { client: { from: vi.fn(() => ({ select })) } as unknown as SupabaseClient, select, eq };
  };

  it("reads the caller's own targets", async () => {
    const c = client({ data: [{ target_url: "https://a.example", criticality: "high", environment: null }], error: null });
    const r = await loadTargetContexts(c.client, "o1");
    expect(c.select).toHaveBeenCalledWith("target_url, criticality, environment");
    expect(c.eq).toHaveBeenCalledWith("owner", "o1");
    expect(r).toMatchObject({ available: true, complete: true });
    expect(r.contexts.get("a.example")?.criticality).toBe("high");
  });

  it("treats a missing column as before-067: unavailable but complete", async () => {
    const r = await loadTargetContexts(client({ data: null, error: { code: "42703" } }).client, "o1");
    expect(r).toMatchObject({ available: false, complete: true });
    expect(r.contexts.size).toBe(0);
  });

  it("marks any other failure incomplete rather than pretending every site is normal", async () => {
    const r = await loadTargetContexts(client({ data: null, error: { code: "500", message: "boom" } }).client, "o1");
    expect(r).toMatchObject({ available: true, complete: false });
  });
});
