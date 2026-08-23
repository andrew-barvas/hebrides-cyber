import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const {
  resolveTxtMock,
  resolveCaaMock,
  resolve6Mock,
  resolveMxMock,
  resolveMock,
} = vi.hoisted(() => ({
  resolveTxtMock: vi.fn(),
  resolveCaaMock: vi.fn(),
  resolve6Mock: vi.fn(),
  resolveMxMock: vi.fn(),
  resolveMock: vi.fn(),
}));

// NOT `importOriginal`-based (`{ ...actual, resolveCaa: mock }`) — that
// form resolves "node:dns/promises" a second, distinct time that never
// gets unified with the instance dns.ts itself imports, so the mocks
// silently never intercept (confirmed by resolveCaaMock.mock.calls staying
// empty while checkDns() quietly ran real DNS lookups against the real
// network). A fully static factory listing every export dns.ts actually
// uses does intercept correctly.
vi.mock("node:dns/promises", () => {
  const exports = {
    resolveTxt: resolveTxtMock,
    resolveCaa: resolveCaaMock,
    resolve6: resolve6Mock,
    resolveMx: resolveMxMock,
    resolve: resolveMock,
  };
  return { ...exports, default: exports };
});

import { checkDns } from "./dns";

// resolveTxt is called for three different names in one checkDns() run
// (the domain itself for SPF, then _dmarc, then per-selector DKIM probes,
// then conditionally _mta-sts/_smtp._tls) — route by the queried name so
// each test can configure exactly what each lookup returns rather than
// relying on call order.
function routeResolveTxt(byName: Record<string, string[][] | "reject">) {
  resolveTxtMock.mockImplementation(async (name: string) => {
    const entry = byName[name];
    if (entry === undefined || entry === "reject") throw new Error("ENOTFOUND");
    return entry;
  });
}

describe("checkDns", () => {
  beforeEach(() => {
    resolveTxtMock.mockReset().mockRejectedValue(new Error("ENOTFOUND"));
    resolveCaaMock.mockReset().mockResolvedValue([]);
    resolve6Mock.mockReset().mockRejectedValue(new Error("ENOTFOUND"));
    resolveMxMock.mockReset().mockResolvedValue([]); // no MX by default — MTA-STS/TLS-RPT skipped
    resolveMock.mockReset().mockResolvedValue([]); // DS lookup — DNSSEC
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns status: checked with sensible defaults when nothing resolves", async () => {
    const result = await checkDns("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.spf.present).toBe(false);
    expect(result.dmarc.present).toBe(false);
    expect(result.caa.present).toBe(false);
    expect(result.dkim.found).toBe(false);
    expect(result.mxCount).toBe(0);
  });

  describe("SPF", () => {
    it("flags a missing SPF record", async () => {
      routeResolveTxt({ "example.com": [] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.present).toBe(false);
      expect(result.spf.issues[0]).toContain("No SPF record");
    });

    it("flags '+all' as allowing any sender", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com +all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues.some((i) => i.includes("+all") || i.includes("'all'"))).toBe(true);
    });

    it("flags '~all' (softfail) distinctly from '-all'", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com ~all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues.some((i) => i.includes("~all"))).toBe(true);
    });

    it("does not flag a strict '-all' policy", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com -all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues).toEqual([]);
    });

    it("flags multiple SPF records as invalid", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 -all"], ["v=spf1 include:_spf.google.com -all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues.some((i) => i.includes("Multiple SPF"))).toBe(true);
    });
  });

  describe("DMARC", () => {
    it("flags a missing DMARC record", async () => {
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.present).toBe(false);
    });

    it("flags policy 'none' as unenforced", async () => {
      routeResolveTxt({ "_dmarc.example.com": [["v=DMARC1; p=none; rua=mailto:d@example.com"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.policy).toBe("none");
      expect(result.dmarc.issues.some((i) => i.includes("'none'"))).toBe(true);
    });

    it("flags a missing rua= reporting address", async () => {
      routeResolveTxt({ "_dmarc.example.com": [["v=DMARC1; p=reject"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.issues.some((i) => i.includes("rua"))).toBe(true);
    });

    it("reports a clean p=reject with rua= as issue-free", async () => {
      routeResolveTxt({ "_dmarc.example.com": [["v=DMARC1; p=reject; pct=100; rua=mailto:d@example.com"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.issues).toEqual([]);
    });
  });

  describe("DKIM", () => {
    it("reports not-found without proving absence when no selector matches", async () => {
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dkim.found).toBe(false);
      expect(result.dkim.selectorsTried).toBeGreaterThan(0);
    });

    it("finds a key at one of the common selectors", async () => {
      routeResolveTxt({ "google._domainkey.example.com": [["v=DKIM1; k=rsa; p=" + "A".repeat(300)]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dkim.found).toBe(true);
      expect(result.dkim.selector).toBe("google");
    });

    it("flags a revoked key (empty p=)", async () => {
      routeResolveTxt({ "google._domainkey.example.com": [["v=DKIM1; k=rsa; p="]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dkim.found).toBe(true);
      expect(result.dkim.issues.some((i) => i.includes("revoked"))).toBe(true);
    });

    it("flags testing mode (t=y)", async () => {
      routeResolveTxt({ "google._domainkey.example.com": [["v=DKIM1; k=rsa; t=y; p=" + "A".repeat(300)]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dkim.issues.some((i) => i.includes("testing mode"))).toBe(true);
    });
  });

  describe("CAA", () => {
    it("flags a missing CAA record", async () => {
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.caa.present).toBe(false);
    });

    it("reports present with no issues when a real issue record exists", async () => {
      resolveCaaMock.mockResolvedValue([{ critical: 0, issue: "letsencrypt.org" }]);
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.caa.present).toBe(true);
      expect(result.caa.issues).toEqual([]);
    });
  });

  describe("DNSSEC", () => {
    it("reports likelySigned when a DS record is present", async () => {
      resolveMock.mockResolvedValue([{ keyTag: 1, algorithm: 8, digestType: 2, digest: "abc" }]);
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dnssec.likelySigned).toBe(true);
    });

    it("reports not signed (but inconclusive, not asserted) when the DS lookup fails", async () => {
      resolveMock.mockRejectedValue(new Error("ENODATA"));
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dnssec.likelySigned).toBe(false);
    });
  });

  describe("MTA-STS and TLS-RPT — only checked when the domain has MX records", () => {
    it("skips both entirely when there are no MX records", async () => {
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.mtaSts.dnsRecordPresent).toBe(false);
      expect(result.tlsRpt.present).toBe(false);
      // fetch (used only inside checkMtaSts) must never be called when
      // there's no mail transport to protect in the first place.
    });

    it("checks MTA-STS policy enforcement mode when MX records exist", async () => {
      resolveMxMock.mockResolvedValue([{ exchange: "mail.example.com", priority: 10 }]);
      routeResolveTxt({ "_mta-sts.example.com": [["v=STSv1; id=1"]] });
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(new Response("version: STSv1\nmode: testing\nmx: mail.example.com\n", { status: 200 }))
      );

      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.mtaSts.dnsRecordPresent).toBe(true);
      expect(result.mtaSts.mode).toBe("testing");
      expect(result.mtaSts.issues.some((i) => i.includes("testing"))).toBe(true);
    });

    it("flags a dangling MTA-STS DNS record when the policy file 404s", async () => {
      resolveMxMock.mockResolvedValue([{ exchange: "mail.example.com", priority: 10 }]);
      routeResolveTxt({ "_mta-sts.example.com": [["v=STSv1; id=1"]] });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 404 })));

      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.mtaSts.policyFetched).toBe(false);
      expect(result.mtaSts.issues.some((i) => i.includes("dangling pointer"))).toBe(true);
    });

    it("flags TLS-RPT present without a rua= address", async () => {
      resolveMxMock.mockResolvedValue([{ exchange: "mail.example.com", priority: 10 }]);
      routeResolveTxt({ "_smtp._tls.example.com": [["v=TLSRPTv1"]] });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 404 })));

      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.tlsRpt.present).toBe(true);
      expect(result.tlsRpt.issues.some((i) => i.includes("rua"))).toBe(true);
    });
  });

  it("reports ipv6 true only when AAAA records actually resolve", async () => {
    resolve6Mock.mockResolvedValue(["2001:db8::1"]);
    const result = await checkDns("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.ipv6).toBe(true);
  });

  it("uses the hostname from the target URL, not the whole URL, for lookups", async () => {
    routeResolveTxt({ "example.com": [["v=spf1 -all"]] });
    const result = await checkDns("https://example.com/some/path?x=1");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.spf.present).toBe(true);
  });
});
