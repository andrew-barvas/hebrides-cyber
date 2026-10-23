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

// checkDnssec asks Cloudflare DoH for the DS record; route that by URL so the
// MTA-STS tests (which stub fetch themselves) are unaffected.
function stubDoh(body: unknown, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(body), { status }))
  );
}

describe("checkDns", () => {
  beforeEach(() => {
    resolveTxtMock.mockReset().mockRejectedValue(new Error("ENOTFOUND"));
    resolveCaaMock.mockReset().mockResolvedValue([]);
    resolve6Mock.mockReset().mockRejectedValue(new Error("ENOTFOUND"));
    resolveMxMock.mockReset().mockResolvedValue([]); // no MX by default — MTA-STS/TLS-RPT skipped
    vi.unstubAllGlobals();
    stubDoh({ Status: 0 }); // DNSSEC DS lookup (DNS-over-HTTPS) — no DS answer by default
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

  // Regression: scanning https://www.hebridescyber.co.uk reported "No SPF
  // record" and "No DMARC record" because both were looked up on the www
  // host (a CNAME to Azure, no TXT at all). The records live on the
  // registered domain, and that's where they must be read.
  describe("scanning a www host", () => {
    it("reads SPF, DMARC and MX from the registered domain, not the www host", async () => {
      routeResolveTxt({
        "example.co.uk": [["v=spf1 include:spf.protection.outlook.com -all"]],
        "_dmarc.example.co.uk": [["v=DMARC1; p=quarantine; rua=mailto:d@example.co.uk"]],
      });
      resolveMxMock.mockImplementation(async (name: string) =>
        name === "example.co.uk" ? [{ exchange: "example-co-uk.mail.protection.outlook.com", priority: 0 }] : []
      );

      const result = await checkDns("https://www.example.co.uk/");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.present).toBe(true);
      expect(result.dmarc.present).toBe(true);
      expect(result.mxCount).toBe(1);
      expect(resolveTxtMock).not.toHaveBeenCalledWith("www.example.co.uk");
      expect(resolveTxtMock).not.toHaveBeenCalledWith("_dmarc.www.example.co.uk");
    });

    it("checks IPv6 on the web host itself", async () => {
      await checkDns("https://www.example.co.uk/");
      expect(resolve6Mock).toHaveBeenCalledWith("www.example.co.uk");
    });

    it("climbs to the registered domain for CAA, as CAs do, when the host has none", async () => {
      resolveCaaMock.mockImplementation(async (name: string) => {
        if (name === "example.co.uk") return [{ critical: 0, issue: "letsencrypt.org" }];
        throw Object.assign(new Error("ENODATA"), { code: "ENODATA" });
      });
      const result = await checkDns("https://www.example.co.uk/");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.caa.present).toBe(true);
    });

    it("prefers the host's own CAA set over its parent's", async () => {
      resolveCaaMock.mockImplementation(async (name: string) =>
        name === "www.example.co.uk" ? [{ critical: 0, issue: "digicert.com" }] : [{ critical: 0, issue: "letsencrypt.org" }]
      );
      await checkDns("https://www.example.co.uk/");
      expect(resolveCaaMock).toHaveBeenCalledTimes(1);
      expect(resolveCaaMock).toHaveBeenCalledWith("www.example.co.uk");
    });
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
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com +all"]], "_spf.google.com": [["v=spf1 -all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues.some((i) => i.includes("+all") || i.includes("'all'"))).toBe(true);
    });

    it("flags '~all' (softfail) distinctly from '-all'", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com ~all"]], "_spf.google.com": [["v=spf1 -all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues.some((i) => i.includes("~all"))).toBe(true);
    });

    it("does not flag a strict '-all' policy whose include chain resolves within the limit", async () => {
      // The include target must resolve so the recursive lookup counter sees a
      // complete, under-limit chain — otherwise it would (correctly) note it
      // could not be fully evaluated, which is a separate concern from the
      // qualifier check this test covers.
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com -all"]], "_spf.google.com": [["v=spf1 ip4:1.2.3.0/24 -all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues).toEqual([]);
      expect(result.spf.lookupCount).toBe(1);
      expect(result.spf.lookupError).toBe(false);
    });

    it("flags multiple SPF records as invalid", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 -all"], ["v=spf1 include:_spf.google.com -all"]], "_spf.google.com": [["v=spf1 -all"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.issues.some((i) => i.includes("Multiple SPF"))).toBe(true);
    });
  });

  describe("SPF recursive lookup counting (RFC 7208 §4.6.4)", () => {
    it("counts nested include lookups, not just the top-level ones, and flags >10", async () => {
      // Top-level record spends 1 (include:a). a spends 10 more (10 includes
      // to leaf records that each cost 0) → 11 total, over the limit.
      routeResolveTxt({ "example.com": [["v=spf1 include:a.example -all"]] });
      const chain: Record<string, string> = {
        "a.example": "v=spf1 " + Array.from({ length: 10 }, (_, i) => `include:leaf${i}.example`).join(" ") + " -all",
      };
      for (let i = 0; i < 10; i++) chain[`leaf${i}.example`] = "v=spf1 -all"; // no further lookups
      const spfLookup = async (name: string) => chain[name] ?? null;

      const result = await checkDns("https://example.com", { spfLookup });
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.lookupCount).toBe(11);
      expect(result.spf.lookupError).toBe(false);
      expect(result.spf.issues.some((i) => i.includes("11 DNS lookups") && i.includes("limit of 10"))).toBe(true);
    });

    it("stays silent for a chain that totals 10 or fewer", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:_spf.google.com -all"]] });
      const spfLookup = async (name: string) =>
        name === "_spf.google.com" ? "v=spf1 include:_netblocks.google.com ~all" : name === "_netblocks.google.com" ? "v=spf1 ip4:1.2.3.0/24 -all" : null;
      const result = await checkDns("https://example.com", { spfLookup });
      if (result.status !== "checked") throw new Error("expected checked");
      // 1 (top include) + 1 (nested include) + 0 (ip4 is free) = 2.
      expect(result.spf.lookupCount).toBe(2);
      expect(result.spf.issues.some((i) => i.includes("DNS lookup"))).toBe(false);
    });

    it("terminates on a circular include and never claims a definitive 'exceeds'", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:a.example -all"]] });
      // a → b → a (cycle). The visited-set breaks it; the count is whatever
      // was tallied before the loop closed, and no infinite recursion occurs.
      const spfLookup = async (name: string) =>
        name === "a.example" ? "v=spf1 include:b.example -all" : name === "b.example" ? "v=spf1 include:a.example -all" : null;
      const result = await checkDns("https://example.com", { spfLookup });
      if (result.status !== "checked") throw new Error("expected checked");
      // 3 includes seen (top→a, a→b, b→a-but-already-visited is skipped), none over 10.
      expect(result.spf.lookupCount).toBeLessThanOrEqual(10);
      expect(result.spf.issues.some((i) => i.includes("over the RFC 7208 limit"))).toBe(false);
    });

    it("reports 'could not evaluate', not 'exceeds', when a chain record fails to resolve", async () => {
      routeResolveTxt({ "example.com": [["v=spf1 include:broken.example -all"]] });
      const spfLookup = async (name: string) => {
        if (name === "broken.example") throw new Error("SERVFAIL");
        return null;
      };
      const result = await checkDns("https://example.com", { spfLookup });
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.spf.lookupError).toBe(true);
      expect(result.spf.issues.some((i) => i.includes("could not be fully evaluated"))).toBe(true);
      expect(result.spf.issues.some((i) => i.includes("over the RFC 7208 limit"))).toBe(false);
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
      expect(result.dmarc.partialEnforcement).toBe(false);
      expect(result.dmarc.noReporting).toBe(false);
    });

    it("flags partial enforcement when an enforcing policy has pct<100", async () => {
      routeResolveTxt({ "_dmarc.example.com": [["v=DMARC1; p=quarantine; pct=50; rua=mailto:d@example.com"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.partialEnforcement).toBe(true);
      expect(result.dmarc.pct).toBe(50);
    });

    it("flags no reporting when an enforcing policy has no rua=", async () => {
      routeResolveTxt({ "_dmarc.example.com": [["v=DMARC1; p=reject"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.noReporting).toBe(true);
    });

    it("does not flag partial-enforcement or no-reporting on a p=none policy (covered by dmarc-none)", async () => {
      routeResolveTxt({ "_dmarc.example.com": [["v=DMARC1; p=none; pct=50"]] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dmarc.partialEnforcement).toBe(false);
      expect(result.dmarc.noReporting).toBe(false);
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
    it("reports signed when the parent zone publishes a DS record", async () => {
      stubDoh({ Status: 0, Answer: [{ type: 43, data: "2371 13 2 abc" }] });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dnssec.likelySigned).toBe(true);
    });

    it("reports unsigned (a real finding) on NOERROR with no DS answer", async () => {
      stubDoh({ Status: 0 });
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dnssec.likelySigned).toBe(false);
      expect(result.dnssec.inconclusive).toBeUndefined();
    });

    it.each([
      ["a resolver error status", () => stubDoh({ Status: 2 })],
      ["an HTTP failure", () => stubDoh({}, 503)],
      ["a network error", () => vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")))],
    ])("is inconclusive, not unsigned, on %s", async (_name, arrange) => {
      arrange();
      const result = await checkDns("https://example.com");
      if (result.status !== "checked") throw new Error("expected checked");
      expect(result.dnssec.inconclusive).toBe(true);
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
        vi.fn(async (url: string) =>
          url.includes("cloudflare-dns.com")
            ? new Response(JSON.stringify({ Status: 0 }))
            : new Response("version: STSv1\nmode: testing\nmx: mail.example.com\n", { status: 200 })
        )
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
