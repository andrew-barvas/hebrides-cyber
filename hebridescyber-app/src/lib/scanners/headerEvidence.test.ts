// Evidence on header findings (LAUNCH-PRIORITY.md item 3 / E-75 follow-up):
// checkHeaders() records the response it judged, and summariseResults()
// attaches it to every header finding except cookie flags.
import { describe, it, expect, vi, afterEach } from "vitest";
import { summariseResults, type ScanResults } from "./index";
import { checkHeaders } from "./headers";
import { REDACTED } from "../findingEvidence";

const err = { status: "error", note: "not run" } as const;

function results(headers: ScanResults["headers"]): ScanResults {
  return {
    target_url: "https://www.example.com",
    checked_at: "2026-10-31T00:00:00Z",
    tls: { ...err } as unknown as ScanResults["tls"],
    headers,
    dns: err as ScanResults["dns"],
    exposure: err as ScanResults["exposure"],
    directoryListing: { status: "error", listings: [], note: "x" } as unknown as ScanResults["directoryListing"],
    cloudMisconfig: { status: "error", publicBuckets: [], note: "x" } as unknown as ScanResults["cloudMisconfig"],
    fingerprint: err as ScanResults["fingerprint"],
    ports: err as ScanResults["ports"],
    playwright: err as ScanResults["playwright"],
    recon: err as ScanResults["recon"],
    webapp: err as ScanResults["webapp"],
    safeBrowsing: err as ScanResults["safeBrowsing"],
    waybackDiscovery: err as ScanResults["waybackDiscovery"],
    hibp: err as ScanResults["hibp"],
    wpVulnDb: err as unknown as ScanResults["wpVulnDb"],
    softwareCveDb: err as unknown as ScanResults["softwareCveDb"],
    businessLogic: err as ScanResults["businessLogic"],
    apiSpec: { status: "not_configured", findings: [], endpointsTested: 0, specSource: "none" } as unknown as ScanResults["apiSpec"],
    zap: { status: "not_configured", note: "x" } as ScanResults["zap"],
  };
}

function stubResponse(headers: Record<string, string>, url = "https://www.example.com/") {
  const res = new Response("<html>secret body</html>", { status: 200, headers });
  Object.defineProperty(res, "url", { value: url });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(res));
}

describe("header finding evidence", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("records the judged response, after redirects, with security headers and no body", async () => {
    stubResponse(
      {
        "content-type": "text/html",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "set-cookie": "sid=s3ss10nvalue; Path=/",
      },
      "https://www.example.com/home",
    );
    const result = await checkHeaders("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");

    expect(result.evidence?.request).toEqual({ method: "GET", url: "https://www.example.com/home" });
    expect(result.evidence?.response.headers).toMatchObject({
      "content-type": "text/html",
      "x-frame-options": "DENY",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
    });
    expect(result.evidence?.response.bodyExcerpt).toBeUndefined();
    expect(JSON.stringify(result.evidence)).not.toContain("s3ss10nvalue");
  });

  it("masks a key in a CSP report-uri but keeps the policy readable", async () => {
    stubResponse({ "content-security-policy": "default-src 'self'; report-uri https://o1.ingest.example.io/api/1/security/?sentry_key=abc123def" });
    const result = await checkHeaders("https://www.example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    const csp = result.evidence?.response.headers["content-security-policy"];
    expect(csp).toBe(`default-src 'self'; report-uri https://o1.ingest.example.io/api/1/security/?${REDACTED}`);
  });

  it("attaches the evidence to header findings but not to cookie-flag findings", async () => {
    stubResponse({ "access-control-allow-origin": "*", "set-cookie": "sid=s3ss10nvalue; Path=/", "x-powered-by": "PHP/8.1" });
    const headers = await checkHeaders("https://www.example.com");
    const findings = summariseResults(results(headers)).findings;

    const withEvidence = findings.filter((f) => f.checkId?.startsWith("headers.") && !f.checkId.startsWith("headers.cookie-flags"));
    expect(withEvidence.map((f) => f.checkId)).toEqual(
      expect.arrayContaining(["headers.missing-critical", "headers.cors-wildcard", "headers.info-disclosure"]),
    );
    for (const f of withEvidence) expect(f.evidence?.response.headers["access-control-allow-origin"]).toBe("*");

    const cookie = findings.find((f) => f.checkId === "headers.cookie-flags:sid");
    expect(cookie).toBeDefined();
    expect(cookie?.evidence).toBeUndefined();
  });

  it("leaves findings without evidence for scans stored before evidence existed", () => {
    const stored = {
      status: "checked",
      httpStatus: 200,
      owasp: { headers: [{ name: "strict-transport-security", present: false, value: null }], missingCount: 1, score: 0 },
      csp: { present: true, value: "x", issues: [], grade: "A" },
      cookies: [],
      cors: { wildcardOrigin: false, allowCredentialsWithWildcard: false, value: null, issues: [] },
      infoDisclosure: { serverHeader: null, poweredByHeader: null, generatorHeader: null, issues: [] },
      smugglingSurface: { contentLength: null, transferEncoding: null, issues: [] },
    } as unknown as ScanResults["headers"];
    const f = summariseResults(results(stored)).findings.find((x) => x.checkId === "headers.missing-critical");
    expect(f).toBeDefined();
    expect(f && "evidence" in f).toBe(false);
  });
});
