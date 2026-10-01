// summariseResults() for the dangling-DNS and domain-registration checks:
// the result → finding mapping, including every "report nothing" path.
import { describe, it, expect } from "vitest";
import { summariseResults, type ScanResults } from "./index";
import type { DomainRegistrationResult } from "./domainRegistration";
import type { TakeoverResult } from "./takeover";
import { getComplianceRefs } from "./compliance";

const err = { status: "error", note: "not run" } as const;

function results(extra: Partial<ScanResults>): ScanResults {
  return {
    target_url: "https://www.example.com",
    checked_at: "2026-09-27T00:00:00Z",
    tls: { ...err } as unknown as ScanResults["tls"],
    headers: err as ScanResults["headers"],
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
    ...extra,
  };
}

function registration(overrides: Partial<Extract<DomainRegistrationResult, { status: "checked" }>>): DomainRegistrationResult {
  return {
    status: "checked",
    domain: "example.com",
    expiresAt: "2027-06-01T00:00:00.000Z",
    daysUntilExpiry: 247,
    registrar: "Example Registrar Ltd",
    statuses: ["client transfer prohibited"],
    transferLocked: true,
    ...overrides,
  };
}

const ids = (r: ScanResults) => summariseResults(r).findings.map((f) => f.checkId);

describe("dangling DNS findings", () => {
  const takeover: TakeoverResult = {
    status: "checked",
    hostsChecked: 3,
    dangling: [
      { host: "old.example.com", cname: "oldapp.azurewebsites.net", provider: "Azure App Service", confidence: "high", evidence: "oldapp.azurewebsites.net does not exist (NXDOMAIN)" },
      { host: "shop.example.com", cname: "acme.myshopify.com", provider: "Shopify", confidence: "medium", evidence: "x" },
    ],
  };

  it("reports one finding per dangling host, severity by confidence, with evidence and a fix", () => {
    const findings = summariseResults(results({ takeover })).findings;
    const [azure, shopify] = findings;
    expect(azure).toMatchObject({
      checkId: "takeover.dangling-cname:old.example.com",
      severity: "high",
      title: "Dangling DNS record: old.example.com points to an unclaimed Azure App Service resource",
    });
    expect(azure.detail).toContain("NXDOMAIN");
    expect(azure.remediation).toContain("oldapp");
    expect(azure.complianceRefs).toEqual(getComplianceRefs("takeover.dangling-cname:x"));
    expect(shopify.severity).toBe("medium");
  });

  it("reports nothing when the check didn't complete, or for scans stored before it existed", () => {
    expect(ids(results({ takeover: { status: "error", note: "x" } }))).toEqual(["meta.no-issues"]);
    expect(ids(results({}))).toEqual(["meta.no-issues"]);
  });
});

describe("domain registration findings", () => {
  it("says nothing about a healthy, locked domain", () => {
    expect(ids(results({ domainRegistration: registration({}) }))).toEqual(["meta.no-issues"]);
  });

  it.each([
    [29, "medium"],
    [14, "high"],
    [0, "high"],
  ] as const)("flags expiry in %i days as %s", (days, severity) => {
    const [f] = summariseResults(results({ domainRegistration: registration({ daysUntilExpiry: days }) })).findings;
    expect(f).toMatchObject({ checkId: "domain.expiring", severity });
    expect(f.detail).toContain("Example Registrar Ltd");
  });

  it("flags an expired registration separately", () => {
    expect(ids(results({ domainRegistration: registration({ daysUntilExpiry: -3 }) }))).toEqual(["domain.expired"]);
  });

  it("flags a missing transfer lock only when the registry says so (false, not null)", () => {
    expect(ids(results({ domainRegistration: registration({ transferLocked: false, statuses: ["active"] }) }))).toEqual(["domain.transfer-lock-missing"]);
    expect(ids(results({ domainRegistration: registration({ transferLocked: null, statuses: [] }) }))).toEqual(["meta.no-issues"]);
  });

  it("says nothing when the expiry date is unknown", () => {
    expect(ids(results({ domainRegistration: registration({ daysUntilExpiry: null, expiresAt: null }) }))).toEqual(["meta.no-issues"]);
  });
});

describe("end-of-life findings", () => {
  const item = {
    tech: "PHP",
    label: "PHP",
    product: "php",
    kind: "platform" as const,
    version: "7.4.33",
    packagedBy: null,
    state: "unsupported" as const,
    cycle: "7.4",
    eolDate: "2022-11-28",
    daysOverdue: 1417,
  };
  const fingerprint = {
    status: "checked",
    technologies: [],
    riskySoftware: [{ name: "PHP", version: "7.4.33", reason: "PHP < 8.0 is end-of-life with no security patches" }],
  } as ScanResults["fingerprint"];

  it("reports unsupported software against Cyber Essentials patching, keyed by product", () => {
    const [f] = summariseResults(results({ endOfLife: { status: "checked", items: [item], evaluated: ["PHP"] } })).findings;
    expect(f).toMatchObject({ checkId: "eol.unsupported:php", severity: "high", title: "End-of-life software: PHP 7.4.33" });
    expect(f.detail).toContain("reached end of life on 2022-11-28 (1417 days ago)");
    expect(f.remediation).toContain("https://endoflife.date/php");
    expect(getComplianceRefs("eol.unsupported:php").map((r) => r.control)).toContain("Security update management");
  });

  it("downgrades and explains a distribution package", () => {
    const [f] = summariseResults(results({ endOfLife: { status: "checked", items: [{ ...item, packagedBy: "Ubuntu" }], evaluated: ["PHP"] } })).findings;
    expect(f.severity).toBe("low");
    expect(f.detail).toContain("probably a distribution package");
    expect(f.remediation).toContain("Ubuntu");
  });

  it("gives an informational heads-up before the date, with no compliance gap", () => {
    const approaching = { ...item, version: "8.2.20", state: "approaching" as const, cycle: "8.2", eolDate: "2026-12-31", daysLeft: 77 };
    const [f] = summariseResults(results({ endOfLife: { status: "checked", items: [approaching], evaluated: ["PHP"] } })).findings;
    expect(f).toMatchObject({ checkId: "eol.approaching:php", severity: "info", title: "PHP 8.2 reaches end of life on 2026-12-31" });
    expect(getComplianceRefs("eol.approaching:php")).toEqual([]);
  });

  it("replaces the hand-kept outdated-library finding once EOL data reached a verdict", () => {
    const withEol = ids(results({ fingerprint, endOfLife: { status: "checked", items: [item], evaluated: ["PHP"] } }));
    expect(withEol).toContain("eol.unsupported:php");
    expect(withEol).not.toContain("fingerprint.risky-library:PHP");
  });

  it("keeps the outdated-library finding when the EOL lookup failed", () => {
    expect(ids(results({ fingerprint, endOfLife: { status: "error", note: "endoflife.date lookup failed for: php" } }))).toContain(
      "fingerprint.risky-library:PHP"
    );
  });
});

describe("certificate trust findings", () => {
  const tls = (overrides: Record<string, unknown>) =>
    ({
      status: "checked",
      isHttps: true,
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      cipherBits: null,
      certificateExpiresAt: "Dec  1 00:00:00 2026 GMT",
      certificateIssuedAt: "Sep  1 00:00:00 2026 GMT",
      daysUntilExpiry: 60,
      daysOld: 30,
      subject: "example.com",
      issuer: "Let's Encrypt",
      subjectAltNames: ["example.com"],
      selfSigned: false,
      weakProtocol: false,
      weakCipher: false,
      hsts: { present: true, maxAge: 31536000, includeSubDomains: true, preload: false, adequate: true },
      trustProblem: null,
      trustErrorCode: null,
      ...overrides,
    }) as unknown as ScanResults["tls"];

  it.each([
    [{ trustProblem: "expired", daysUntilExpiry: -3 }, "tls.cert-expired", "critical"],
    [{ trustProblem: "hostname-mismatch", subjectAltNames: ["other.com"] }, "tls.cert-name-mismatch", "critical"],
    [{ trustProblem: "incomplete-chain" }, "tls.cert-chain-incomplete", "medium"],
    [{ trustProblem: "untrusted", trustErrorCode: "SELF_SIGNED_CERT_IN_CHAIN" }, "tls.cert-untrusted", "high"],
    [{ trustProblem: "self-signed", selfSigned: true }, "tls.self-signed", "high"],
  ])("reports %o as %s", (overrides, checkId, severity) => {
    const tlsFindings = summariseResults(results({ tls: tls(overrides) })).findings.filter((f) => f.checkId?.startsWith("tls."));
    expect(tlsFindings).toEqual([expect.objectContaining({ checkId, severity })]);
    expect(getComplianceRefs(checkId).length).toBeGreaterThan(0);
  });

  it("calls an expired certificate expired, not 'expiring soon'", () => {
    const found = ids(results({ tls: tls({ daysUntilExpiry: -1 }) }));
    expect(found).toContain("tls.cert-expired");
    expect(found).not.toContain("tls.cert-expiring");
  });

  it("still reads results stored before trust problems were recorded", () => {
    expect(ids(results({ tls: tls({ trustProblem: undefined, trustErrorCode: undefined, daysUntilExpiry: 10 }) }))).toContain("tls.cert-expiring");
  });
});

describe("subdomain certificate findings", () => {
  const issue = { certName: "*.example.com", hosts: ["a.example.com", "b.example.com"], validTo: "Sep 20 00:00:00 2026 GMT", issuer: "Let's Encrypt" };

  it("reports an expired certificate once, keyed by its name, naming every host", () => {
    const [f] = summariseResults(
      results({ subdomainCerts: { status: "checked", hostsChecked: 5, hostsAnswering: 4, issues: [{ ...issue, state: "expired", daysUntilExpiry: -11 }] } })
    ).findings;
    expect(f).toMatchObject({ checkId: "subdomain-certs.expired:*.example.com", severity: "medium", title: "Expired certificate on subdomains: a.example.com (+1)" });
    expect(f.detail).toContain("a.example.com, b.example.com");
    expect(f.detail).toContain("11 days ago");
  });

  it("raises an expiring certificate to medium in its last week", () => {
    const sev = (days: number) =>
      summariseResults(results({ subdomainCerts: { status: "checked", hostsChecked: 1, hostsAnswering: 1, issues: [{ ...issue, state: "expiring", daysUntilExpiry: days }] } }))
        .findings[0].severity;
    expect(sev(5)).toBe("medium");
    expect(sev(15)).toBe("low");
  });
});
