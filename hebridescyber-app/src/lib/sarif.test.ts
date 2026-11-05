import { describe, it, expect } from "vitest";
import { buildSarif, repoRelativePath, ruleIdOf, securitySeverityOf, MAX_SARIF_RESULTS, SARIF_SCHEMA, type SarifFinding } from "./sarif";

const TARGET = "https://www.example.com";
const SCAN = "scan-1";

const finding = (over: Partial<SarifFinding> = {}): SarifFinding => ({
  severity: "medium",
  title: "Missing recommended headers (2)",
  detail: "referrer-policy, permissions-policy",
  checkId: "headers.missing-recommended",
  ...over,
});

const build = (findings: SarifFinding[], extra: Partial<Parameters<typeof buildSarif>[0]> = {}) =>
  buildSarif({ targetUrl: TARGET, scanId: SCAN, findings, siteUrl: "https://www.hebridescyber.co.uk", ...extra });

const run = (findings: SarifFinding[]) => build(findings).runs[0];

describe("buildSarif: the log", () => {
  it("is a SARIF 2.1.0 log with one run that names the tool", () => {
    const log = build([finding()]);
    expect(log.$schema).toBe(SARIF_SCHEMA);
    expect(log.version).toBe("2.1.0");
    expect(log.runs).toHaveLength(1);
    expect(log.runs[0].tool.driver).toMatchObject({ name: "Hebrides Cyber", informationUri: "https://www.hebridescyber.co.uk" });
  });

  it("is a valid, empty run when there are no findings", () => {
    const r = run([]);
    expect(r.results).toEqual([]);
    expect(r.tool.driver.rules).toEqual([]);
  });

  it("keeps different sites apart by category, so one repository can upload several", () => {
    expect(run([finding()]).automationDetails?.id).toBe("hebridescyber/www.example.com/");
    expect(buildSarif({ targetUrl: "not a url", scanId: SCAN, findings: [] }).runs[0].automationDetails?.id).toBe("hebridescyber/unknown/");
  });

  it("is the same bytes however the findings arrive, so two exports of one scan match", () => {
    const a = finding({ severity: "high", checkId: "tls.weak", title: "Weak TLS" });
    const b = finding({ severity: "low", checkId: "dns.spf", title: "SPF" });
    const c = finding({ severity: "high", checkId: "cookie.flags:session", title: "Cookie" });
    expect(JSON.stringify(build([a, b, c]))).toBe(JSON.stringify(build([c, b, a])));
  });

  it("does not change the findings it is given", () => {
    const input = [finding({ severity: "low", checkId: "b" }), finding({ severity: "high", checkId: "a" })];
    const before = JSON.stringify(input);
    build(input);
    expect(JSON.stringify(input)).toBe(before);
  });
});

describe("rules and results", () => {
  it("makes one rule per check and one result per finding, keyed by the checkId's base", () => {
    const r = run([
      finding({ checkId: "headers.cookie-flags:session", title: "Cookie session" }),
      finding({ checkId: "headers.cookie-flags:csrf", title: "Cookie csrf" }),
      finding({ checkId: "tls.weak", title: "Weak TLS" }),
    ]);
    expect(r.tool.driver.rules?.map((x) => x.id).sort()).toEqual(["headers.cookie-flags", "tls.weak"]);
    expect(r.results).toHaveLength(3);
    const idx = new Map(r.tool.driver.rules?.map((x, i) => [x.id, i]));
    for (const res of r.results ?? []) expect(res.ruleIndex).toBe(idx.get(res.ruleId as string));
  });

  it("uses the full checkId as the result's fingerprint, so GitHub follows one alert across uploads", () => {
    const r = run([finding({ checkId: "headers.cookie-flags:session" })]);
    expect(r.results?.[0].partialFingerprints).toEqual({ "hebridesCheckId/v1": "headers.cookie-flags:session" });
  });

  it("gives a finding stored before checkIds existed a stable stand-in rule and fingerprint", () => {
    const old = finding({ checkId: undefined, title: "Missing HSTS header!" });
    expect(ruleIdOf(old)).toBe("legacy.missing-hsts-header");
    const res = run([old]).results?.[0];
    expect(res?.ruleId).toBe("legacy.missing-hsts-header");
    expect(res?.partialFingerprints).toEqual({ "hebridesCheckId/v1": "legacy:missing-hsts-header" });
  });

  it("puts the remediation on the rule as help, and omits help when there is none", () => {
    const withFix = run([finding({ remediation: "Add the header in next.config." })]).tool.driver.rules?.[0];
    expect(withFix?.help).toEqual({ text: "Add the header in next.config.", markdown: "Add the header in next.config." });
    expect(run([finding()]).tool.driver.rules?.[0].help).toBeUndefined();
  });

  it("tags a rule with the frameworks its findings map to", () => {
    const f = finding({ complianceRefs: [{ framework: "owasp-top-10", control: "A05" }, { framework: "cyber-essentials", control: "Secure configuration" }, { framework: "owasp-top-10", control: "A02" }] });
    expect(run([f]).tool.driver.rules?.[0].properties?.tags).toEqual(["security", "owasp-top-10", "cyber-essentials"]);
  });
});

describe("severity", () => {
  it.each([
    ["critical", "error"],
    ["high", "error"],
    ["medium", "warning"],
    ["low", "note"],
    ["info", "note"],
  ] as const)("maps %s to level %s", (severity, level) => {
    const res = run([finding({ severity, checkId: `x.${severity}` })]).results?.[0];
    expect(res?.level).toBe(level);
  });

  it("uses a finding's CVSS score for GitHub's security-severity, else a default for its severity, else none", () => {
    expect(securitySeverityOf(finding({ severity: "medium", cvssScore: 9.8 }))).toBe(9.8);
    expect(securitySeverityOf(finding({ severity: "critical" }))).toBe(9.5);
    expect(securitySeverityOf(finding({ severity: "high" }))).toBe(8);
    expect(securitySeverityOf(finding({ severity: "medium" }))).toBe(5.5);
    expect(securitySeverityOf(finding({ severity: "low" }))).toBe(2);
    expect(securitySeverityOf(finding({ severity: "info" }))).toBeNull();
    // A nonsense score is ignored, not trusted.
    expect(securitySeverityOf(finding({ severity: "high", cvssScore: 42 }))).toBe(8);
    expect(securitySeverityOf(finding({ severity: "high", cvssScore: Number.NaN }))).toBe(8);
  });

  it("gives a rule the highest security-severity among its findings, as a string, and none for info", () => {
    const rules = run([
      finding({ checkId: "a.check:1", severity: "low" }),
      finding({ checkId: "a.check:2", severity: "critical" }),
      finding({ checkId: "b.info", severity: "info" }),
    ]).tool.driver.rules;
    expect(rules?.find((r) => r.id === "a.check")?.properties?.["security-severity"]).toBe("9.5");
    expect(rules?.find((r) => r.id === "b.info")?.properties?.["security-severity"]).toBeUndefined();
  });

  it("orders results most severe first", () => {
    const order = run([finding({ severity: "low", checkId: "l" }), finding({ severity: "critical", checkId: "c" }), finding({ severity: "medium", checkId: "m" })]).results?.map((r) => r.level);
    expect(order).toEqual(["error", "warning", "note"]);
  });
});

describe("locations", () => {
  const loc = (f: SarifFinding) => run([f]).results?.[0].locations?.[0].physicalLocation;

  it("anchors a code finding at its file and line, relative to the repository root", () => {
    expect(loc(finding({ metadata: { file: "src/app/page.tsx", line: 42 } }))).toEqual({
      artifactLocation: { uri: "src/app/page.tsx", uriBaseId: "%SRCROOT%" },
      region: { startLine: 42 },
    });
  });

  it("falls back to line 1 when the line is missing, zero or not a number", () => {
    for (const line of [undefined, 0, -3, Number.NaN, "7"]) {
      expect(loc(finding({ metadata: { file: "a.ts", line } }))?.region).toEqual({ startLine: 1 });
    }
  });

  it("locates a finding with no file at the scanned URL", () => {
    expect(loc(finding())).toEqual({ artifactLocation: { uri: TARGET } });
    expect(loc(finding({ metadata: { proofOfExploit: { confirmed: true } } }))).toEqual({ artifactLocation: { uri: TARGET } });
  });

  it("does not trust a path that is not plainly inside the repository", () => {
    for (const file of ["/etc/passwd", "../outside.ts", "a/../../b.ts", "C:\\Windows\\x.dll", "https://evil.example/x", "file:///x", "", "   ", "a//b.ts", "./", 7, null]) {
      expect(loc(finding({ metadata: { file, line: 3 } })), String(file)).toEqual({ artifactLocation: { uri: TARGET } });
    }
  });

  it("normalises a Windows separator and a leading ./, and percent-encodes what a URI must", () => {
    expect(repoRelativePath("src\\lib\\a b#1.ts")).toBe("src/lib/a%20b%231.ts");
    expect(repoRelativePath("./docs/readme.md")).toBe("docs/readme.md");
  });
});

describe("triage", () => {
  it("leaves out false positives entirely", () => {
    const r = run([finding({ checkId: "a.real" }), finding({ checkId: "a.fp", triage: { state: "false_positive", reason: "scanner noise", expiresAt: null, triagedAt: "2026-10-30T00:00:00.000Z" } })]);
    expect(r.results?.map((x) => x.ruleId)).toEqual(["a.real"]);
    expect(r.tool.driver.rules?.map((x) => x.id)).toEqual(["a.real"]);
  });

  it("keeps an accepted risk, as a suppression that carries the owner's reason", () => {
    const res = run([finding({ triage: { state: "accepted_risk", reason: "Internal tool, behind VPN", expiresAt: null, triagedAt: "2026-10-30T00:00:00.000Z" } })]).results?.[0];
    expect(res?.suppressions).toEqual([{ kind: "external", status: "accepted", justification: "Internal tool, behind VPN" }]);
    expect(res?.properties?.triage).toMatchObject({ state: "accepted_risk" });
  });

  it("says when a snooze ends", () => {
    const res = run([finding({ triage: { state: "snoozed", reason: "Fix scheduled", expiresAt: "2026-12-01T00:00:00.000Z", triagedAt: "2026-10-30T00:00:00.000Z" } })]).results?.[0];
    expect(res?.suppressions?.[0].justification).toBe("Fix scheduled (snoozed until 2026-12-01)");
  });

  it("adds no suppression to an untriaged finding", () => {
    expect(run([finding({ triage: null })]).results?.[0].suppressions).toBeUndefined();
    expect(run([finding()]).results?.[0].suppressions).toBeUndefined();
  });
});

describe("what a result carries", () => {
  it("marks a confirmed-exploitable finding, and carries threat intelligence, CVEs and compliance refs", () => {
    const res = run([
      finding({
        cveIds: ["CVE-2026-0001"],
        cvssScore: 8.1,
        threatIntel: { knownExploited: true, epss: 0.42 },
        complianceRefs: [{ framework: "pci-dss", control: "6.4" }],
        fixDifficulty: "easy",
        metadata: { proofOfExploit: { confirmed: true, evidence: "reproduced" } },
        corroboratedBy: [{ tool: "nuclei", checkId: "n.x", title: "Same issue" }],
      }),
    ]).results?.[0].properties;
    expect(res).toMatchObject({
      severity: "medium",
      checkId: "headers.missing-recommended",
      confirmedExploitable: true,
      knownExploited: true,
      epss: 0.42,
      cvssScore: 8.1,
      cveIds: ["CVE-2026-0001"],
      complianceRefs: ["pci-dss: 6.4"],
      fixDifficulty: "easy",
      corroboratedBy: ["nuclei: Same issue"],
    });
  });

  it("does not claim confirmation or exploitation it has no record of", () => {
    const props = run([finding()]).results?.[0].properties;
    expect(props).not.toHaveProperty("confirmedExploitable");
    expect(props).not.toHaveProperty("knownExploited");
  });

  it("writes a message from the title and detail, collapsing whitespace and capping the length", () => {
    expect(run([finding({ title: "T", detail: "line one\n\n  line   two" })]).results?.[0].message.text).toBe("T: line one line two");
    expect(run([finding({ title: "T", detail: "" })]).results?.[0].message.text).toBe("T");
    const long = run([finding({ detail: "x".repeat(5000) })]).results?.[0].message.text ?? "";
    expect(long).toHaveLength(1000);
    expect(long.endsWith("…")).toBe(true);
  });
});

describe("limits", () => {
  it("keeps the most severe results past GitHub's per-run limit, and says how many were left out", () => {
    const many: SarifFinding[] = [
      ...Array.from({ length: MAX_SARIF_RESULTS }, (_, i) => finding({ severity: "low", checkId: `low.check:${String(i).padStart(5, "0")}` })),
      finding({ severity: "critical", checkId: "crit.one" }),
      finding({ severity: "critical", checkId: "crit.two" }),
    ];
    const r = run(many);
    expect(r.results).toHaveLength(MAX_SARIF_RESULTS);
    expect(r.results?.slice(0, 2).map((x) => x.ruleId)).toEqual(["crit.one", "crit.two"]);
    expect(r.properties).toMatchObject({ findingCount: MAX_SARIF_RESULTS, omittedResults: 2 });
  });

  it("reports no omission when everything fits", () => {
    expect(run([finding()]).properties).not.toHaveProperty("omittedResults");
  });
});

describe("ruleIdOf", () => {
  it("is the part of the checkId before the first colon", () => {
    expect(ruleIdOf(finding({ checkId: "a.b:c:d" }))).toBe("a.b");
    expect(ruleIdOf(finding({ checkId: "a.b" }))).toBe("a.b");
  });
});
