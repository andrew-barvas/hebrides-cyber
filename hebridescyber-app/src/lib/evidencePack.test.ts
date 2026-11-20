import { describe, expect, it } from "vitest";
import type { FindingRow } from "./findingsView";
import { ceReadinessFromRows, insuranceAnswers, renderEvidencePackHtml, type EvidenceInputs } from "./evidencePack";

const row = (checkId: string, over: Partial<FindingRow> = {}): FindingRow =>
  ({ key: `a.example ${checkId}`, host: "a.example", checkId, checkBase: checkId.split(":")[0], category: checkId.split(".")[0], severity: "high", title: checkId, detail: null, knownExploited: false, triage: null, ...over }) as unknown as FindingRow;

const base: EvidenceInputs = { rows: [], scannedSites: [{ host: "a.example", lastScanAt: "2026-11-19T00:00:00Z" }], m365Checked: null, workspaceChecked: null, answers: [] };
const byId = (input: EvidenceInputs) => Object.fromEntries(insuranceAnswers(input).map((a) => [a.id, a]));

describe("insuranceAnswers", () => {
  it("evidences what a clean scan shows, and never claims what it can't see", () => {
    const a = byId(base);
    expect(a.email_spoofing.source).toBe("evidenced");
    expect(a.remote_access.source).toBe("evidenced");
    expect(a.encryption.source).toBe("evidenced");
    expect(a.patching.source).toBe("evidenced");
    expect(a.mfa_email.source).toBe("not_evidenced");
    expect(a.backups.source).toBe("not_evidenced");
    expect(a.breached_credentials).toBeUndefined();
  });

  it("with no scan at all, nothing is evidenced", () => {
    const a = byId({ ...base, scannedSites: [] });
    expect(Object.values(a).every((x) => x.source !== "evidenced")).toBe(true);
  });

  it("reports gaps from open findings, naming them", () => {
    const a = byId({
      ...base,
      rows: [row("dns.dmarc-missing"), row("network-exposure.open-port:3389"), row("eol.unsupported", { knownExploited: true, title: "PHP 7.4" }), row("tls.cert-expired"), row("hibp.domain-breach:Canva"), row("m365.mfaNotEnforcedAllUsers")],
      m365Checked: "2026-11-18T00:00:00Z",
    });
    expect(a.email_spoofing).toMatchObject({ source: "gap" });
    expect(a.remote_access.detail[0]).toContain("network-exposure.open-port:3389");
    expect(a.patching.answer).toBe("No: actively exploited vulnerabilities are unpatched");
    expect(a.patching.detail[0]).toBe("PHP 7.4 (a.example)");
    expect(a.encryption.source).toBe("gap");
    expect(a.breached_credentials.source).toBe("gap");
    expect(a.mfa_email.source).toBe("gap");
  });

  it("evidences MFA only from a checked tenant, otherwise uses the self-assessment", () => {
    expect(byId({ ...base, workspaceChecked: "2026-11-18T09:00:00Z" }).mfa_email).toMatchObject({ source: "evidenced", answer: "Yes" });
    expect(byId({ ...base, answers: [{ questionKey: "user-access.mfa", answer: "partial" }] }).mfa_email).toMatchObject({ source: "declared", answer: "Partly (self-declared)" });
    expect(byId({ ...base, answers: [{ questionKey: "malware.protection", answer: "yes" }] }).endpoint_protection).toMatchObject({ source: "declared", answer: "Yes (self-declared)" });
  });

  it("an open port that isn't remote access isn't counted", () => {
    expect(byId({ ...base, rows: [row("network-exposure.open-port:8080")] }).remote_access.source).toBe("evidenced");
  });
});

describe("renderEvidencePackHtml", () => {
  it("escapes everything and labels each answer's source", () => {
    const html = renderEvidencePackHtml({
      company: "Acme <Ltd>",
      generatedAt: "2026-11-20T10:00:00Z",
      sites: base.scannedSites,
      ce: ceReadinessFromRows([row("dns.spf-missing")], [{ questionKey: "firewalls.host", answer: "yes" }]),
      insurance: insuranceAnswers({ ...base, rows: [row("dns.spf-missing", { title: "No SPF <record>" })] }),
      fixFirst: [],
    });
    expect(html).toContain("Acme &lt;Ltd&gt;");
    expect(html).toContain("No SPF &lt;record&gt; (a.example)");
    expect(html).not.toContain("<record>");
    expect(html).toContain("Gap found");
    expect(html).toContain("Your records");
    expect(html).toContain("not a certification");
    expect(html).toContain("Yes (self-declared)");
  });
});
