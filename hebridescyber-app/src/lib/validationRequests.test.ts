import { describe, it, expect } from "vitest";
import type { Finding } from "./scanners";
import { buildValidationSnapshot, operatorEmail } from "./validationRequests";
import { worthValidating } from "./validationEligibility";

const finding = (over: Partial<Finding> = {}): Finding => ({ checkId: "xss.reflected", severity: "high", title: "Reflected XSS", detail: "Parameter q is reflected", remediation: "Encode output", ...over }) as Finding;
const proven = { metadata: { proofOfExploit: { confirmed: true, evidence: "Payload ran at /search?q=1", validatedAt: "2026-11-01" } } };

describe("worthValidating", () => {
  it("offers it for critical and high findings, and for medium or lower ones only when shown to reproduce", () => {
    expect(worthValidating(finding({ severity: "critical" }))).toBe(true);
    expect(worthValidating(finding({ severity: "high" }))).toBe(true);
    expect(worthValidating(finding({ severity: "medium" }))).toBe(false);
    expect(worthValidating(finding({ severity: "medium", ...proven }))).toBe(true);
    expect(worthValidating(finding({ severity: "info" }))).toBe(false);
  });

  it("never offers it for a finding with no check id, which could not be addressed later", () => {
    expect(worthValidating(finding({ checkId: undefined, severity: "critical" }))).toBe(false);
  });
});

describe("buildValidationSnapshot", () => {
  it("keeps what the customer saw, including whether the scanner confirmed it", () => {
    const s = buildValidationSnapshot(finding({ cveIds: ["CVE-2025-1"], ...proven }));
    expect(s).toEqual({
      checkId: "xss.reflected",
      severity: "high",
      title: "Reflected XSS",
      detail: "Parameter q is reflected",
      cveIds: ["CVE-2025-1"],
      confirmedExploitable: true,
      evidence: "Payload ran at /search?q=1",
    });
  });

  it("marks an unconfirmed finding as such, with no evidence line", () => {
    expect(buildValidationSnapshot(finding())).toMatchObject({ confirmedExploitable: false, evidence: null, cveIds: [] });
  });

  it("bounds text so a huge finding cannot bloat the row or the email", () => {
    const s = buildValidationSnapshot(finding({ title: "t".repeat(2000), detail: "d".repeat(9000), cveIds: Array.from({ length: 50 }, (_, i) => `CVE-2025-${i}`) }));
    expect(s.title.length).toBeLessThanOrEqual(500);
    expect(s.detail.length).toBeLessThanOrEqual(1500);
    expect(s.cveIds).toHaveLength(20);
  });
});

describe("operatorEmail", () => {
  it("escapes everything a customer or a scan could control", () => {
    const snapshot = buildValidationSnapshot(finding({ title: "<script>alert(1)</script>", ...proven }));
    const mail = operatorEmail({ requesterEmail: "a@b.test", host: "example.com", snapshot, note: "<img src=x onerror=1>\nplease", requestId: "r-1" });
    expect(mail.html).not.toContain("<script>");
    expect(mail.html).not.toContain("<img");
    expect(mail.html).toContain("&lt;script&gt;");
    expect(mail.html).toContain("No testing has happened");
    expect(mail.subject).toBe("Validation request: high on example.com");
  });

  it("copes with no requester email and no note", () => {
    const mail = operatorEmail({ requesterEmail: null, host: "example.com", snapshot: buildValidationSnapshot(finding()), note: null, requestId: "r-1" });
    expect(mail.html).toContain("unknown");
    expect(mail.html).not.toContain("Their note");
  });
});
