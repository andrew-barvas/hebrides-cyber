import { describe, it, expect } from "vitest";
import type { Finding } from "./index";
import { applyPlatformGuides, mailProviderFromMx } from "./platformGuides";

const f = (checkId: string, remediation?: string): Finding => ({ checkId, severity: "medium", title: "t", detail: "d", remediation });

describe("mailProviderFromMx", () => {
  it("recognises Microsoft 365 and Google Workspace, and nothing else", () => {
    expect(mailProviderFromMx(["contoso-com.mail.protection.outlook.com."])).toBe("microsoft365");
    expect(mailProviderFromMx(["aspmx.l.google.com", "alt1.aspmx.l.google.com"])).toBe("google");
    expect(mailProviderFromMx(["smtp.google.com"])).toBe("google");
    expect(mailProviderFromMx(["mx1.ionos.co.uk"])).toBeNull();
    expect(mailProviderFromMx([])).toBeNull();
  });
});

describe("applyPlatformGuides", () => {
  it("tells a Shopify, Wix or Squarespace customer that header findings can't be fixed from their account", () => {
    for (const platform of ["Shopify", "Wix", "Squarespace"]) {
      const findings = [f("headers.csp-absent", "Add a policy."), f("tls.hsts-missing")];
      applyPlatformGuides(findings, { technologies: [platform], mailProvider: null });
      expect(findings[0].remediation).toContain("Add a policy.");
      expect(findings[0].remediation).toContain(`**On ${platform}:**`);
      expect(findings[0].remediation).toContain("can't fix this from your account");
      expect(findings[1].remediation).toContain(`**On ${platform}:**`);
    }
  });

  it("gives Cloudflare steps for headers, HSTS and the TLS version", () => {
    const findings = [f("headers.missing-critical"), f("tls.hsts-short"), f("tls.weak-protocol")];
    applyPlatformGuides(findings, { technologies: ["Cloudflare", "Nginx"], mailProvider: null });
    expect(findings[0].remediation).toContain("Transform Rules");
    expect(findings[1].remediation).toContain("Edge Certificates → HTTP Strict Transport Security");
    expect(findings[2].remediation).toContain("Minimum TLS Version");
  });

  it("prefers the hosted platform's answer over Cloudflare when both are detected", () => {
    const [finding] = [f("headers.csp-absent")];
    applyPlatformGuides([finding], { technologies: ["Cloudflare", "Shopify"], mailProvider: null });
    expect(finding.remediation).toContain("**On Shopify:**");
    expect(finding.remediation).not.toContain("Cloudflare");
  });

  it("gives provider-specific SPF and DKIM steps", () => {
    const ms = [f("dns.spf-missing"), f("dns.dkim-not-detected")];
    applyPlatformGuides(ms, { technologies: [], mailProvider: "microsoft365" });
    expect(ms[0].remediation).toContain("include:spf.protection.outlook.com");
    expect(ms[1].remediation).toContain("selector1 and selector2");
    const g = [f("dns.spf-issues"), f("dns.dkim-issues")];
    applyPlatformGuides(g, { technologies: [], mailProvider: "google" });
    expect(g[0].remediation).toContain("include:_spf.google.com");
    expect(g[1].remediation).toContain("google._domainkey");
  });

  it("adds nothing when nothing relevant was detected, and never touches severity or title", () => {
    const findings = [f("headers.csp-absent", "Add a policy."), f("dns.spf-missing", "Add SPF."), f("exposure.env-file", "Remove it.")];
    applyPlatformGuides(findings, { technologies: ["Nginx"], mailProvider: null });
    expect(findings.map((x) => x.remediation)).toEqual(["Add a policy.", "Add SPF.", "Remove it."]);
    applyPlatformGuides(findings, { technologies: ["Shopify"], mailProvider: "google" });
    expect(findings[2].remediation).toBe("Remove it.");
    expect(findings.every((x) => x.severity === "medium" && x.title === "t")).toBe(true);
  });
});
