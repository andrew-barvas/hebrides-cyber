import { describe, it, expect } from "vitest";
import { buildRemediationPack } from "./remediation";
import type { Finding } from "./scanners";

function finding(partial: Partial<Finding> & Pick<Finding, "severity" | "title">): Finding {
  return { detail: "d", ...partial } as Finding;
}

describe("buildRemediationPack", () => {
  it("drops informational findings entirely", () => {
    const md = buildRemediationPack("https://example.com", [finding({ severity: "info", title: "FYI", checkId: "recon.subdomains-found" })], null);
    expect(md).not.toContain("FYI");
    expect(md).toContain("No actionable findings");
  });

  it("groups findings by the checkId's module prefix, under a human-readable label", () => {
    const md = buildRemediationPack(
      "https://example.com",
      [
        finding({ severity: "high", title: "Missing CSP", checkId: "headers.csp" }),
        finding({ severity: "medium", title: "No MX record", checkId: "dns.mx" }),
      ],
      null
    );
    expect(md).toContain("## Headers");
    expect(md).toContain("## DNS / email");
  });

  it("falls back to a humanised raw prefix for an unlisted category, and 'Other' with no checkId at all", () => {
    const md = buildRemediationPack(
      "https://example.com",
      [finding({ severity: "low", title: "Something new", checkId: "brand-new-scanner.thing" }), finding({ severity: "low", title: "Legacy row" })],
      null
    );
    expect(md).toContain("## Brand new scanner");
    expect(md).toContain("## Other");
  });

  it("orders categories by their most severe finding, most urgent first", () => {
    const md = buildRemediationPack(
      "https://example.com",
      [
        finding({ severity: "low", title: "Minor DNS thing", checkId: "dns.minor" }),
        finding({ severity: "critical", title: "Exposed .env", checkId: "exposure.env" }),
      ],
      null
    );
    expect(md.indexOf("## Exposed files")).toBeLessThan(md.indexOf("## DNS / email"));
  });

  it("sorts findings within a category by severity, most severe first", () => {
    const md = buildRemediationPack(
      "https://example.com",
      [
        finding({ severity: "low", title: "Weak cipher", checkId: "tls.weak-cipher" }),
        finding({ severity: "critical", title: "Expired cert", checkId: "tls.expired" }),
      ],
      null
    );
    expect(md.indexOf("[CRITICAL] Expired cert")).toBeLessThan(md.indexOf("[LOW] Weak cipher"));
  });

  it("reuses a finding's own remediation text when present", () => {
    const md = buildRemediationPack(
      "https://example.com",
      [finding({ severity: "high", title: "Something", checkId: "exposure.env", remediation: "Rotate every secret immediately." })],
      null
    );
    expect(md).toContain("Rotate every secret immediately.");
  });

  it("includes the target, timestamp and score when given one, and omits the score line otherwise", () => {
    const withScore = buildRemediationPack("https://example.com", [], 72);
    expect(withScore).toContain("**Target:** https://example.com");
    expect(withScore).toContain("**Score at time of scan:** 72/100");

    const withoutScore = buildRemediationPack("https://example.com", [], null);
    expect(withoutScore).not.toContain("Score at time of scan");
  });
});
