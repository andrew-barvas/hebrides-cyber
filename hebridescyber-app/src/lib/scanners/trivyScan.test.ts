import { describe, it, expect } from "vitest";
import { buildTrivyImageFindings, buildTrivyConfigFindings } from "./trivyScan";

describe("buildTrivyImageFindings", () => {
  it("returns an empty array when there are no results", () => {
    expect(buildTrivyImageFindings({}, "node:20-alpine")).toEqual([]);
  });

  it("builds one Finding per vulnerability, with a stable checkId keyed on CVE + package", () => {
    const report = {
      Results: [
        {
          Target: "node:20-alpine (alpine 3.19.1)",
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2024-1234",
              PkgName: "openssl",
              InstalledVersion: "3.1.4-r0",
              FixedVersion: "3.1.5-r0",
              Severity: "HIGH",
              Title: "openssl: some real vulnerability",
            },
          ],
        },
      ],
    };

    const findings = buildTrivyImageFindings(report, "node:20-alpine");

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "trivy-image.vulnerable-package:CVE-2024-1234:openssl",
      severity: "high",
      cveIds: ["CVE-2024-1234"],
    });
    expect(findings[0].title).toContain("CVE-2024-1234");
    expect(findings[0].title).toContain("openssl");
    expect(findings[0].detail).toContain("node:20-alpine");
    expect(findings[0].remediation).toContain("openssl 3.1.5-r0");
  });

  it("does not populate cveIds for a non-CVE vulnerability id (e.g. a distro-specific advisory id)", () => {
    const report = {
      Results: [
        { Vulnerabilities: [{ VulnerabilityID: "GHSA-xxxx-yyyy-zzzz", PkgName: "foo", Severity: "MEDIUM" }] },
      ],
    };

    const findings = buildTrivyImageFindings(report, "node:20-alpine");
    expect(findings[0].cveIds).toBeUndefined();
  });

  it("skips a vulnerability entry missing an id or package name rather than emitting a broken finding", () => {
    const report = { Results: [{ Vulnerabilities: [{ Severity: "HIGH" }, { VulnerabilityID: "CVE-2024-0001" }] }] };
    expect(buildTrivyImageFindings(report, "node:20-alpine")).toEqual([]);
  });

  it("maps an unrecognised/missing severity to info rather than throwing or defaulting to critical", () => {
    const report = { Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-2024-0002", PkgName: "foo" }] }] };
    expect(buildTrivyImageFindings(report, "img")[0].severity).toBe("info");
  });

  it("notes when no fixed version is published yet, without fabricating one", () => {
    const report = { Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-2024-0003", PkgName: "foo", Severity: "CRITICAL" }] }] };
    expect(buildTrivyImageFindings(report, "img")[0].remediation).toContain("No fixed version has been published");
  });
});

describe("buildTrivyConfigFindings", () => {
  it("returns an empty array when there are no results", () => {
    expect(buildTrivyConfigFindings({})).toEqual([]);
  });

  it("builds one Finding per misconfiguration, with a stable checkId keyed on rule id + file path", () => {
    const report = {
      Results: [
        {
          Target: "main.tf",
          Type: "terraform",
          Misconfigurations: [
            {
              ID: "AVD-AWS-0107",
              Title: "Security group allows ingress from 0.0.0.0/0",
              Message: "Security group rule allows ingress from public internet.",
              Severity: "CRITICAL",
              Resolution: "Set a CIDR range that does not include 0.0.0.0/0.",
              PrimaryURL: "https://avd.aquasec.com/misconfig/avd-aws-0107",
            },
          ],
        },
      ],
    };

    const findings = buildTrivyConfigFindings(report);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "trivy-config.misconfiguration:AVD-AWS-0107:main.tf", severity: "critical" });
    expect(findings[0].title).toContain("main.tf");
    expect(findings[0].remediation).toContain("Set a CIDR range");
    expect(findings[0].remediation).toContain("avd.aquasec.com");
  });

  it("falls back to a generic remediation pointer when Trivy's own Resolution field is empty", () => {
    const report = { Results: [{ Target: "deployment.yaml", Misconfigurations: [{ ID: "AVD-K8S-0001", Severity: "LOW" }] }] };
    const findings = buildTrivyConfigFindings(report);
    expect(findings[0].remediation).toContain("no specific remediation text was published");
  });

  it("skips a misconfiguration entry missing an id", () => {
    const report = { Results: [{ Target: "main.tf", Misconfigurations: [{ Title: "no id" }] }] };
    expect(buildTrivyConfigFindings(report)).toEqual([]);
  });
});
