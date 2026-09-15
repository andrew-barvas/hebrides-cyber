import { describe, it, expect } from "vitest";
import { generateCycloneDxBom, type SbomInput } from "./sbomExport";
import type { Finding } from "./scanners";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: "dependency-manifest.npm:lodash",
    severity: "medium",
    title: "Vulnerable dependency: lodash@4.17.20",
    detail: "OSV.dev reports 1 known CVE affecting lodash at version 4.17.20",
    cveIds: ["CVE-2021-23337"],
    ...overrides,
  };
}

describe("generateCycloneDxBom", () => {
  it("produces valid CycloneDX 1.5 structure", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [makeFinding()],
    };

    const bom = generateCycloneDxBom(input);

    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.5");
    expect(bom.version).toBe(1);
    expect(bom.serialNumber).toMatch(/^urn:uuid:/);
    expect(bom.metadata.tools[0].vendor).toBe("Hebrides Cyber");
    expect(bom.metadata.component?.name).toBe("https://example.com");
  });

  it("extracts components from dependency findings", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [
        makeFinding(),
        makeFinding({
          checkId: "dependency-manifest.pip:requests",
          title: "Vulnerable dependency: requests@2.28.0",
          cveIds: ["CVE-2023-32681"],
        }),
      ],
    };

    const bom = generateCycloneDxBom(input);

    expect(bom.components).toHaveLength(2);
    expect(bom.components[0].name).toBe("lodash");
    expect(bom.components[0].version).toBe("4.17.20");
    expect(bom.components[0].purl).toBe("pkg:npm/lodash@4.17.20");
    expect(bom.components[1].name).toBe("requests");
    expect(bom.components[1].purl).toBe("pkg:pypi/requests@2.28.0");
  });

  it("maps CVEs to vulnerabilities", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [
        makeFinding({ cveIds: ["CVE-2021-23337", "CVE-2020-28500"] }),
      ],
    };

    const bom = generateCycloneDxBom(input);

    expect(bom.vulnerabilities).toHaveLength(2);
    expect(bom.vulnerabilities[0].id).toBe("CVE-2021-23337");
    expect(bom.vulnerabilities[0].source.name).toBe("OSV.dev");
    expect(bom.vulnerabilities[0].affects[0].ref).toBe("npm:lodash@4.17.20");
    expect(bom.vulnerabilities[1].id).toBe("CVE-2020-28500");
  });

  it("skips non-dependency findings", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [
        makeFinding(),
        { checkId: "tls.expired", severity: "high", title: "TLS expired", detail: "cert expired" },
      ],
    };

    const bom = generateCycloneDxBom(input);
    expect(bom.components).toHaveLength(1);
  });

  it("skips additional-vulnerable summary findings", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [
        makeFinding(),
        makeFinding({
          checkId: "dependency-manifest.additional-vulnerable:npm",
          title: "5 further vulnerable npm dependencies not listed individually",
        }),
      ],
    };

    const bom = generateCycloneDxBom(input);
    expect(bom.components).toHaveLength(1);
  });

  it("deduplicates components by bom-ref", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [makeFinding(), makeFinding()],
    };

    const bom = generateCycloneDxBom(input);
    expect(bom.components).toHaveLength(1);
  });

  it("handles empty findings", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [],
    };

    const bom = generateCycloneDxBom(input);
    expect(bom.components).toHaveLength(0);
    expect(bom.vulnerabilities).toHaveLength(0);
  });

  it("handles Go ecosystem purl correctly", () => {
    const input: SbomInput = {
      targetUrl: "https://example.com",
      scanId: "scan-123",
      findings: [
        makeFinding({
          checkId: "dependency-manifest.go:github.com/pkg/errors",
          title: "Vulnerable dependency: github.com/pkg/errors@0.9.1",
          cveIds: ["CVE-2024-0001"],
        }),
      ],
    };

    const bom = generateCycloneDxBom(input);
    expect(bom.components[0].purl).toBe("pkg:golang/github.com/pkg/errors@0.9.1");
  });
});
