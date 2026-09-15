// CycloneDX 1.5 JSON SBOM generation from dependency manifest scan data.
// Consumes the same Finding[] + metadata that dependencyManifest.ts produces,
// formatting it into a standards-compliant Software Bill of Materials.
//
// EU Cyber Resilience Act (2027) requires SBOM for software products.
// CycloneDX 1.5 chosen over SPDX for better vulnerability correlation.

import type { Finding } from "./scanners";

export type SbomComponent = {
  type: "library";
  name: string;
  version: string;
  purl: string;
  "bom-ref": string;
  scope?: "required" | "optional";
};

export type SbomVulnerability = {
  "bom-ref": string;
  id: string;
  source: { name: string; url: string };
  ratings: Array<{ severity: string; method?: string }>;
  affects: Array<{ ref: string }>;
};

export type CycloneDxBom = {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component?: { type: string; name: string; version?: string };
  };
  components: SbomComponent[];
  vulnerabilities: SbomVulnerability[];
};

const ECOSYSTEM_PURL: Record<string, string> = {
  npm: "npm",
  pip: "pypi",
  composer: "composer",
  go: "golang",
  maven: "maven",
};

function extractEcosystem(checkId: string): string {
  const match = checkId.match(/^dependency-manifest\.(\w+):/);
  return match ? match[1] : "npm";
}

function buildPurl(ecosystem: string, name: string, version: string): string {
  const purlType = ECOSYSTEM_PURL[ecosystem] ?? ecosystem;
  const encodedName = name.includes("/")
    ? name.split("/").map(encodeURIComponent).join("/")
    : encodeURIComponent(name);
  return `pkg:${purlType}/${encodedName}@${encodeURIComponent(version)}`;
}

export type SbomInput = {
  targetUrl: string;
  scanId: string;
  findings: Finding[];
  manifestsScanned?: string[];
  dependenciesDeclared?: number;
  dependenciesChecked?: number;
};

export function generateCycloneDxBom(input: SbomInput): CycloneDxBom {
  const components: SbomComponent[] = [];
  const vulnerabilities: SbomVulnerability[] = [];
  const seen = new Set<string>();

  for (const finding of input.findings) {
    if (!finding.checkId?.startsWith("dependency-manifest.")) continue;
    if (finding.checkId.includes("additional-vulnerable")) continue;

    const titleMatch = finding.title.match(/Vulnerable dependency: (.+)@(.+)$/);
    if (!titleMatch) continue;

    const [, name, version] = titleMatch;
    const ecosystem = extractEcosystem(finding.checkId);
    const purl = buildPurl(ecosystem, name, version);
    const bomRef = `${ecosystem}:${name}@${version}`;

    if (!seen.has(bomRef)) {
      seen.add(bomRef);
      components.push({
        type: "library",
        name,
        version,
        purl,
        "bom-ref": bomRef,
      });
    }

    if (finding.cveIds) {
      for (const cveId of finding.cveIds) {
        vulnerabilities.push({
          "bom-ref": `vuln-${cveId}`,
          id: cveId,
          source: { name: "OSV.dev", url: `https://osv.dev/vulnerability/${cveId}` },
          ratings: [{ severity: finding.severity, method: "other" }],
          affects: [{ ref: bomRef }],
        });
      }
    }
  }

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "Hebrides Cyber", name: "Security Scanner", version: "1.0.0" }],
      component: {
        type: "application",
        name: input.targetUrl,
      },
    },
    components,
    vulnerabilities,
  };
}
