import { describe, it, expect } from "vitest";
import {
  analysisFor,
  buildPurl,
  collectVexSignals,
  EPSS_EXPLOITABLE_THRESHOLD,
  generateCycloneDxBom,
  generateCycloneDxBomFromInventory,
  isDependencyInventory,
  toLicenseChoices,
  type SbomInput,
} from "./sbomExport";
import type { DependencyInventory } from "./scanners/dependencyManifest";
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

    expect(bom.vulnerabilities!).toHaveLength(2);
    expect(bom.vulnerabilities![0].id).toBe("CVE-2021-23337");
    expect(bom.vulnerabilities![0].source.name).toBe("OSV.dev");
    expect(bom.vulnerabilities![0].affects[0].ref).toBe("npm:lodash@4.17.20");
    expect(bom.vulnerabilities![1].id).toBe("CVE-2020-28500");
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
    expect(bom.components[0].purl).toBe("pkg:golang/github.com/pkg/errors@v0.9.1");
  });

  it("builds a correct Maven purl (group/artifact, not %3A)", () => {
    const bom = generateCycloneDxBom({
      targetUrl: "https://example.com",
      scanId: "s",
      findings: [makeFinding({ checkId: "dependency-manifest.maven:org.example:demo-lib", title: "Vulnerable dependency: org.example:demo-lib@1.0.0" })],
    });
    expect(bom.components[0].purl).toBe("pkg:maven/org.example/demo-lib@1.0.0");
  });

  it("prefers structured metadata over the title, listing every version", () => {
    const bom = generateCycloneDxBom({
      targetUrl: "https://example.com",
      scanId: "s",
      findings: [
        makeFinding({
          checkId: "dependency-manifest.maven:org.example:demo-lib",
          title: "Vulnerable dependency: org.example:demo-lib@1.0.0, 1.1.0",
          metadata: { packageName: "org.example:demo-lib", versions: [{ version: "1.0.0" }, { version: "1.1.0" }] },
        }),
      ],
    });
    expect(bom.components.map((c) => c.purl)).toEqual(["pkg:maven/org.example/demo-lib@1.0.0", "pkg:maven/org.example/demo-lib@1.1.0"]);
  });
});

describe("toLicenseChoices", () => {
  it("maps SPDX ids to license.id and non-standard markers to license.name", () => {
    expect(toLicenseChoices(["MIT", "Apache-2.0"])).toEqual([{ license: { id: "MIT" } }, { license: { id: "Apache-2.0" } }]);
    expect(toLicenseChoices(["non-standard"])).toEqual([{ license: { name: "non-standard" } }]);
  });
  it("is undefined for no data", () => {
    expect(toLicenseChoices(undefined)).toBeUndefined();
    expect(toLicenseChoices([])).toBeUndefined();
  });
});

describe("generateCycloneDxBomFromInventory licences", () => {
  it("populates component.licenses from the inventory's deps.dev data, omitting it where absent", () => {
    const inv = inventory();
    inv.packages[0].license = ["MIT"];
    inv.packages[1].license = ["GPL-3.0-only"];
    // packages[2] has no licence → no licenses field.
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inv });
    expect(bom.components[0].licenses).toEqual([{ license: { id: "MIT" } }]);
    expect(bom.components[1].licenses).toEqual([{ license: { id: "GPL-3.0-only" } }]);
    expect(bom.components[2].licenses).toBeUndefined();
  });
});

describe("buildPurl", () => {
  it("builds spec-correct purls per ecosystem", () => {
    expect(buildPurl("Maven", "org.example:demo-lib", "1.2.3")).toBe("pkg:maven/org.example/demo-lib@1.2.3");
    expect(buildPurl("npm", "@acme/widget", "2.0.0")).toBe("pkg:npm/%40acme/widget@2.0.0");
    expect(buildPurl("PyPI", "Demo_Pkg", "1.0")).toBe("pkg:pypi/demo-pkg@1.0");
    expect(buildPurl("Go", "example.com/mod/sub", "1.4.0")).toBe("pkg:golang/example.com/mod/sub@v1.4.0");
    expect(buildPurl("RubyGems", "demo-gem", "3.1.0")).toBe("pkg:gem/demo-gem@3.1.0");
    expect(buildPurl("crates.io", "demo_crate", "0.4.1")).toBe("pkg:cargo/demo_crate@0.4.1");
    expect(buildPurl("NuGet", "Demo.Package", "6.0.0")).toBe("pkg:nuget/Demo.Package@6.0.0");
    expect(buildPurl("Packagist", "vendor/demo", "5.0.0")).toBe("pkg:composer/vendor/demo@5.0.0");
    expect(buildPurl("npm", "demo", "1.0.0+build.1")).toBe("pkg:npm/demo@1.0.0%2Bbuild.1");
  });
});

function inventory(overrides: Partial<DependencyInventory> = {}): DependencyInventory {
  return {
    schemaVersion: 1,
    files: [{ file: "package-lock.json", ecosystem: "npm", kind: "lockfile", graph: true }],
    packages: [
      { ecosystem: "npm", name: "app-dep", version: "1.0.0", direct: true, scope: "required", fileIndex: 0, dependsOn: [1] },
      { ecosystem: "npm", name: "@acme/inner", version: "2.0.0", direct: false, scope: "required", fileIndex: 0, vulnIds: ["GHSA-test-0001"], fixedVersion: "2.0.1" },
      { ecosystem: "npm", name: "dev-tool", version: "3.0.0", direct: true, scope: "optional", fileIndex: 0 },
    ],
    totalPackages: 3,
    truncated: false,
    vulnerabilityLookup: "completed",
    advisories: [{ id: "GHSA-test-0001", cveIds: ["CVE-2099-0001"], severity: "high", cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvssScore: 7.5 }],
    ...overrides,
  };
}

describe("generateCycloneDxBomFromInventory", () => {
  it("lists every package with purl, group, scope and properties", () => {
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inventory() });
    expect(bom.components).toHaveLength(3);
    const inner = bom.components[1];
    expect(inner).toMatchObject({ group: "@acme", name: "inner", version: "2.0.0", purl: "pkg:npm/%40acme/inner@2.0.0", scope: "required" });
    expect(inner.properties).toContainEqual({ name: "hebrides:dependency", value: "transitive" });
    expect(inner.properties).toContainEqual({ name: "hebrides:version-source", value: "lockfile-exact" });
    expect(bom.components[2].scope).toBe("optional");
  });

  it("builds the dependency graph from the application down", () => {
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inventory() });
    expect(bom.metadata.component?.["bom-ref"]).toBe("application");
    expect(bom.dependencies).toContainEqual({ ref: "application", dependsOn: ["pkg:npm/app-dep@1.0.0", "pkg:npm/dev-tool@3.0.0"] });
    expect(bom.dependencies).toContainEqual({ ref: "pkg:npm/app-dep@1.0.0", dependsOn: ["pkg:npm/%40acme/inner@2.0.0"] });
    expect(bom.dependencies).toContainEqual({ ref: "pkg:npm/%40acme/inner@2.0.0", dependsOn: [] });
  });

  it("links vulnerabilities to the affected components", () => {
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inventory() });
    expect(bom.vulnerabilities).toHaveLength(1);
    expect(bom.vulnerabilities![0]).toMatchObject({
      id: "GHSA-test-0001",
      references: [{ id: "CVE-2099-0001" }],
      ratings: [{ severity: "high", method: "CVSSv31", score: 7.5 }],
      affects: [{ ref: "pkg:npm/%40acme/inner@2.0.0" }],
    });
  });

  it("omits vulnerabilities entirely when the lookup failed, rather than claiming none", () => {
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inventory({ vulnerabilityLookup: "failed", advisories: [] }) });
    expect(bom.vulnerabilities).toBeUndefined();
    expect(bom.metadata.properties).toContainEqual({ name: "hebrides:vulnerability-lookup", value: "failed" });
  });

  it("has no graph entries for files that record none", () => {
    const inv = inventory({
      files: [{ file: "gradle.lockfile", ecosystem: "Maven", kind: "lockfile", graph: false }],
      packages: [{ ecosystem: "Maven", name: "org.example:demo-lib", version: "1.0", direct: null, scope: "required", fileIndex: 0 }],
      advisories: [],
    });
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inv });
    expect(bom.components[0]).toMatchObject({ group: "org.example", name: "demo-lib", purl: "pkg:maven/org.example/demo-lib@1.0" });
    expect(bom.dependencies).toBeUndefined();
  });

  it("recognises only a usable inventory", () => {
    expect(isDependencyInventory(inventory())).toBe(true);
    expect(isDependencyInventory(undefined)).toBe(false);
    expect(isDependencyInventory({ schemaVersion: 2, files: [], packages: [] })).toBe(false);
    expect(isDependencyInventory(inventory({ files: [] }))).toBe(false);
  });

  it("emits no analysis object when no VEX signals are threaded in (older scans serialise unchanged)", () => {
    const bom = generateCycloneDxBomFromInventory({ targetUrl: "https://example.com", scanId: "s", inventory: inventory() });
    expect(bom.vulnerabilities![0].analysis).toBeUndefined();
  });

  it("populates per-vulnerability VEX analysis when signals are present", () => {
    const bom = generateCycloneDxBomFromInventory({
      targetUrl: "https://example.com",
      scanId: "s",
      inventory: inventory(),
      vex: { kevCveIds: ["CVE-2099-0001"] },
    });
    // The one advisory (GHSA-test-0001 → CVE-2099-0001) is KEV-listed.
    expect(bom.vulnerabilities![0].analysis).toMatchObject({ state: "exploitable" });
    expect(bom.vulnerabilities![0].analysis?.detail).toContain("CISA KEV");
  });

  it("writes in_triage (present, not absent) for an untriaged advisory once VEX is on", () => {
    const bom = generateCycloneDxBomFromInventory({
      targetUrl: "https://example.com",
      scanId: "s",
      inventory: inventory(),
      vex: { kevCveIds: [], epssByCve: {}, notAffected: {} },
    });
    expect(bom.vulnerabilities![0].analysis).toEqual({ state: "in_triage" });
  });
});

describe("analysisFor (VEX exploitability states)", () => {
  it("is in_triage with no signals at all", () => {
    expect(analysisFor("GHSA-x", ["CVE-1"], undefined)).toEqual({ state: "in_triage" });
    expect(analysisFor("GHSA-x", ["CVE-1"], {})).toEqual({ state: "in_triage" });
  });

  it("marks a KEV-listed CVE exploitable, naming it", () => {
    const a = analysisFor("GHSA-x", ["CVE-1", "CVE-2"], { kevCveIds: ["CVE-2"] });
    expect(a.state).toBe("exploitable");
    expect(a.detail).toContain("CVE-2");
    expect(a.detail).not.toContain("ransomware");
  });

  it("notes ransomware use when CISA marks the KEV CVE", () => {
    const a = analysisFor("GHSA-x", ["CVE-2"], { kevCveIds: ["CVE-2"], ransomwareCveIds: ["CVE-2"] });
    expect(a.state).toBe("exploitable");
    expect(a.detail).toContain("ransomware");
  });

  it("marks EPSS at/above the threshold exploitable, below it in_triage", () => {
    expect(analysisFor("GHSA-x", ["CVE-1"], { epssByCve: { "CVE-1": EPSS_EXPLOITABLE_THRESHOLD } }).state).toBe("exploitable");
    expect(analysisFor("GHSA-x", ["CVE-1"], { epssByCve: { "CVE-1": 0.01 } }).state).toBe("in_triage");
  });

  it("a false-positive triage wins over KEV and sets not_affected with a justification", () => {
    const a = analysisFor("GHSA-x", ["CVE-2"], {
      kevCveIds: ["CVE-2"],
      notAffected: { "GHSA-x": "we don't call the affected API" },
    });
    expect(a.state).toBe("not_affected");
    expect(a.justification).toBe("code_not_reachable");
    expect(a.detail).toContain("we don't call the affected API");
  });

  it("matches not_affected on a CVE id, not just the advisory id", () => {
    const a = analysisFor("GHSA-x", ["CVE-2"], { notAffected: { "CVE-2": "patched out of our build" } });
    expect(a.state).toBe("not_affected");
  });
});

describe("collectVexSignals", () => {
  function depFinding(overrides: Partial<Finding> = {}): Finding {
    return {
      checkId: "dependency-manifest.npm:lodash",
      severity: "high",
      title: "Vulnerable dependency: lodash@4.17.20",
      detail: "x",
      cveIds: ["CVE-2021-23337"],
      metadata: { osvIds: ["GHSA-dep-1"] },
      ...overrides,
    };
  }

  it("collects KEV, ransomware and EPSS from threat-intel-enriched findings", () => {
    const signals = collectVexSignals([
      depFinding({ threatIntel: { knownExploited: true, kevCveIds: ["CVE-2021-23337"], ransomware: true } }),
      depFinding({ checkId: "dependency-manifest.pip:requests", cveIds: ["CVE-2023-32681"], threatIntel: { knownExploited: false, epss: 0.42 } }),
    ]);
    expect(signals.kevCveIds).toContain("CVE-2021-23337");
    expect(signals.ransomwareCveIds).toContain("CVE-2021-23337");
    expect(signals.epssByCve?.["CVE-2023-32681"]).toBe(0.42);
  });

  it("maps a false-positive triage to a not_affected reason keyed by advisory and CVE id", () => {
    const signals = collectVexSignals(
      [depFinding()],
      (checkId) => checkId === "dependency-manifest.npm:lodash"
    );
    expect(signals.notAffected?.["GHSA-dep-1"]).toContain("false positive");
    expect(signals.notAffected?.["CVE-2021-23337"]).toContain("false positive");
  });

  it("ignores non-dependency findings and never defaults not_affected", () => {
    const signals = collectVexSignals([
      { checkId: "tls.no-https", severity: "critical", title: "x", detail: "y" },
      depFinding(),
    ]);
    expect(Object.keys(signals.notAffected ?? {})).toHaveLength(0);
    expect(signals.kevCveIds).toHaveLength(0);
  });

  it("falls back to a finding's own CVE ids for KEV when kevCveIds is absent", () => {
    const signals = collectVexSignals([depFinding({ threatIntel: { knownExploited: true } })]);
    expect(signals.kevCveIds).toContain("CVE-2021-23337");
  });
});
