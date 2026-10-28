// CycloneDX 1.5 JSON SBOM generation.
//
// Two sources, newest first:
//   1. generateCycloneDxBomFromInventory — the dependency inventory
//      dependencyManifest.ts stores with every scan since lockfile support
//      (results.extended.dependencyManifest.inventory): every package, not
//      just vulnerable ones, with scope, the dependency graph where the
//      lockfile records one, and vulnerabilities linked to components.
//   2. generateCycloneDxBom — the older path for scans stored before that,
//      which only had findings: lists the vulnerable direct dependencies.
//      It reads a finding's structured metadata where present and only
//      falls back to parsing the finding title for those old scans.
//
// EU Cyber Resilience Act (2027) requires SBOM for software products.
// CycloneDX 1.5 chosen over SPDX for better vulnerability correlation.

import type { Finding } from "./scanners";
import type { DependencyInventory } from "./scanners/dependencyManifest";

// CycloneDX 1.5 licence entry: an SPDX id goes in `license.id`, anything else
// in `license.name`. Scans stored before licence enrichment have no licence
// data, so the field is optional and deserialises absent.
export type SbomLicenseChoice = { license: { id?: string; name?: string } };

export type SbomComponent = {
  type: "library";
  group?: string;
  name: string;
  version: string;
  purl: string;
  "bom-ref": string;
  scope?: "required" | "optional";
  licenses?: SbomLicenseChoice[];
  properties?: Array<{ name: string; value: string }>;
};

// Known SPDX ids are a closed set; rather than ship the whole list, treat an id
// that looks like an SPDX expression (letters/digits/.+- and a licence-ish
// shape) as `license.id`, and deps.dev's "non-standard" marker as `license.name`.
const SPDX_ID_RE = /^[A-Za-z0-9][A-Za-z0-9.+-]*$/;

/** Maps deps.dev SPDX strings to CycloneDX licence choices. */
export function toLicenseChoices(licenses: string[] | undefined): SbomLicenseChoice[] | undefined {
  if (!licenses || licenses.length === 0) return undefined;
  const choices = licenses.map((l) =>
    SPDX_ID_RE.test(l) && l.toLowerCase() !== "non-standard" ? { license: { id: l } } : { license: { name: l } }
  );
  return choices.length > 0 ? choices : undefined;
}

// CycloneDX 1.5 vulnerability `analysis` object — the VEX (Vulnerability
// Exploitability eXchange) statement. `state` is one of CycloneDX's own
// impact-analysis values; `justification` (when state is not_affected) is one
// of CycloneDX's impactJustification values. We only ever emit a subset.
export type SbomAnalysisState = "exploitable" | "in_triage" | "not_affected" | "resolved";
export type SbomVulnerabilityAnalysis = {
  state: SbomAnalysisState;
  /** CycloneDX impactJustification — only set with state "not_affected". */
  justification?: string;
  detail?: string;
};

export type SbomVulnerability = {
  "bom-ref": string;
  id: string;
  source: { name: string; url: string };
  references?: Array<{ id: string; source: { name: string; url: string } }>;
  ratings: Array<{ severity: string; method?: string; score?: number; vector?: string }>;
  description?: string;
  affects: Array<{ ref: string }>;
  /** VEX exploitability statement — populated when VEX signals are threaded
   *  in. Absent (not in_triage) when the BOM was generated without them, so a
   *  consumer treats "no analysis" the same as "in triage". */
  analysis?: SbomVulnerabilityAnalysis;
};

// FIRST EPSS probability at or above which we assert "exploitable" without a
// KEV listing: a ≥10% modelled chance of exploitation in the next 30 days is
// the common actionable cut-off (and the band riskScore.ts already treats as
// elevated). Below it, and absent a KEV listing or a triage decision, the
// honest state is in_triage — we have no evidence either way.
export const EPSS_EXPLOITABLE_THRESHOLD = 0.1;

/**
 * The signals a VEX `analysis` is derived from, all optional so a caller that
 * has none still produces valid (in_triage) statements:
 *   - kevCveIds: CVE ids CISA KEV lists as known-exploited (from threatIntel);
 *   - ransomwareCveIds: the subset CISA marks as used in ransomware (detail only);
 *   - epssByCve: CVE id → FIRST EPSS probability (0–1);
 *   - notAffected: advisory id OR CVE id → the recorded false-positive triage
 *     reason. Only ever built from a real triage decision — see
 *     collectVexSignals — so not_affected is never defaulted.
 */
export type SbomVexInput = {
  kevCveIds?: readonly string[];
  ransomwareCveIds?: readonly string[];
  epssByCve?: Readonly<Record<string, number>>;
  notAffected?: Readonly<Record<string, string>>;
};

export type CycloneDxBom = {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component?: { type: string; name: string; version?: string; "bom-ref"?: string };
    properties?: Array<{ name: string; value: string }>;
  };
  components: SbomComponent[];
  dependencies?: Array<{ ref: string; dependsOn: string[] }>;
  /** Absent (not empty) when the vulnerability lookup failed — an empty list would claim "none known". */
  vulnerabilities?: SbomVulnerability[];
};

// Finding checkId slug or OSV ecosystem name → purl type (https://github.com/package-url/purl-spec).
const PURL_TYPE: Record<string, string> = {
  npm: "npm",
  pip: "pypi",
  PyPI: "pypi",
  composer: "composer",
  Packagist: "composer",
  go: "golang",
  Go: "golang",
  maven: "maven",
  Maven: "maven",
  ruby: "gem",
  RubyGems: "gem",
  cargo: "cargo",
  "crates.io": "cargo",
  nuget: "nuget",
  NuGet: "nuget",
};

const enc = (s: string) => encodeURIComponent(s);

/**
 * A package URL for `name@version` in `ecosystem` (an OSV ecosystem name or
 * a dependency-manifest checkId slug). Per the purl spec: Maven is
 * pkg:maven/<group>/<artifact>; PyPI names are lower-cased with "_" → "-";
 * Go module paths keep their "/" segments and versions their "v"; an npm
 * scope's "@" is percent-encoded.
 */
export function buildPurl(ecosystem: string, name: string, version: string): string {
  const type = PURL_TYPE[ecosystem] ?? ecosystem.toLowerCase();
  let path: string;
  let v = version;
  if (type === "maven") {
    const [group, artifact] = name.split(":");
    path = artifact ? `${group.split("/").map(enc).join("/")}/${enc(artifact)}` : enc(name);
  } else if (type === "pypi") {
    path = enc(name.toLowerCase().replace(/_/g, "-"));
  } else {
    path = name.split("/").map(enc).join("/");
    if (type === "golang" && /^\d/.test(v)) v = `v${v}`;
  }
  return `pkg:${type}/${path}@${enc(v)}`;
}

/** CycloneDX group/name split: Maven "group:artifact", npm "@scope/name". */
function groupAndName(ecosystem: string, name: string): { group?: string; name: string } {
  const type = PURL_TYPE[ecosystem];
  if (type === "maven" && name.includes(":")) {
    const [group, artifact] = name.split(":");
    return { group, name: artifact };
  }
  if (type === "npm" && name.startsWith("@") && name.includes("/")) {
    const idx = name.indexOf("/");
    return { group: name.slice(0, idx), name: name.slice(idx + 1) };
  }
  return { name };
}

const TOOLS = [{ vendor: "Hebrides Cyber", name: "Security Scanner", version: "1.0.0" }];

function osvSource(id: string) {
  return { name: "OSV.dev", url: `https://osv.dev/vulnerability/${enc(id)}` };
}

// ---- From the stored inventory (current scans) --------------------------------

export type InventorySbomInput = {
  targetUrl: string;
  scanId: string;
  inventory: DependencyInventory;
  /** VEX signals, when the caller has them. Omit and every vulnerability's
   *  analysis defaults to in_triage (absent) — scans serialised before VEX
   *  existed still produce a valid BOM. */
  vex?: SbomVexInput;
};

/**
 * The CycloneDX VEX `analysis` for one advisory, from its own id and CVE ids.
 * Precedence (most-to-least decisive):
 *   1. a recorded false_positive triage on the advisory/CVE → not_affected,
 *      justification code_not_reachable, detail = the recorded reason;
 *   2. a KEV listing → exploitable, detail naming the KEV (and ransomware) CVE;
 *   3. EPSS ≥ threshold → exploitable, detail naming the score;
 *   4. otherwise in_triage.
 * not_affected is only ever reached from signal (1) — a real triage decision,
 * never defaulted (evidence discipline).
 */
export function analysisFor(advisoryId: string, cveIds: readonly string[], vex: SbomVexInput | undefined): SbomVulnerabilityAnalysis {
  if (!vex) return { state: "in_triage" };
  const ids = [advisoryId, ...cveIds];

  const notAffectedReason = vex.notAffected
    ? ids.map((id) => vex.notAffected![id]).find((r): r is string => typeof r === "string")
    : undefined;
  if (notAffectedReason !== undefined) {
    return {
      state: "not_affected",
      justification: "code_not_reachable",
      detail: notAffectedReason || "Triaged as a false positive.",
    };
  }

  const kev = new Set(vex.kevCveIds ?? []);
  const kevHits = cveIds.filter((c) => kev.has(c));
  if (kevHits.length > 0) {
    const ransom = new Set(vex.ransomwareCveIds ?? []);
    const inRansom = kevHits.some((c) => ransom.has(c));
    const detail = `CISA KEV lists ${kevHits.join(", ")} as known-exploited${inRansom ? " and used in ransomware campaigns" : ""}.`;
    return { state: "exploitable", detail };
  }

  const epss = vex.epssByCve ?? {};
  let topEpss = -1;
  let topCve = "";
  for (const c of cveIds) {
    const score = epss[c];
    if (typeof score === "number" && score > topEpss) {
      topEpss = score;
      topCve = c;
    }
  }
  if (topEpss >= EPSS_EXPLOITABLE_THRESHOLD) {
    return { state: "exploitable", detail: `FIRST EPSS puts ${topCve} at ${(topEpss * 100).toFixed(1)}% probability of exploitation in the next 30 days.` };
  }

  return { state: "in_triage" };
}

/** True for an inventory this module can turn into an SBOM (written by dependencyManifest.ts, schema 1). */
export function isDependencyInventory(value: unknown): value is DependencyInventory {
  const v = value as DependencyInventory | null | undefined;
  return !!v && v.schemaVersion === 1 && Array.isArray(v.files) && v.files.length > 0 && Array.isArray(v.packages);
}

export function generateCycloneDxBomFromInventory(input: InventorySbomInput): CycloneDxBom {
  const { inventory } = input;
  const appRef = "application";
  const refs = inventory.packages.map((p) => buildPurl(p.ecosystem, p.name, p.version));

  const components: SbomComponent[] = inventory.packages.map((p, i) => {
    const file = inventory.files[p.fileIndex];
    const properties = [
      ...(p.direct !== null ? [{ name: "hebrides:dependency", value: p.direct ? "direct" : "transitive" }] : []),
      ...(file ? [{ name: "hebrides:source-file", value: file.file }, { name: "hebrides:version-source", value: file.kind === "lockfile" ? "lockfile-exact" : "manifest-range" }] : []),
    ];
    const licenses = toLicenseChoices(p.license);
    return {
      type: "library",
      ...groupAndName(p.ecosystem, p.name),
      version: p.version,
      purl: refs[i],
      "bom-ref": refs[i],
      ...(p.scope ? { scope: p.scope } : {}),
      ...(licenses ? { licenses } : {}),
      ...(properties.length ? { properties } : {}),
    };
  });

  // The graph, where the files record one: the application depends on its
  // direct dependencies, and each package on what the lockfile says it does.
  const dependencies: Array<{ ref: string; dependsOn: string[] }> = [];
  const direct = inventory.packages.map((p, i) => (p.direct === true ? refs[i] : null)).filter((r): r is string => r !== null);
  if (direct.length) dependencies.push({ ref: appRef, dependsOn: direct });
  inventory.packages.forEach((p, i) => {
    if (inventory.files[p.fileIndex]?.graph) dependencies.push({ ref: refs[i], dependsOn: (p.dependsOn ?? []).map((d) => refs[d]).filter(Boolean) });
  });

  const bom: CycloneDxBom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: TOOLS,
      component: { type: "application", name: input.targetUrl, "bom-ref": appRef },
      properties: [
        ...inventory.files.map((f) => ({ name: "hebrides:scanned-file", value: `${f.file} (${f.kind})` })),
        { name: "hebrides:vulnerability-lookup", value: inventory.vulnerabilityLookup },
        ...(inventory.truncated ? [{ name: "hebrides:truncated", value: `${inventory.packages.length} of ${inventory.totalPackages} packages listed` }] : []),
      ],
    },
    components,
    ...(dependencies.length ? { dependencies } : {}),
  };

  if (inventory.vulnerabilityLookup === "completed") {
    bom.vulnerabilities = inventory.advisories
      .map((a): SbomVulnerability => ({
        "bom-ref": `vuln-${a.id}`,
        id: a.id,
        source: osvSource(a.id),
        ...(a.cveIds.length ? { references: a.cveIds.map((c) => ({ id: c, source: { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${c}` } })) } : {}),
        ratings: [
          a.cvssVector && a.cvssScore !== undefined
            ? { severity: a.severity ?? "unknown", method: a.cvssVector.startsWith("CVSS:3.1") ? "CVSSv31" : "CVSSv3", score: a.cvssScore, vector: a.cvssVector }
            : { severity: a.severity ?? "unknown", method: "other" },
        ],
        ...(a.summary ? { description: a.summary } : {}),
        affects: inventory.packages.map((p, i) => (p.vulnIds?.includes(a.id) ? { ref: refs[i] } : null)).filter((x): x is { ref: string } => x !== null),
        // VEX exploitability statement. Omitted entirely when no signals were
        // threaded in (input.vex absent), so an older scan serialises exactly
        // as before; otherwise always present, defaulting to in_triage.
        ...(input.vex ? { analysis: analysisFor(a.id, a.cveIds, input.vex) } : {}),
      }))
      .filter((v) => v.affects.length > 0);
  }
  return bom;
}

/**
 * Builds the VEX signals for an inventory BOM from the scan's own
 * threat-intel-enriched dependency findings plus a triage lookup. Pure.
 *
 * Each dependency finding carries its advisory ids (metadata.osvIds), its CVE
 * ids, and — after threatIntel.ts's enrichment pass — a threatIntel block
 * (KEV membership, ransomware, EPSS). A false_positive triage on that
 * finding's checkId makes every advisory/CVE it covers not_affected.
 *
 * `isFalsePositive(checkId)` is the one injected lookup: the route builds it
 * from the triage index, so this stays pure and unit-testable without a DB.
 */
export function collectVexSignals(
  findings: Finding[] | undefined,
  isFalsePositive: (checkId: string | undefined) => boolean = () => false
): SbomVexInput {
  const kevCveIds = new Set<string>();
  const ransomwareCveIds = new Set<string>();
  const epssByCve: Record<string, number> = {};
  const notAffected: Record<string, string> = {};

  for (const f of findings ?? []) {
    if (!f.checkId?.startsWith("dependency-manifest.")) continue;
    const cveIds = f.cveIds ?? [];
    const osvIds = Array.isArray((f.metadata as { osvIds?: unknown })?.osvIds)
      ? ((f.metadata as { osvIds?: string[] }).osvIds ?? [])
      : [];

    const ti = f.threatIntel;
    if (ti?.knownExploited) {
      // kevCveIds names the KEV-listed CVEs when present; fall back to all of
      // the finding's CVE ids (knownExploited is only ever true off a real
      // KEV read, so this isn't a guess about which — it's the finding's set).
      for (const c of ti.kevCveIds ?? cveIds) kevCveIds.add(c);
      if (ti.ransomware) for (const c of ti.kevCveIds ?? cveIds) ransomwareCveIds.add(c);
    }
    if (typeof ti?.epss === "number") {
      // The finding carries the highest EPSS across its CVEs; attribute it to
      // each so analysisFor() finds it under whichever CVE the advisory lists.
      for (const c of cveIds) epssByCve[c] = Math.max(epssByCve[c] ?? 0, ti.epss);
    }

    if (isFalsePositive(f.checkId)) {
      const reason = `Triaged as a false positive for ${f.checkId}.`;
      for (const id of [...osvIds, ...cveIds]) notAffected[id] = reason;
    }
  }

  return {
    kevCveIds: [...kevCveIds],
    ransomwareCveIds: [...ransomwareCveIds],
    epssByCve,
    notAffected,
  };
}

// ---- From findings (scans stored before the inventory existed) -----------------

function extractEcosystem(checkId: string): string {
  const match = checkId.match(/^dependency-manifest\.(\w+):/);
  return match ? match[1] : "npm";
}

export type SbomInput = {
  targetUrl: string;
  scanId: string;
  findings: Finding[];
  manifestsScanned?: string[];
  dependenciesDeclared?: number;
  dependenciesChecked?: number;
};

/** name and version(s) of a dependency finding: its metadata when present, else (pre-lockfile scans only) its title. */
function findingPackage(finding: Finding): { name: string; versions: string[] } | null {
  const meta = finding.metadata as { packageName?: unknown; versions?: Array<{ version?: unknown }> } | undefined;
  if (typeof meta?.packageName === "string" && Array.isArray(meta.versions)) {
    const versions = meta.versions.map((v) => v.version).filter((v): v is string => typeof v === "string");
    if (versions.length) return { name: meta.packageName, versions };
  }
  const titleMatch = finding.title.match(/Vulnerable dependency: (.+)@(.+)$/);
  return titleMatch ? { name: titleMatch[1], versions: [titleMatch[2]] } : null;
}

export function generateCycloneDxBom(input: SbomInput): CycloneDxBom {
  const components: SbomComponent[] = [];
  const vulnerabilities: SbomVulnerability[] = [];
  const seen = new Set<string>();

  for (const finding of input.findings) {
    if (!finding.checkId?.startsWith("dependency-manifest.")) continue;
    if (finding.checkId.includes("additional-vulnerable")) continue;

    const pkg = findingPackage(finding);
    if (!pkg) continue;
    const ecosystem = extractEcosystem(finding.checkId);

    for (const version of pkg.versions) {
      const purl = buildPurl(ecosystem, pkg.name, version);
      const bomRef = `${ecosystem}:${pkg.name}@${version}`;

      if (!seen.has(bomRef)) {
        seen.add(bomRef);
        components.push({ type: "library", name: pkg.name, version, purl, "bom-ref": bomRef });
      }

      for (const cveId of finding.cveIds ?? []) {
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
      tools: TOOLS,
      component: {
        type: "application",
        name: input.targetUrl,
      },
    },
    components,
    vulnerabilities,
  };
}
