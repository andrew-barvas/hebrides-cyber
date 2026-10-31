// SARIF 2.1.0 export of one scan's findings, for GitHub code scanning (the
// Security tab and pull-request annotations) and any other tool that reads
// SARIF. Pure: findings in, a SARIF log out, no I/O, so it is testable without a
// database. The route that serves it is pages/api/v1/scans/[id]/export.ts.
//
// Choices that are easy to get wrong, and why they are as they are:
//
//   - A result's identity is its checkId, the same stable identity
//     findingsDiff.ts and the lifecycle use. It becomes the result's
//     partialFingerprint, so GitHub follows one alert across uploads instead of
//     opening a duplicate each time the wording of a title changes.
//   - A rule is the checkId's base (the part before the first ":"). Instances of
//     one check on different cookies, ports or files are results of one rule.
//   - Location comes from structured data only: metadata.file and metadata.line
//     (code, workflow, dependency and secret findings). Never parsed out of a
//     finding's text, which is how a wrong fix gets attached to a finding. A
//     finding with no file is located at the scanned URL, which GitHub lists in
//     the Security tab but cannot annotate on a pull request.
//   - Triage is carried, not hidden: accepted and snoozed findings are included
//     as SARIF suppressions with the owner's reason. False positives are left out
//     entirely, as in the executive report: they are "not a real issue".
//   - Nothing here changes a finding's severity or score. Severity maps to a SARIF
//     level and to GitHub's numeric security-severity; CVSS is used when present.
import type { Log, ReportingDescriptor, Result } from "sarif";
import type { Finding } from "./scanners";
import type { FindingTriage } from "./findingTriage";
import { confirmedProof } from "./proofEvidence";

export const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

/** GitHub processes at most this many results per run; keep the most severe. */
export const MAX_SARIF_RESULTS = 5000;

/** SARIF has no limit on a message, but long ones are unreadable in an alert. */
const MAX_MESSAGE_CHARS = 1000;

const SEVERITY_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];
const rank = (s: Finding["severity"]) => SEVERITY_ORDER.indexOf(s);

type SarifLevel = "error" | "warning" | "note";
const LEVEL: Record<Finding["severity"], SarifLevel> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

/** GitHub's severity buckets: 9.0+ critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low. Info gets none. */
const DEFAULT_SECURITY_SEVERITY: Partial<Record<Finding["severity"], number>> = { critical: 9.5, high: 8.0, medium: 5.5, low: 2.0 };

export type SarifFinding = Finding & { triage?: FindingTriage | null };

export type SarifInput = {
  targetUrl: string;
  scanId: string;
  findings: SarifFinding[];
  /** Public site address for the tool's informationUri. */
  siteUrl?: string;
};

const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "finding";

/** The rule a finding belongs to: its checkId's base, or a stable stand-in for a finding stored before checkIds existed. */
export function ruleIdOf(f: Finding): string {
  if (f.checkId) {
    const colon = f.checkId.indexOf(":");
    const base = colon === -1 ? f.checkId : f.checkId.slice(0, colon);
    if (base) return base;
  }
  return `legacy.${slug(f.title)}`;
}

/** The result's identity across uploads. */
function fingerprintOf(f: Finding): string {
  return f.checkId || `legacy:${slug(f.title)}`;
}

/** GitHub's 0-10 number: the finding's CVSS score when it has one, else a default for its severity. */
export function securitySeverityOf(f: Finding): number | null {
  if (typeof f.cvssScore === "number" && Number.isFinite(f.cvssScore) && f.cvssScore >= 0 && f.cvssScore <= 10) return Math.round(f.cvssScore * 10) / 10;
  return DEFAULT_SECURITY_SEVERITY[f.severity] ?? null;
}

/**
 * A path inside the repository, or null. Rejects anything that is not plainly
 * relative to the repo root (absolute paths, drive letters, "..", URL schemes),
 * because a location outside the repo is at best useless and at worst misleading.
 */
export function repoRelativePath(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const normalised = raw.trim().replace(/\\/g, "/").replace(/^(\.\/)+/, "");
  if (!normalised || normalised.startsWith("/") || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(normalised)) return null;
  const parts = normalised.split("/");
  if (parts.some((p) => p === ".." || p === "" || p === ".")) return null;
  return parts.map(encodeURIComponent).join("/");
}

function locationOf(f: Finding, targetUrl: string): NonNullable<Result["locations"]>[number] {
  const file = repoRelativePath(f.metadata?.file);
  if (file) {
    const line = f.metadata?.line;
    const startLine = typeof line === "number" && Number.isFinite(line) && line >= 1 ? Math.floor(line) : 1;
    return { physicalLocation: { artifactLocation: { uri: file, uriBaseId: "%SRCROOT%" }, region: { startLine } } };
  }
  return { physicalLocation: { artifactLocation: { uri: targetUrl } } };
}

function messageOf(f: Finding): string {
  const text = f.detail ? `${f.title}: ${f.detail}` : f.title;
  const flat = text.replace(/\s+/g, " ").trim() || "Finding";
  return flat.length > MAX_MESSAGE_CHARS ? `${flat.slice(0, MAX_MESSAGE_CHARS - 1)}…` : flat;
}

/** Only the owner's decisions that keep a finding visible become suppressions. */
function suppressionsOf(triage: FindingTriage | null | undefined): Result["suppressions"] | undefined {
  if (!triage || triage.state === "false_positive") return undefined;
  const until = triage.state === "snoozed" && triage.expiresAt ? ` (snoozed until ${triage.expiresAt.slice(0, 10)})` : "";
  return [{ kind: "external", status: "accepted", justification: `${triage.reason}${until}` }];
}

function resultProperties(f: SarifFinding): Record<string, unknown> {
  const props: Record<string, unknown> = { severity: f.severity };
  if (f.checkId) props.checkId = f.checkId;
  if (confirmedProof(f)) props.confirmedExploitable = true;
  if (f.threatIntel) {
    props.knownExploited = f.threatIntel.knownExploited;
    if (typeof f.threatIntel.epss === "number") props.epss = f.threatIntel.epss;
  }
  if (typeof f.cvssScore === "number") props.cvssScore = f.cvssScore;
  if (f.cveIds?.length) props.cveIds = f.cveIds;
  if (f.complianceRefs?.length) props.complianceRefs = f.complianceRefs.map((r) => `${r.framework}: ${r.control}`);
  if (f.fixDifficulty) props.fixDifficulty = f.fixDifficulty;
  if (f.corroboratedBy?.length) props.corroboratedBy = f.corroboratedBy.map((c) => `${c.tool}: ${c.title}`);
  if (f.triage && f.triage.state !== "false_positive") props.triage = { state: f.triage.state, reason: f.triage.reason, expiresAt: f.triage.expiresAt };
  return props;
}

export function buildSarif(input: SarifInput): Log {
  const siteUrl = (input.siteUrl ?? "https://www.hebridescyber.co.uk").replace(/\/+$/, "");

  // False positives are not real issues: leave them out. Most severe first, then a
  // stable order, so two exports of the same scan are byte-identical.
  const kept = input.findings
    .filter((f) => f.triage?.state !== "false_positive")
    .sort((a, b) => rank(a.severity) - rank(b.severity) || ruleIdOf(a).localeCompare(ruleIdOf(b)) || fingerprintOf(a).localeCompare(fingerprintOf(b)));
  const omitted = Math.max(0, kept.length - MAX_SARIF_RESULTS);
  const findings = kept.slice(0, MAX_SARIF_RESULTS);

  const rules: ReportingDescriptor[] = [];
  const ruleIndex = new Map<string, number>();
  const ruleSeverity = new Map<string, number>();
  const results: Result[] = [];

  for (const f of findings) {
    const id = ruleIdOf(f);
    let index = ruleIndex.get(id);
    if (index === undefined) {
      index = rules.length;
      ruleIndex.set(id, index);
      const frameworks = [...new Set((f.complianceRefs ?? []).map((r) => r.framework))];
      rules.push({
        id,
        name: id,
        shortDescription: { text: f.title.slice(0, 200) || id },
        ...(f.remediation ? { help: { text: f.remediation, markdown: f.remediation } } : {}),
        helpUri: `${siteUrl}/what-we-check`,
        defaultConfiguration: { level: LEVEL[f.severity] },
        properties: { tags: ["security", ...frameworks] },
      });
    }
    // Findings arrive most severe first, so a rule's first instance sets its level;
    // the numeric severity is still the maximum across its instances.
    const sev = securitySeverityOf(f);
    if (sev !== null && sev > (ruleSeverity.get(id) ?? -1)) ruleSeverity.set(id, sev);

    results.push({
      ruleId: id,
      ruleIndex: index,
      level: LEVEL[f.severity],
      message: { text: messageOf(f) },
      locations: [locationOf(f, input.targetUrl)],
      partialFingerprints: { "hebridesCheckId/v1": fingerprintOf(f) },
      ...(suppressionsOf(f.triage) ? { suppressions: suppressionsOf(f.triage) } : {}),
      properties: resultProperties(f),
    });
  }

  for (const rule of rules) {
    const sev = ruleSeverity.get(rule.id);
    if (sev !== undefined) rule.properties = { ...rule.properties, "security-severity": sev.toFixed(1) };
  }

  let host = "unknown";
  try {
    host = new URL(input.targetUrl).hostname;
  } catch {
    // an unparseable stored URL still exports, under a generic category
  }

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Hebrides Cyber", organization: "Hebrides Cyber", informationUri: siteUrl, rules } },
        // Keeps different sites' results apart when one repository uploads for several.
        automationDetails: { id: `hebridescyber/${host}/` },
        results,
        properties: { targetUrl: input.targetUrl, scanId: input.scanId, findingCount: findings.length, ...(omitted > 0 ? { omittedResults: omitted } : {}) },
      },
    ],
  };
}
