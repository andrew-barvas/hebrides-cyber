// GitHub Actions workflow security scanning of the customer's connected
// repository, via zizmor (MIT, https://github.com/zizmorcore/zizmor) — a
// real, actively maintained static-analysis tool for GitHub Actions
// workflows and composite actions. Installed from PyPI (pip install
// zizmor==1.30.1; see scheduled-scans.yml/tool-integration.yml), not
// hand-rolled: zizmor already covers script injection via untrusted
// ${{ ... }} expansion, insecure pull_request_target/workflow_run triggers,
// unpinned action references, excessive permissions, secret exposure and
// more — duplicating that logic in-house would be strictly worse.
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md):
//   - a failed clone, a non-zero (tool-failure) exit or unparseable output is
//     status "error", never an empty "completed";
//   - checkIds hash location only (path|line|ident) and never contain code;
//   - details carry the file, line and the exact flagged snippet zizmor
//     itself reports (a `uses:`/`run:`/`on:` fragment, not arbitrary source);
//   - the GitHub token never leaves repoClone.ts unsanitised.
//
// --persona regular (the default, NOT --pedantic) is used deliberately: the
// pedantic persona surfaces code-smell-level findings (excessive-permissions,
// undocumented-permissions, concurrency-limits, anonymous-definition) that
// zizmor's own documentation says trade recall for more false positives —
// the same "precision over recall" choice sast.ts makes for its own rule
// pack. --offline is NOT used: zizmor's online audits (known-vulnerable-actions
// against a live advisory database, impostor-commit against the real commit
// history) are high-value, real supply-chain checks, and the GitHub token
// already resolved for the clone is the same credential zizmor needs for
// them — see resolveGithubAuth() below. If no token is available online
// audits are silently skipped by zizmor itself; the scan still completes.
//
// CLI flags and the JSON (v1) output shape were checked against a real
// zizmor 1.30.1 binary (`zizmor --help`, plus a real scan of a sample
// repository with representative findings — the captured output is
// fixtures/zizmor-scan.json). --no-exit-codes is required: by default
// zizmor's exit code encodes whether findings were present (not just
// whether the tool ran successfully), which this wrapper deliberately does
// not want to parse — findings come from the JSON array alone, so an empty
// array and a tool crash are told apart by exit code 0 vs non-zero, not by
// "did it find anything."
import { execTool } from "../../lib/execTool";
import { createHash } from "node:crypto";
import type { Finding } from "../../lib/scanners";
import { resolveGithubAuth } from "../../lib/githubApp";
import { isValidGithubRepo, sanitiseGitOutput, withShallowClone } from "../../lib/repoClone";
import { workflowSecurityCategoryForIdent, WORKFLOW_SECURITY_CATEGORY_LABELS } from "../../lib/scanners/workflowSecurityCatalog";
import { workflowSecurityRemediation } from "../../lib/scanners/remediationText";

const execFileAsync = execTool;

const ZIZMOR_SCAN_TIMEOUT_MS = 120_000;
const ZIZMOR_PROBE_TIMEOUT_MS = 15_000;
const CLONE_TIMEOUT_MS = 60_000;
/** Findings are persisted and rendered; past this, the note says how many were dropped. */
export const WORKFLOW_SECURITY_MAX_FINDINGS = 50;
const SNIPPET_MAX_CHARS = 200;

export type WorkflowSecurityResult =
  | { status: "completed"; repo: string; findings: Finding[]; matches: number; note?: string }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string }
  | { status: "error"; repo: string; findings: []; note: string };

export type WorkflowSecurityOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to resolveGithubAuth(). Override only for tests/local verification. */
  githubToken?: string;
};

// ---- zizmor JSON (v1) --------------------------------------------------------

export type ZizmorPoint = { row: number; column: number };
export type ZizmorLocation = {
  symbolic: {
    key: { Local?: { verbatim_path?: string } } | Record<string, unknown>;
    kind?: "Primary" | "Hidden" | "Related" | string;
  };
  concrete: {
    location: { start_point: ZizmorPoint; end_point: ZizmorPoint };
    feature?: string;
  };
};
export type ZizmorFinding = {
  ident?: string;
  desc?: string;
  url?: string;
  determinations?: { confidence?: string; severity?: string; persona?: string };
  locations?: ZizmorLocation[];
  ignored?: boolean;
};

export function buildZizmorArgs(targetDir: string, githubToken: string | undefined): string[] {
  const args = ["--no-exit-codes", "--no-progress", "--format", "json"];
  if (githubToken) args.push("--gh-token", githubToken);
  args.push(targetDir);
  return args;
}

/** Throws on output that isn't a zizmor JSON array — the caller turns that into status "error". */
export function parseZizmorOutput(stdout: string): ZizmorFinding[] {
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) throw new Error("zizmor output is not a JSON array");
  return parsed as ZizmorFinding[];
}

// ---- Report -> Finding[] -----------------------------------------------------

/** zizmor idents are already lowercase-hyphenated ("unpinned-uses"); defend against the unexpected anyway. */
export function normaliseIdent(ident: string | undefined): string {
  const cleaned = (ident ?? "").toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return cleaned || "unknown-rule";
}

/**
 * Stable identity for New/Fixed diffing: ident + repo-relative path + line,
 * hashed so no YAML content ends up in the id. Same shape as sast.ts's
 * sastCheckId.
 */
export function workflowSecurityCheckId(ident: string, relPath: string, line: number): string {
  const hash = createHash("sha256").update(`${relPath}|${line}|${ident}`).digest("hex").slice(0, 16);
  return `workflow-security.${ident}:${hash}`;
}

/** Repo-relative, forward-slash path; strips the temp clone directory. Same shape as sast.ts's toRepoRelativePath. */
export function toRepoRelativePath(rawPath: string, rootDir: string): string {
  const path = rawPath.replace(/\\/g, "/");
  const root = rootDir.replace(/\\/g, "/").replace(/\/+$/, "");
  if (root && path.startsWith(`${root}/`)) return path.slice(root.length + 1);
  // Belt and braces: never let a temp-directory prefix reach a report.
  const marker = path.search(/\/hebridescyber-workflowsec-[^/]+\/repo\//);
  if (marker !== -1) return path.slice(path.indexOf("/repo/", marker) + "/repo/".length);
  return path.replace(/^\.?\//, "");
}

const SEVERITY_LADDER: Finding["severity"][] = ["info", "low", "medium", "high", "critical"];

/** zizmor's own severity (Informational/Low/Medium/High) maps directly; it has no "Critical" tier of its own. */
export function workflowSecuritySeverity(zizmorSeverity: string | undefined): Finding["severity"] {
  switch ((zizmorSeverity ?? "").toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

/** The flagged source fragment, trimmed to one line and a safe length. */
export function safeFeatureSnippet(feature: string | undefined): string | null {
  if (!feature) return null;
  const first = feature.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0);
  if (!first) return null;
  return first.length > SNIPPET_MAX_CHARS ? `${first.slice(0, SNIPPET_MAX_CHARS - 1)}…` : first;
}

/** The Primary-kind location is the actual flagged span; Hidden/Related are context only. Falls back to the first location if none is marked Primary. */
function primaryLocation(locations: ZizmorLocation[] | undefined): ZizmorLocation | null {
  if (!locations || locations.length === 0) return null;
  return locations.find((l) => l.symbolic?.kind === "Primary") ?? locations[0];
}

export function buildWorkflowSecurityFindings(
  report: ZizmorFinding[],
  rootDir: string
): { findings: Finding[]; matches: number; truncated: boolean } {
  const seen = new Set<string>();
  const built: { finding: Finding; rank: number }[] = [];

  for (const f of report) {
    if (f.ignored) continue;
    const loc = primaryLocation(f.locations);
    if (!loc) continue;
    const rawPath = (loc.symbolic?.key as { Local?: { verbatim_path?: string } } | undefined)?.Local?.verbatim_path;
    if (!rawPath) continue;
    const relPath = toRepoRelativePath(rawPath, rootDir);
    const line = (loc.concrete?.location?.start_point?.row ?? -1) + 1; // zizmor rows are 0-indexed
    if (line <= 0) continue;

    const ident = normaliseIdent(f.ident);
    const checkId = workflowSecurityCheckId(ident, relPath, line);
    if (seen.has(checkId)) continue;
    seen.add(checkId);

    const category = workflowSecurityCategoryForIdent(ident);
    const label = WORKFLOW_SECURITY_CATEGORY_LABELS[category];
    const severity = workflowSecuritySeverity(f.determinations?.severity);
    const snippet = safeFeatureSnippet(loc.concrete?.feature);
    const message = (f.desc ?? "").replace(/\s+/g, " ").trim();
    const confidence = f.determinations?.confidence;

    const detailParts = [
      `${message || "A GitHub Actions workflow security rule matched this file."}`,
      `Found by zizmor's \`${ident}\` audit in \`${relPath}\` at line ${line}${confidence ? ` (confidence: ${confidence})` : ""}.`,
    ];
    if (snippet) detailParts.push(`Flagged: \`${snippet.replace(/`/g, "'")}\``);

    built.push({
      rank: SEVERITY_LADDER.indexOf(severity),
      finding: {
        checkId,
        severity,
        title: `[Workflow security] ${label} in ${relPath}:${line}`,
        detail: detailParts.join(" "),
        remediation: workflowSecurityRemediation(category, ident),
        metadata: { ident, file: relPath, line, ...(confidence ? { confidence } : {}) },
      },
    });
  }

  // Most severe first, so the cap drops the least important matches.
  built.sort((a, b) => b.rank - a.rank || (a.finding.title < b.finding.title ? -1 : a.finding.title > b.finding.title ? 1 : 0));
  const truncated = built.length > WORKFLOW_SECURITY_MAX_FINDINGS;
  return { findings: built.slice(0, WORKFLOW_SECURITY_MAX_FINDINGS).map((b) => b.finding), matches: built.length, truncated };
}

// ---- Entry point --------------------------------------------------------------

type ExecFailure = { code?: string | number; killed?: boolean; signal?: string | null; message?: string; stderr?: string };

function zizmorBinary(): string {
  return process.env.ZIZMOR_BIN || "zizmor";
}

/**
 * Never throws. No repo → not_applicable; no binary/token/git → not_configured;
 * a clone, scan or parse failure → error.
 */
export async function runWorkflowSecurity(options: WorkflowSecurityOptions): Promise<WorkflowSecurityResult> {
  const githubRepo = options.githubRepo || null;
  if (!githubRepo) {
    return { status: "not_applicable", repo: "", findings: [], note: "No repository connected — see /account to connect one." };
  }
  if (!isValidGithubRepo(githubRepo)) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "Connected githubRepo is not a valid 'owner/repo' — reconnect via /account." };
  }

  // Cheap probe first, so a runner without zizmor doesn't clone for nothing.
  try {
    await execFileAsync(zizmorBinary(), ["--version"], { timeout: ZIZMOR_PROBE_TIMEOUT_MS, maxBuffer: 1024 * 1024 });
  } catch (err) {
    const failure = err as ExecFailure;
    if (failure.code === "ENOENT") {
      return { status: "not_configured", repo: githubRepo, findings: [], note: "zizmor is not installed in this environment — skipping workflow security scanning." };
    }
    return { status: "error", repo: githubRepo, findings: [], note: `zizmor --version failed: ${(failure.message ?? "unknown error").slice(0, 300)}` };
  }

  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping workflow security scanning. See .env.example." };
  }

  try {
    const outcome = await withShallowClone(
      githubRepo,
      token,
      { tempPrefix: "hebridescyber-workflowsec-", timeoutMs: CLONE_TIMEOUT_MS },
      async (cloneDir): Promise<WorkflowSecurityResult> => {
        let stdout: string;
        try {
          ({ stdout } = await execFileAsync(zizmorBinary(), buildZizmorArgs(cloneDir, token), {
            timeout: ZIZMOR_SCAN_TIMEOUT_MS,
            maxBuffer: 20 * 1024 * 1024,
          }));
        } catch (err) {
          const failure = err as ExecFailure;
          if (failure.code === "ENOENT") {
            return { status: "not_configured", repo: githubRepo, findings: [], note: "zizmor is not installed in this environment — skipping workflow security scanning." };
          }
          if (failure.killed) {
            return { status: "error", repo: githubRepo, findings: [], note: `zizmor exceeded ${ZIZMOR_SCAN_TIMEOUT_MS / 1000}s on ${githubRepo}` };
          }
          const why = (failure.stderr || failure.message || "unknown error").replace(/\s+/g, " ").slice(0, 300);
          return { status: "error", repo: githubRepo, findings: [], note: sanitiseGitOutput(`zizmor scan failed (exit ${String(failure.code ?? "?")}): ${why}`, token) };
        }

        let report: ZizmorFinding[];
        try {
          report = parseZizmorOutput(stdout);
        } catch (err) {
          return { status: "error", repo: githubRepo, findings: [], note: `could not parse zizmor output: ${(err as Error).message}` };
        }

        const { findings, matches, truncated } = buildWorkflowSecurityFindings(report, cloneDir);
        const notes: string[] = [];
        if (truncated) notes.push(`Only the ${WORKFLOW_SECURITY_MAX_FINDINGS} most severe of ${matches} workflow security matches are reported.`);
        return { status: "completed", repo: githubRepo, findings, matches, ...(notes.length ? { note: notes.join(" ") } : {}) };
      }
    );

    if (outcome.ok) return outcome.value;
    if (outcome.failure.reason === "git_missing") {
      return { status: "not_configured", repo: githubRepo, findings: [], note: "git is not installed in this environment — skipping workflow security scanning." };
    }
    return { status: "error", repo: githubRepo, findings: [], note: outcome.failure.note };
  } catch (err) {
    return { status: "error", repo: githubRepo, findings: [], note: sanitiseGitOutput(`workflow security scan failed: ${(err as Error).message}`, token) };
  }
}
