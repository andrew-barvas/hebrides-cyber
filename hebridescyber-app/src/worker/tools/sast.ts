// Static code analysis (SAST) of the customer's connected GitHub repository,
// with the Opengrep engine and our own rule pack (hebridescyber-app/sast-rules/).
//
// LICENSING — why this shape: Semgrep's maintained rules are under the
// Semgrep Rules License v1.0, which forbids use in a competing commercial
// SaaS, and the opengrep-rules repository is archived and marked "for
// research, testing & benchmarking". So the engine is Opengrep (LGPL-2.1,
// https://github.com/opengrep/opengrep), run as a separate binary via
// execFile — no linking — and every rule it runs here was written from
// scratch for this project (MIT, see sast-rules/*.yaml headers). Do not copy
// rules in from semgrep-rules or opengrep-rules.
//
// What it is and isn't: pattern and taint matching of ~35 high-precision
// rules (request input reaching SQL/eval/shell/unserialize/include/redirect,
// TLS verification off, debug mode on, JWT verification off) across
// JavaScript/TypeScript, Python and PHP. It is not a code review: it can't
// see validation in another file, framework-level protections, or whether a
// route is reachable. Rules are tuned for precision over recall.
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md):
//   - a failed clone, a missing rule pack, a non-zero exit or unparseable
//     output is status "error", never an empty "completed";
//   - checkIds hash location only (path|line|rule) and never contain code;
//   - details carry the file, line and at most a 200-character snippet, with
//     long token-like string literals masked;
//   - the GitHub token never leaves repoClone.ts unsanitised.
//
// CLI flags were checked against a real Opengrep 1.30.0 binary (`opengrep
// scan --help`, plus a real scan of a sample repository — the captured
// output is fixtures/opengrep-scan.json). Notably `--exclude-minified-files`
// is listed in --help but rejected by the 1.30.0 CLI, so minified files are
// excluded by name pattern instead, and `--no-rewrite-rule-ids` is required:
// without it check_id is prefixed with the rules directory's path.
import { execTool } from "../../lib/execTool";
import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import type { Finding } from "../../lib/scanners";
import { resolveGithubAuth } from "../../lib/githubApp";
import { isValidGithubRepo, sanitiseGitOutput, withShallowClone } from "../../lib/repoClone";
import { extractCweIds, sastCategoryForCwes, SAST_CATEGORY_LABELS, type SastCategory } from "../../lib/scanners/sastCatalog";
import { sastLanguageForPath, sastRemediation } from "../../lib/scanners/remediationText";

const execFileAsync = execTool;

const OPENGREP_SCAN_TIMEOUT_MS = 240_000;
const OPENGREP_PROBE_TIMEOUT_MS = 15_000;
const CLONE_TIMEOUT_MS = 60_000;
/** Per-file size cap handed to opengrep; bigger files are generated or vendored. */
export const SAST_MAX_TARGET_BYTES = 500_000;
/** Findings are persisted and rendered; past this, the note says how many were dropped. */
export const SAST_MAX_FINDINGS = 50;
const SNIPPET_MAX_CHARS = 200;

/**
 * Paths never worth scanning: dependencies, build output, and test code
 * (deliberately vulnerable fixtures and test-only TLS shortcuts are the main
 * source of false positives). Directory names match at any depth.
 */
export const SAST_EXCLUDE_DIRS = [
  "node_modules", "vendor", "bower_components", "dist", "build", ".next", "coverage",
  "test", "tests", "__tests__", "__mocks__", "spec", "fixtures", "e2e",
] as const;
export const SAST_EXCLUDE_FILE_PATTERNS = [
  "*.min.js", "*.min.mjs", "*.bundle.js", "*.test.*", "*.spec.*", "test_*.py", "*_test.py", "conftest.py",
] as const;

export type SastResult =
  | { status: "completed"; repo: string; findings: Finding[]; filesScanned: number; matches: number; note?: string }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string }
  | { status: "error"; repo: string; findings: []; note: string };

export type SastOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to resolveGithubAuth(). Override only for tests/local verification. */
  githubToken?: string;
  /** Defaults to SAST_RULES_DIR, else <cwd>/sast-rules (the worker runs from hebridescyber-app/). */
  rulesDir?: string;
};

// ---- Opengrep JSON ----------------------------------------------------------

export type OpengrepResult = {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    is_ignored?: boolean;
    metadata?: { cwe?: unknown; confidence?: unknown; severity?: unknown; [key: string]: unknown };
  };
};

export type OpengrepReport = {
  version?: string;
  results?: OpengrepResult[];
  errors?: Array<{ level?: string; type?: unknown; message?: string; path?: string }>;
  paths?: { scanned?: string[] };
};

export function buildOpengrepArgs(rulesDir: string, targetDir: string): string[] {
  const args = [
    "scan",
    "--config", rulesDir,
    "--json",
    "--quiet",
    "--disable-version-check",
    "--no-rewrite-rule-ids",
    "--max-target-bytes", String(SAST_MAX_TARGET_BYTES),
    "--timeout", "10",
    "--timeout-threshold", "3",
    "--max-lines-per-finding", "3",
    "--max-chars-per-line", String(SNIPPET_MAX_CHARS),
  ];
  for (const dir of SAST_EXCLUDE_DIRS) args.push("--exclude", dir);
  for (const pattern of SAST_EXCLUDE_FILE_PATTERNS) args.push("--exclude", pattern);
  args.push(targetDir);
  return args;
}

/** Throws on output that isn't an Opengrep JSON report — the caller turns that into status "error". */
export function parseOpengrepOutput(stdout: string): OpengrepReport {
  const parsed: unknown = JSON.parse(stdout);
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as OpengrepReport).results)) {
    throw new Error("opengrep output has no results array");
  }
  return parsed as OpengrepReport;
}

/**
 * Rule-level problems (a broken rule file, an unparseable config) mean the
 * scan didn't really run. Errors tied to one target file (a syntax error in
 * the customer's code, a per-file timeout) only mean that file was skipped.
 */
export function fatalOpengrepErrors(report: OpengrepReport): string[] {
  return (report.errors ?? [])
    .filter((e) => (e.level ?? "error") === "error" && !e.path)
    .map((e) => (e.message ?? JSON.stringify(e.type ?? "unknown error")).slice(0, 200));
}

// ---- Report -> Finding[] ----------------------------------------------------

/** "sast-rules.javascript.js-sql-injection" or "js-sql-injection" → "js-sql-injection". */
export function normaliseRuleId(checkId: string | undefined): string {
  const last = (checkId ?? "").split(".").pop() ?? "";
  const cleaned = last.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return cleaned || "unknown-rule";
}

/**
 * Stable identity for New/Fixed diffing: rule + repo-relative path + line,
 * hashed so no code (and no path text) ends up in the id. Like secretScan's
 * secretCheckId, only location data goes in. A finding moves (new id) if
 * code above it shifts by a line — accepted, since hashing the matched code
 * instead would put a function of the customer's source into the id.
 */
export function sastCheckId(ruleId: string, relPath: string, line: number): string {
  const hash = createHash("sha256").update(`${relPath}|${line}|${ruleId}`).digest("hex").slice(0, 16);
  return `sast.${ruleId}:${hash}`;
}

/** Repo-relative, forward-slash path; strips the temp clone directory. */
export function toRepoRelativePath(rawPath: string, rootDir: string): string {
  const path = rawPath.replace(/\\/g, "/");
  const root = rootDir.replace(/\\/g, "/").replace(/\/+$/, "");
  if (root && path.startsWith(`${root}/`)) return path.slice(root.length + 1);
  // Belt and braces: never let a temp-directory prefix reach a report.
  const marker = path.search(/\/hebridescyber-sast-[^/]+\/repo\//);
  if (marker !== -1) return path.slice(path.indexOf("/repo/", marker) + "/repo/".length);
  return path.replace(/^\.?\//, "");
}

export function isExcludedPath(relPath: string): boolean {
  const segments = relPath.toLowerCase().split("/");
  const basename = segments[segments.length - 1] ?? "";
  if (segments.slice(0, -1).some((s) => (SAST_EXCLUDE_DIRS as readonly string[]).includes(s))) return true;
  return SAST_EXCLUDE_FILE_PATTERNS.some((pattern) => {
    const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
    return re.test(basename);
  });
}

const SEVERITY_LADDER: Finding["severity"][] = ["info", "low", "medium", "high", "critical"];

/**
 * metadata.severity (our own product severity on every rule in the pack)
 * wins; otherwise the engine severity maps across. A LOW-confidence rule is
 * downgraded one step — none of ours are, but a rule added later might be.
 */
export function sastSeverity(
  engineSeverity: string | undefined,
  metadata: { severity?: unknown; confidence?: unknown } | undefined
): Finding["severity"] {
  const declared = typeof metadata?.severity === "string" ? metadata.severity.toLowerCase() : "";
  let level = SEVERITY_LADDER.indexOf(declared as Finding["severity"]);
  if (level === -1) {
    switch ((engineSeverity ?? "").toUpperCase()) {
      case "CRITICAL":
        level = 4;
        break;
      case "ERROR":
      case "HIGH":
        level = 3;
        break;
      case "WARNING":
      case "MEDIUM":
        level = 2;
        break;
      case "INFO":
      case "LOW":
        level = 1;
        break;
      default:
        level = 2;
    }
  }
  if (typeof metadata?.confidence === "string" && metadata.confidence.toUpperCase() === "LOW") level -= 1;
  return SEVERITY_LADDER[Math.max(0, Math.min(SEVERITY_LADDER.length - 1, level))];
}

/**
 * One line of matched code, trimmed to 200 characters, with token-like string
 * literals (no whitespace, 12+ characters) masked — the rules don't target
 * secrets, but a matched line can still contain one (a hard-coded JWT key next
 * to algorithms: ["none"]), and this text is shown in reports and webhooks.
 */
export function safeSnippet(lines: string | undefined): string | null {
  if (!lines) return null;
  const first = lines.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0);
  if (!first || /^requires login$/i.test(first)) return null;
  const masked = first.replace(/(["'`])([^\s"'`]{12,})\1/g, (_m, q: string) => `${q}***${q}`);
  return masked.length > SNIPPET_MAX_CHARS ? `${masked.slice(0, SNIPPET_MAX_CHARS - 1)}…` : masked;
}

type Built = { finding: Finding; rank: number };

export function buildSastFindings(
  report: OpengrepReport,
  rootDir: string
): { findings: Finding[]; matches: number; truncated: boolean } {
  const seen = new Set<string>();
  const built: Built[] = [];

  for (const r of report.results ?? []) {
    if (r.extra?.is_ignored) continue;
    const line = typeof r.start?.line === "number" ? r.start.line : 0;
    if (!r.path || line <= 0) continue;
    const relPath = toRepoRelativePath(r.path, rootDir);
    if (isExcludedPath(relPath)) continue;

    const ruleId = normaliseRuleId(r.check_id);
    const checkId = sastCheckId(ruleId, relPath, line);
    // Taint mode reports one result per source→sink path; one per location is enough.
    if (seen.has(checkId)) continue;
    seen.add(checkId);

    const metadata = r.extra?.metadata ?? {};
    const cweIds = extractCweIds(metadata.cwe);
    const category: SastCategory | null = sastCategoryForCwes(cweIds);
    const severity = sastSeverity(r.extra?.severity, metadata);
    const label = category ? SAST_CATEGORY_LABELS[category] : ruleId;
    const snippet = safeSnippet(r.extra?.lines);
    const message = (r.extra?.message ?? "").replace(/\s+/g, " ").trim();
    const confidence = typeof metadata.confidence === "string" ? metadata.confidence.toUpperCase() : undefined;

    const detailParts = [
      `${message || "A static-analysis rule matched this code."}`,
      `Found by rule \`${ruleId}\` in \`${relPath}\` at line ${line}${cweIds.length ? ` (${cweIds.join(", ")})` : ""}.`,
    ];
    if (snippet) detailParts.push(`Matched code: \`${snippet.replace(/`/g, "'")}\``);
    detailParts.push(
      "This is a pattern-based finding from reading the source, not a confirmed exploit: check whether the route is reachable and whether the value is validated somewhere the analyser can't see."
    );

    built.push({
      rank: SEVERITY_LADDER.indexOf(severity),
      finding: {
        checkId,
        severity,
        title: `[SAST] ${label} in ${relPath}:${line}`,
        detail: detailParts.join(" "),
        remediation: sastRemediation(category, sastLanguageForPath(relPath)),
        metadata: { ruleId, file: relPath, line, cwe: cweIds, ...(confidence ? { confidence } : {}) },
      },
    });
  }

  // Most severe first, so the cap drops the least important matches.
  built.sort((a, b) => b.rank - a.rank || (a.finding.title < b.finding.title ? -1 : a.finding.title > b.finding.title ? 1 : 0));
  const truncated = built.length > SAST_MAX_FINDINGS;
  return { findings: built.slice(0, SAST_MAX_FINDINGS).map((b) => b.finding), matches: built.length, truncated };
}

// ---- Entry point ------------------------------------------------------------

type ExecFailure = { code?: string | number; killed?: boolean; signal?: string | null; message?: string; stderr?: string };

function opengrepBinary(): string {
  return process.env.OPENGREP_BIN || "opengrep";
}

function defaultRulesDir(): string {
  return process.env.SAST_RULES_DIR || join(process.cwd(), "sast-rules");
}

/**
 * Never throws. No repo → not_applicable; no binary/rules/token/git →
 * not_configured; a clone, scan or parse failure → error.
 */
export async function runSast(options: SastOptions): Promise<SastResult> {
  const githubRepo = options.githubRepo || null;
  if (!githubRepo) {
    return { status: "not_applicable", repo: "", findings: [], note: "No repository connected — see /account to connect one." };
  }
  if (!isValidGithubRepo(githubRepo)) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "Connected githubRepo is not a valid 'owner/repo' — reconnect via /account." };
  }

  const rulesDir = options.rulesDir ?? defaultRulesDir();
  try {
    if (!(await stat(rulesDir)).isDirectory()) throw new Error("not a directory");
  } catch {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "SAST rule pack (sast-rules/) not found in this environment — skipping static analysis." };
  }

  // Cheap probe first, so a runner without opengrep doesn't clone for nothing.
  try {
    await execFileAsync(opengrepBinary(), ["--version"], { timeout: OPENGREP_PROBE_TIMEOUT_MS, maxBuffer: 1024 * 1024 });
  } catch (err) {
    const failure = err as ExecFailure;
    if (failure.code === "ENOENT") {
      return { status: "not_configured", repo: githubRepo, findings: [], note: "opengrep is not installed in this environment — skipping static analysis." };
    }
    return { status: "error", repo: githubRepo, findings: [], note: `opengrep --version failed: ${(failure.message ?? "unknown error").slice(0, 300)}` };
  }

  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping static analysis. See .env.example." };
  }

  try {
    const outcome = await withShallowClone(
      githubRepo,
      token,
      { tempPrefix: "hebridescyber-sast-", timeoutMs: CLONE_TIMEOUT_MS },
      async (cloneDir): Promise<SastResult> => {
        let stdout: string;
        try {
          ({ stdout } = await execFileAsync(opengrepBinary(), buildOpengrepArgs(rulesDir, cloneDir), {
            timeout: OPENGREP_SCAN_TIMEOUT_MS,
            maxBuffer: 50 * 1024 * 1024,
          }));
        } catch (err) {
          const failure = err as ExecFailure;
          if (failure.code === "ENOENT") {
            return { status: "not_configured", repo: githubRepo, findings: [], note: "opengrep is not installed in this environment — skipping static analysis." };
          }
          if (failure.killed) {
            return { status: "error", repo: githubRepo, findings: [], note: `opengrep exceeded ${OPENGREP_SCAN_TIMEOUT_MS / 1000}s on ${githubRepo}` };
          }
          const why = (failure.stderr || failure.message || "unknown error").replace(/\s+/g, " ").slice(0, 300);
          return { status: "error", repo: githubRepo, findings: [], note: sanitiseGitOutput(`opengrep scan failed (exit ${String(failure.code ?? "?")}): ${why}`, token) };
        }

        let report: OpengrepReport;
        try {
          report = parseOpengrepOutput(stdout);
        } catch (err) {
          return { status: "error", repo: githubRepo, findings: [], note: `could not parse opengrep output: ${(err as Error).message}` };
        }

        const fatal = fatalOpengrepErrors(report);
        if (fatal.length > 0) {
          return { status: "error", repo: githubRepo, findings: [], note: sanitiseGitOutput(`opengrep reported ${fatal.length} rule/config error(s): ${fatal[0]}`, token) };
        }

        const { findings, matches, truncated } = buildSastFindings(report, cloneDir);
        const filesScanned = report.paths?.scanned?.length ?? 0;
        const fileErrors = (report.errors ?? []).filter((e) => e.path).length;
        const notes: string[] = [];
        if (truncated) notes.push(`Only the ${SAST_MAX_FINDINGS} most severe of ${matches} SAST matches are reported.`);
        if (fileErrors > 0) notes.push(`${fileErrors} file(s) could not be fully analysed (parse errors or per-file timeouts) and may hide further issues.`);
        if (filesScanned === 0) notes.push("No JavaScript/TypeScript, Python or PHP files were found to analyse.");
        return { status: "completed", repo: githubRepo, findings, filesScanned, matches, ...(notes.length ? { note: notes.join(" ") } : {}) };
      }
    );

    if (outcome.ok) return outcome.value;
    if (outcome.failure.reason === "git_missing") {
      return { status: "not_configured", repo: githubRepo, findings: [], note: "git is not installed in this environment — skipping static analysis." };
    }
    return { status: "error", repo: githubRepo, findings: [], note: outcome.failure.note };
  } catch (err) {
    return { status: "error", repo: githubRepo, findings: [], note: sanitiseGitOutput(`static analysis failed: ${(err as Error).message}`, token) };
  }
}
