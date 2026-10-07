// Gitleaks secret scanning of a customer's connected GitHub repository.
//
// ============================================================================
// THE ONE RULE OF THIS MODULE: WE NEVER STORE THE SECRET.
// ----------------------------------------------------------------------------
// Every other scanner in this suite reports on things that are already public
// by definition (open ports, response headers, DNS records). This one is
// different: gitleaks' raw output contains the *actual credential value*, and
// a Finding produced here goes on to be written to scan_results, rendered into
// HTML and PDF reports, POSTed to customer webhooks (src/lib/webhooks.ts),
// pushed into Slack (src/lib/slack.ts), and — via public share links — served
// to anyone holding the URL. Copying a live AWS key into all of that would
// take a secret that was exposed in one place and re-expose it in five more,
// under our name.
//
// So the contract is: a Finding from this module carries the RULE that fired,
// the FILE PATH, the LINE, and the COMMIT — everything the customer needs to
// go look at their own repo and confirm — plus, at most, a short masked
// prefix. Never the value. Three independent layers enforce this:
//
//   1. gitleaks is invoked with `--redact`, so the raw secret is never even
//      written to the report file on disk.
//   2. maskSecretValue() re-masks whatever comes back regardless, in case a
//      gitleaks version ignores or changes that flag.
//   3. buildSecretFindings() only ever reads the fields it explicitly names —
//      `Match`, `Message`, `Author` and `Email` are dropped on the floor, not
//      spread into the Finding. (`Match` is the surrounding source line, which
//      by construction contains the secret; the commit `Message` and author
//      identity are free text / PII we have no business persisting.)
//
// If you change this file, re-check all three. A regression here is not a
// cosmetic bug — it is us leaking the customer's credentials.
// ============================================================================
//
// GitHub access resolves through src/lib/githubApp.ts's resolveGithubAuth():
// a GitHub App installation token when the customer has installed the App on
// this repo, else the shared GITHUB_PAT. The blast-radius risk of a shared
// PAT (flagged in generate-fix-pr.ts's original TODO) applies here with more
// force than anywhere else in the codebase — this module hands the token to
// `git` over the network — which is exactly why an installation token
// (repo-scoped, expires in an hour) is worth the extra plumbing here first.
// sanitiseForOutput() scrubs whichever token was used out of every string
// this module can return, regardless of which auth path supplied it.
//
// Deliberately NOT wired to any table. The `repo_connections` table (owner /
// github_repo / connected_at) is approved but unbuilt, so this is a pure
// function over an explicit { githubRepo } and composes once that lands — see
// the call-site sketch at the bottom of this file.

import { execTool } from "../execTool";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "./index";
import { resolveGithubAuth } from "../githubApp";
import { sanitiseGitOutput } from "../repoClone";

const execFileAsync = execTool;

const githubApi = "https://api.github.com";

// Matches the other extended tools (nuclei/nmap/sqlmap all use 120s).
const CLONE_TIMEOUT_MS = 120_000;
const GITLEAKS_TIMEOUT_MS = 120_000;
const GITHUB_API_TIMEOUT_MS = 10_000;

// gitleaks can emit thousands of hits on a repo that once committed a vendored
// key bundle. Findings are persisted and rendered, so cap what we keep — the
// first 100 are more than enough to make the point, and the note says so.
const MAX_FINDINGS = 100;

// GitHub reports repo size in KB. Above this we stop taking full history (see
// the clone-strategy note on cloneRepository).
const LARGE_REPO_KB = 500_000; // ~500 MB
const SHALLOW_FALLBACK_DEPTH = 500;

// gitleaks reports Entropy only for rules that use an entropy threshold; pure
// regex rules report 0. Below this, an entropy-scored hit is weak evidence.
const MIN_TRUSTED_ENTROPY = 3.0;

export type SecretScanResult =
  | { status: "completed"; repo: string; findings: Finding[]; historyDepth: "full" | "shallow"; note?: string }
  | { status: "not_configured"; repo: string; findings: []; note: string }
  | { status: "error"; repo: string; findings: []; note: string };

export type SecretScanOptions = {
  /** `owner/repo`, exactly as stored by the (unbuilt) repo_connections table. */
  githubRepo: string;
  /** Defaults to src/lib/githubApp.ts's resolveGithubAuth() result (App token or GITHUB_PAT). Override only for tests/local verification. */
  githubToken?: string;
};

/**
 * One row of gitleaks' JSON report (`--report-format json`). Field names are
 * gitleaks' own PascalCase. Everything is optional because we parse defensively
 * across gitleaks versions rather than trusting a schema we don't control.
 *
 * NOTE the fields deliberately absent from the code below: `Match` (the whole
 * source line, containing the secret), `Message` (commit message), `Author`
 * and `Email` (PII). They exist in the report; they must not exit this module.
 */
export type GitleaksReportEntry = {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Commit?: string;
  Date?: string;
  Entropy?: number;
  Tags?: string[];
  Secret?: string;
  Fingerprint?: string;
};

const SECRET_REMEDIATION = `**Rotate the credential first — before you touch the repository.** Anyone who
cloned or forked the repo, and every CI cache and mirror, already has a copy.
Deleting the file does not un-leak it; only revoking the credential does.

1. Revoke/rotate the key in the issuing provider's console (AWS IAM, Stripe,
   GitHub, your cloud provider, etc.) and issue a replacement.
2. Check that provider's audit log for use of the old key by anyone but you.
3. Remove it from git history — the commit is still in every clone even if the
   file no longer exists on the default branch:
   \`\`\`bash
   # preferred: https://github.com/newren/git-filter-repo
   git filter-repo --path path/to/file --invert-paths
   # then force-push, and have every collaborator re-clone
   \`\`\`
4. Replace the hard-coded value with an environment variable or a secrets
   manager (AWS Secrets Manager, Azure Key Vault, GitHub Actions secrets).
5. Stop the next one at the door — add gitleaks as a pre-commit hook:
   \`\`\`bash
   gitleaks protect --staged --redact
   \`\`\`

If this specific hit is a placeholder in a test or documentation file, add it to
a \`.gitleaksignore\` file (by fingerprint) so future scans stay quiet.`;

// ---- Auth / GitHub ---------------------------------------------------------

function ghHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

/**
 * The clone URL embeds the PAT, so it lands in the temp clone's .git/config and
 * in any git error text. Every string this module returns goes through here —
 * the shared sanitiser in src/lib/repoClone.ts (token, then any URL userinfo).
 */
const sanitiseForOutput = sanitiseGitOutput;

// ---- Path / severity heuristics -------------------------------------------

// Directory names that mean "this is illustrative code, not production config".
const SAMPLE_DIRS = new Set([
  "test", "tests", "spec", "specs", "__tests__", "__mocks__", "e2e",
  "fixture", "fixtures", "testdata", "mock", "mocks",
  "example", "examples", "sample", "samples", "demo", "demos",
  "doc", "docs", "seed", "seeds",
]);

const SAMPLE_NAME_MARKERS = ["example", "sample", "dummy", "fake", "mock", "placeholder", "template", "test", "spec"];

// Prose, not config. A key in a README is usually a documented placeholder.
const PROSE_EXTENSIONS = [".md", ".mdx", ".rst", ".txt", ".adoc"];

/**
 * "Never report a finding you cannot evidence" cuts both ways here. We have
 * hard evidence that a *pattern* matched at a *place* — that much is always
 * reportable. What we cannot evidence is that the credential is live, because
 * the only way to prove that is to authenticate with someone else's key, which
 * we are never going to do. So liveness is never asserted, and paths that
 * conventionally hold placeholders are downgraded rather than suppressed: a
 * real key checked into tests/ is still a real key.
 */
export function looksLikeSamplePath(file: string): boolean {
  const path = file.toLowerCase().replace(/\\/g, "/");
  const segments = path.split("/");
  const basename = segments[segments.length - 1] ?? "";

  for (const segment of segments.slice(0, -1)) {
    if (SAMPLE_DIRS.has(segment)) return true;
  }
  if (PROSE_EXTENSIONS.some((ext) => basename.endsWith(ext))) return true;
  // Markers must start a word ("test_config", "config.test.ts", "fake-keys"),
  // not merely appear inside one: as plain substrings "latest", "attestation"
  // and "contest" all contain "test" and "inspect" contains "spec", so a real
  // key in config.latest.json was downgraded from critical to medium — the
  // dangerous direction for this module to be wrong in.
  return SAMPLE_NAME_MARKERS.some((marker) => new RegExp(`(^|[^a-z])${marker}`).test(basename));
}

// Rules whose pattern is structurally unambiguous — an AKIA-prefixed 20-char
// token or a PEM private-key header is not something you type by accident.
const DEFINITIVE_RULES = new Set([
  "private-key", "aws-access-token", "aws-secret-key", "gcp-service-account",
  "gcp-api-key", "github-pat", "github-fine-grained-pat", "github-app-token",
  "github-oauth", "github-refresh-token", "gitlab-pat", "stripe-access-token",
  "slack-bot-token", "slack-user-token", "slack-app-token", "azure-ad-client-secret",
  "openai-api-key", "anthropic-api-key", "sendgrid-api-token", "twilio-api-key",
  "square-access-token", "digitalocean-pat", "npm-access-token",
  "databricks-api-token", "shopify-access-token", "mailchimp-api-key",
  "planetscale-password", "atlassian-api-token",
]);

// Rules that are entropy- or keyword-driven rather than provider-specific.
// These are where gitleaks' false positives live.
const GENERIC_RULE_MARKERS = ["generic", "entropy", "password", "keyword", "secret-key-value"];

const SEVERITY_LADDER: Finding["severity"][] = ["info", "low", "medium", "high", "critical"];

export function severityForSecret(ruleId: string, entropy: number, file: string): Finding["severity"] {
  const rule = ruleId.toLowerCase();
  const definitive = DEFINITIVE_RULES.has(rule) || rule.includes("private-key");
  const generic = GENERIC_RULE_MARKERS.some((marker) => rule.includes(marker));

  // 4 = critical. Only a structurally unambiguous credential pattern starts
  // there; a keyword/entropy hit starts at medium because it is as likely to
  // be a config knob named "secret" as a real key.
  let level = definitive ? 4 : generic ? 2 : 3;

  // Entropy of 0 means the rule didn't score it, not "no entropy".
  if (entropy > 0 && entropy < MIN_TRUSTED_ENTROPY) level -= 1;
  if (looksLikeSamplePath(file)) level -= 2;

  return SEVERITY_LADDER[Math.max(0, Math.min(SEVERITY_LADDER.length - 1, level))];
}

// ---- Redaction -------------------------------------------------------------

/**
 * Turns a secret into something safe to persist. With `--redact` gitleaks has
 * usually already replaced the value, in which case we emit no fragment at all;
 * this is the second line of defence for when it hasn't.
 *
 * Returns a PREFIX only. The prefix of a credential identifies its type and
 * lets a customer tell two of their own keys apart ("which one is it?"); a
 * suffix would do the same job while giving away the high-entropy tail that
 * actually matters if a partial leak is ever brute-forced.
 */
export function maskSecretValue(secret: string | undefined): string | null {
  if (!secret) return null;
  const value = secret.trim();
  if (!value) return null;
  // gitleaks --redact substitutes this; there is nothing left to mask.
  if (/^REDACTED$/i.test(value) || /^\*+$/.test(value)) return null;
  // Too short to reveal a prefix without revealing most of the value.
  if (value.length < 12) return `[redacted, ${value.length} chars]`;
  return `${value.slice(0, 4)}${"*".repeat(8)} (${value.length} chars)`;
}

/**
 * Stable identity for the New/Fixed diff (src/lib/findingsDiff.ts) — this is
 * what makes "this secret is STILL exposed, three scans later" possible, which
 * for secret scanning is arguably more valuable than the first report.
 *
 * Keyed on commit + file + line, all of which are immutable for a historical
 * commit: the commit that introduced a secret never changes its sha, its path,
 * or the line the secret sat on, no matter how many times the repo is scanned
 * or what happens on the default branch afterwards. (This mirrors gitleaks'
 * own Fingerprint, which we don't use directly because its format has changed
 * between versions and we need determinism across upgrades.)
 *
 * Crucially it does NOT hash the secret value. A truncated hash of a
 * low-entropy secret is brute-forceable, so a checkId derived from the value
 * would be a slow leak of the value — the exact thing this module exists to
 * prevent. Only location data goes in.
 */
export function secretCheckId(ruleId: string, commit: string, file: string, startLine: number): string {
  const locator = `${commit}|${file}|${startLine}`;
  const hash = createHash("sha256").update(locator).digest("hex").slice(0, 16);
  const rule = (ruleId || "unknown-rule").toLowerCase().replace(/[^a-z0-9-]/g, "-");
  return `secretScan.exposed-secret:${rule}-${hash}`;
}

// ---- Report -> Finding[] ---------------------------------------------------

/**
 * Exported for the local verification script and future unit tests: it is the
 * half of this module that must be provable without a gitleaks binary present.
 */
export function buildSecretFindings(githubRepo: string, entries: GitleaksReportEntry[]): { findings: Finding[]; truncated: boolean } {
  const findings: Finding[] = [];
  // One secret committed on a long-lived branch shows up once per commit that
  // touched it. Collapse those to the earliest occurrence so the report says
  // "this key is exposed" once rather than forty times. The secret hash used
  // as the map key is computed here and thrown away with the function scope —
  // it is never returned, logged, or persisted.
  const seen = new Set<string>();
  let truncated = false;

  for (const entry of entries) {
    const ruleId = entry.RuleID ?? "unknown-rule";
    const file = entry.File ?? "(unknown file)";
    const startLine = typeof entry.StartLine === "number" ? entry.StartLine : 0;
    const commit = entry.Commit ?? "";
    const entropy = typeof entry.Entropy === "number" ? entry.Entropy : 0;

    const dedupeKey = entry.Secret
      ? `${ruleId}|${file}|${createHash("sha256").update(entry.Secret).digest("hex")}`
      : `${ruleId}|${file}|${startLine}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    if (findings.length >= MAX_FINDINGS) {
      truncated = true;
      break;
    }

    const severity = severityForSecret(ruleId, entropy, file);
    const sample = looksLikeSamplePath(file);
    const fragment = maskSecretValue(entry.Secret);
    const description = entry.Description && entry.Description.length <= 80 ? entry.Description : ruleId;

    const where = commit
      ? `commit \`${commit.slice(0, 8)}\`${entry.Date ? ` (${entry.Date.slice(0, 10)})` : ""}`
      : "the current working tree";

    const detailParts = [
      `Gitleaks rule \`${ruleId}\` matched in \`${file}\` at line ${startLine || "unknown"}, in ${where} of ${githubRepo}.`,
      commit
        ? "This is a match against full git history, so the credential is exposed to anyone with a clone of the repository even if the file has since been deleted or the value replaced on the default branch."
        : "This is a match against the checked-out tree.",
    ];
    if (entropy > 0) detailParts.push(`Shannon entropy of the matched value: ${entropy.toFixed(2)}.`);
    if (sample) {
      detailParts.push(
        "Severity was downgraded because the file path looks like test, fixture, example, or documentation content, where placeholder credentials are common. Confirm it is a placeholder — if it is real, treat this as critical regardless of where it lives."
      );
    }
    detailParts.push(
      "We do not verify whether the credential is still live: doing so would mean authenticating with your key, which this scanner will never do. Treat it as live until you have checked the issuing provider."
    );
    // The masked prefix goes last and is the ONLY part of the value that ever
    // appears here. See the module header.
    detailParts.push(
      fragment
        ? `Masked value (prefix only, deliberately not stored in full): ${fragment}`
        : "The matched value is not stored anywhere in this report by design — open the file at that commit to see it."
    );

    findings.push({
      checkId: secretCheckId(ruleId, commit, file, startLine),
      severity,
      title: `[Gitleaks] Secret in repository: ${description} in ${file}`,
      detail: detailParts.join(" "),
      remediation: SECRET_REMEDIATION,
    });
  }

  return { findings, truncated };
}

function parseGitleaksReport(raw: string): GitleaksReportEntry[] {
  const text = raw.trim();
  if (!text) return [];
  try {
    const parsed: unknown = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed as GitleaksReportEntry[];
    // Some builds emit a single object when there is exactly one hit.
    if (parsed && typeof parsed === "object") return [parsed as GitleaksReportEntry];
    return [];
  } catch {
    return [];
  }
}

// ---- Clone -----------------------------------------------------------------

type ExecFailure = { code?: string | number; killed?: boolean; signal?: string | null; message?: string };

function isMissingBinary(err: ExecFailure): boolean {
  return err.code === "ENOENT";
}

/**
 * CLONE STRATEGY: full history, not `--depth=1`.
 *
 * A shallow clone reduces gitleaks to grepping the current working tree, which
 * throws away the entire reason to run gitleaks at all. The canonical incident
 * is "key committed on Tuesday, deleted on Wednesday, still in every clone
 * forever" — `--depth=1` cannot see that commit, so the scan would return a
 * clean bill of health for a repository that is actively leaking. Fetching a
 * tarball via the GitHub API is worse still: same blind spot, plus no git
 * metadata at all, so findings would carry no commit to anchor a stable
 * checkId to and the New/Fixed diff would degrade every time a line moved.
 *
 * The cost is bounded rather than avoided:
 *   - the repo's size is read from the GitHub API first, and only repos over
 *     ~500 MB fall back to a bounded `--depth` (reported as historyDepth:
 *     "shallow" and called out in the note, so a thin result is never silently
 *     mistaken for a clean one);
 *   - `--no-checkout` skips materialising a working tree — gitleaks' git mode
 *     reads history via `git log -p`, so the files on disk are dead weight;
 *   - a 120s timeout matches the other extended tools;
 *   - the whole temp directory is removed in a `finally`, so a timeout, a
 *     crash mid-parse, or a thrown error still takes the clone AND the report
 *     file (which is the one place raw secrets could touch disk) with it.
 */
async function cloneRepository(githubRepo: string, token: string, dir: string, depth: number | null): Promise<void> {
  const url = `https://x-access-token:${token}@github.com/${githubRepo}.git`;
  const args = [
    // No ambient credential helper, no interactive prompt: a private repo we
    // lack access to must fail fast rather than hang for the full timeout.
    "-c", "credential.helper=",
    "clone",
    "--quiet",
    "--no-checkout",
    "--no-recurse-submodules",
    ...(depth ? ["--depth", String(depth)] : []),
    url,
    dir,
  ];

  await execFileAsync("git", args, {
    timeout: CLONE_TIMEOUT_MS,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GCM_INTERACTIVE: "never" },
  });
}

/** Repo size in KB, or null if the lookup didn't work (we then assume small). */
async function fetchRepoSizeKb(githubRepo: string, token: string): Promise<{ ok: boolean; sizeKb: number | null; status: number }> {
  try {
    const res = await fetch(`${githubApi}/repos/${githubRepo}`, {
      headers: ghHeaders(token),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, sizeKb: null, status: res.status };
    const body = (await res.json()) as { size?: number };
    return { ok: true, sizeKb: typeof body.size === "number" ? body.size : null, status: res.status };
  } catch {
    // Network blip against api.github.com shouldn't block the scan — fall
    // through and let the clone itself be the access check.
    return { ok: true, sizeKb: null, status: 0 };
  }
}

// ---- Entry point -----------------------------------------------------------

/**
 * Scans a connected GitHub repository for committed secrets.
 *
 * Never throws. Every failure path — no token, no binary, no access, timeout,
 * unparseable report — resolves to a not_configured/error result with empty
 * findings, matching how src/worker/tools/*.ts degrade so that one unavailable
 * tool can never fail a whole scan job.
 */
export async function scanRepositoryForSecrets(options: SecretScanOptions): Promise<SecretScanResult> {
  const githubRepo = options.githubRepo;

  // Same validation as src/pages/api/generate-fix-pr.ts. This value is
  // interpolated into a clone URL and a filesystem path, so it is checked
  // before it is used anywhere, not after.
  if (!githubRepo || !/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return { status: "error", repo: String(githubRepo ?? ""), findings: [], note: "githubRepo must look like 'owner/repo'" };
  }

  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return {
      status: "not_configured",
      repo: githubRepo,
      findings: [],
      note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping repository secret scan. See .env.example.",
    };
  }

  let workDir: string | null = null;
  try {
    workDir = await mkdtemp(join(tmpdir(), "hebridescyber-gitleaks-"));
  } catch (err) {
    return { status: "error", repo: githubRepo, findings: [], note: `could not create temp directory: ${(err as Error).message}` };
  }

  const cloneDir = join(workDir, "repo");
  const reportPath = join(workDir, "gitleaks-report.json");

  try {
    const sizeLookup = await fetchRepoSizeKb(githubRepo, token);
    if (!sizeLookup.ok) {
      return {
        status: "error",
        repo: githubRepo,
        findings: [],
        note: `GitHub returned ${sizeLookup.status} for ${githubRepo} — check that the Hebrides Cyber bot has been added as a collaborator.`,
      };
    }

    const depth = sizeLookup.sizeKb !== null && sizeLookup.sizeKb > LARGE_REPO_KB ? SHALLOW_FALLBACK_DEPTH : null;
    const historyDepth: "full" | "shallow" = depth ? "shallow" : "full";

    try {
      await cloneRepository(githubRepo, token, cloneDir, depth);
    } catch (err) {
      const failure = err as ExecFailure;
      if (isMissingBinary(failure)) {
        return { status: "not_configured", repo: githubRepo, findings: [], note: "git is not installed in this environment — skipping repository secret scan." };
      }
      if (failure.killed) {
        return { status: "error", repo: githubRepo, findings: [], note: `clone of ${githubRepo} exceeded ${CLONE_TIMEOUT_MS / 1000}s` };
      }
      return {
        status: "error",
        repo: githubRepo,
        findings: [],
        note: sanitiseForOutput(`could not clone ${githubRepo}: ${failure.message ?? "unknown git error"}`, token),
      };
    }

    // `--redact` is layer 1 of the redaction contract (module header): the raw
    // secret is never written to reportPath in the first place.
    let leaksDetected = false;
    try {
      await execFileAsync(
        "gitleaks",
        [
          "detect",
          "--source", cloneDir,
          "--report-format", "json",
          "--report-path", reportPath,
          "--redact",
          "--no-banner",
          "--exit-code", "1",
        ],
        { timeout: GITLEAKS_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
      );
    } catch (err) {
      const failure = err as ExecFailure;
      if (isMissingBinary(failure)) {
        return {
          status: "not_configured",
          repo: githubRepo,
          findings: [],
          note: "gitleaks is not installed in this environment — skipping repository secret scan.",
        };
      }
      if (failure.killed) {
        return { status: "error", repo: githubRepo, findings: [], note: `gitleaks exceeded ${GITLEAKS_TIMEOUT_MS / 1000}s on ${githubRepo}` };
      }
      if (failure.code === 1) {
        // Exit 1 is gitleaks saying "leaks found", NOT an error — this is the
        // single easiest way to get this integration silently backwards.
        // Distinguished from a genuine usage error (bad flag on an older
        // build, which also exits 1) by whether the report file was written;
        // otherwise an unrecognised flag would read as "clean repo" forever.
        leaksDetected = true;
      } else {
        return {
          status: "error",
          repo: githubRepo,
          findings: [],
          note: sanitiseForOutput(`gitleaks exited with error: ${failure.message ?? "unknown"}`, token),
        };
      }
    }

    let raw: string | null = null;
    try {
      raw = await readFile(reportPath, "utf8");
    } catch {
      raw = null;
    }

    if (raw === null) {
      if (leaksDetected) {
        return {
          status: "error",
          repo: githubRepo,
          findings: [],
          note: "gitleaks reported leaks but wrote no report file — treating as a tool error rather than a clean result.",
        };
      }
      return { status: "completed", repo: githubRepo, findings: [], historyDepth };
    }

    const entries = parseGitleaksReport(raw);
    const { findings, truncated } = buildSecretFindings(githubRepo, entries);

    const notes: string[] = [];
    if (truncated) notes.push(`Only the first ${MAX_FINDINGS} of ${entries.length} gitleaks hits are reported.`);
    if (historyDepth === "shallow") {
      notes.push(
        `Repository is larger than ${Math.round(LARGE_REPO_KB / 1000)} MB, so only the last ${SHALLOW_FALLBACK_DEPTH} commits were scanned — older history was not checked.`
      );
    }

    return {
      status: "completed",
      repo: githubRepo,
      findings,
      historyDepth,
      ...(notes.length ? { note: notes.join(" ") } : {}),
    };
  } catch (err) {
    // Backstop: this function's contract is that it never throws.
    return { status: "error", repo: githubRepo, findings: [], note: sanitiseForOutput(`secret scan failed: ${(err as Error).message}`, token) };
  } finally {
    // Runs on every path above, including the timeout and error returns. This
    // removes the clone (which holds the PAT in .git/config) and the gitleaks
    // report (the only place a raw secret could have touched disk).
    if (workDir) await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---- Wiring (for whoever lands repo_connections) ---------------------------
//
// Intended call site: inside runExtendedTools() in src/lib/scanExecution.ts,
// which is the only place with the binaries installed. It cannot go in the
// Promise.allSettled block with the others because it needs a connected repo,
// which is an owner-level fact rather than a target-URL one — so runExtendedTools
// gains an optional githubRepo parameter, executeScan looks the connection up
// once (repo_connections, by ownerId) and passes it down:
//
//   const secrets = githubRepo
//     ? await scanRepositoryForSecrets({ githubRepo })
//     : { status: "not_configured" as const, repo: "", findings: [] as Finding[], note: "no repository connected" };
//   extended.secretScan = secrets;
//   if (secrets.status === "completed") findings.push(...secrets.findings);
//
// The findings already carry checkId/severity/remediation, so nothing else in
// the pipeline (scoring, diffing, reports, webhooks) needs to know this module
// exists.
