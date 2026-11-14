// OpenSSF Scorecard for the customer's connected GitHub repository: branch
// protection, code review, dangerous workflows, token permissions, pinned
// dependencies and similar supply-chain practices, each scored 0-10.
//
// Reads Scorecard's published results (api.securityscorecards.dev), which the
// OpenSSF computes weekly for public repositories. Nothing is sent to the
// customer's systems and nothing is installed. Only public repositories are
// queried: the repository is first looked up on GitHub, and a private one is
// never named to the Scorecard API, so its name doesn't leave GitHub.
//
// A repository Scorecard hasn't scored (most new or little-known ones) is
// "not_applicable", never clean. Checks Scorecard couldn't evaluate (score -1)
// are skipped.
import type { Finding } from "../../lib/scanners";
import { resolveGithubAuth } from "../../lib/githubApp";
import { isValidGithubRepo } from "../../lib/repoClone";

export const SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com";
const GITHUB_API = "https://api.github.com";
const TIMEOUT_MS = 15_000;

export type ScorecardResult =
  | { status: "completed"; repo: string; findings: Finding[]; score: number | null; scoredAt: string | null }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "error"; repo: string; findings: []; note: string };

type ScorecardCheck = { name?: string; score?: number; reason?: string; documentation?: { short?: string; url?: string } };
type ScorecardBody = { date?: string; score?: number; checks?: ScorecardCheck[] };

/**
 * The checks worth a finding, with the score below which they report and the
 * severity they report at. Others (Fuzzing, CII-Best-Practices, License,
 * Contributors, Packaging, CI-Tests, Maintained, Webhooks) describe project
 * maturity more than the customer's exposure, so they're left out.
 */
const REPORTED: Record<string, { below: number; severity: Finding["severity"]; fix: string }> = {
  "Dangerous-Workflow": {
    below: 10,
    severity: "high",
    fix: "Remove the untrusted-input patterns Scorecard names from your GitHub Actions workflows, such as pull_request_target jobs that check out the pull request code.",
  },
  "Token-Permissions": {
    below: 5,
    severity: "medium",
    fix: "Set permissions at the top of each workflow to read-only, and grant write scopes only to the jobs that need them.",
  },
  "Branch-Protection": {
    below: 5,
    severity: "medium",
    fix: "Protect the default branch: require pull requests, at least one review and passing status checks, and block force-pushes.",
  },
  "Code-Review": { below: 5, severity: "medium", fix: "Require a second person to approve changes before they merge to the default branch." },
  Vulnerabilities: { below: 10, severity: "medium", fix: "Update the dependencies with known vulnerabilities that Scorecard lists (OSV data)." },
  "Binary-Artifacts": { below: 10, severity: "medium", fix: "Remove checked-in executables and build them from source in CI instead." },
  "Pinned-Dependencies": {
    below: 5,
    severity: "low",
    fix: "Pin GitHub Actions and container images to a full commit SHA or digest, and use lockfiles for package installs.",
  },
  "Dependency-Update-Tool": { below: 10, severity: "low", fix: "Turn on Dependabot or Renovate so dependency updates arrive as pull requests." },
  "Security-Policy": { below: 10, severity: "low", fix: "Add a SECURITY.md saying how to report a vulnerability to you." },
  SAST: { below: 5, severity: "low", fix: "Run a static analysis tool, such as CodeQL, on every pull request." },
  "Signed-Releases": { below: 5, severity: "low", fix: "Sign your release artefacts, for example with Sigstore, so users can verify them." },
};

export function scorecardFindings(repo: string, body: ScorecardBody): Finding[] {
  const findings: Finding[] = [];
  for (const check of body.checks ?? []) {
    const rule = check.name ? REPORTED[check.name] : undefined;
    if (!rule || typeof check.score !== "number" || check.score < 0 || check.score >= rule.below) continue;
    findings.push({
      checkId: `scorecard.${check.name!.toLowerCase()}:${repo}`,
      severity: rule.severity,
      title: `OpenSSF Scorecard: ${check.name} scored ${check.score}/10 for ${repo}`,
      detail: `${check.reason ?? "Below the recommended score."}${check.documentation?.url ? ` See ${check.documentation.url}` : ""}`,
      remediation: rule.fix,
    });
  }
  return findings;
}

export async function runScorecard(input: { githubRepo: string }, fetchImpl: typeof fetch = fetch): Promise<ScorecardResult> {
  const repo = input.githubRepo;
  if (!isValidGithubRepo(repo)) return { status: "error", repo, findings: [], note: "githubRepo must look like 'owner/repo'." };

  // Public or not, from GitHub itself, before the name goes anywhere else.
  try {
    const auth = await resolveGithubAuth(repo);
    const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "HebridesCyberBot/1.0" };
    if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
    const gh = await fetchImpl(`${GITHUB_API}/repos/${repo}`, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (gh.status === 404) {
      return { status: "not_applicable", repo, findings: [], note: "Repository not visible as public on GitHub, so Scorecard (public repositories only) was not asked." };
    }
    if (!gh.ok) return { status: "error", repo, findings: [], note: `GitHub responded ${gh.status} when checking whether the repository is public.` };
    const meta = (await gh.json()) as { private?: boolean };
    if (meta.private !== false) {
      return { status: "not_applicable", repo, findings: [], note: "Private repository: Scorecard only scores public repositories, and the name was not sent to it." };
    }
  } catch (err) {
    return { status: "error", repo, findings: [], note: `Could not check the repository on GitHub: ${(err as Error).message}` };
  }

  try {
    const res = await fetchImpl(`${SCORECARD_API}/${repo}`, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (res.status === 404) return { status: "not_applicable", repo, findings: [], note: "OpenSSF Scorecard has not published a result for this repository yet." };
    if (!res.ok) return { status: "error", repo, findings: [], note: `Scorecard API responded ${res.status}.` };
    const body = (await res.json()) as ScorecardBody;
    if (!Array.isArray(body.checks)) return { status: "error", repo, findings: [], note: "Scorecard response had no checks." };
    return {
      status: "completed",
      repo,
      findings: scorecardFindings(repo, body),
      score: typeof body.score === "number" ? body.score : null,
      scoredAt: body.date ?? null,
    };
  } catch (err) {
    return { status: "error", repo, findings: [], note: `Scorecard lookup failed: ${(err as Error).message}` };
  }
}
