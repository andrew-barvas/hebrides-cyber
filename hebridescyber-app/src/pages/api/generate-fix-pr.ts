// POST /api/generate-fix-pr — the "fix it" half of the product, scoped
// responsibly: turns a scan's findings into a real GitHub pull request
// adding a concrete SECURITY-FIXES.md with copy-pasteable snippets
// (src/lib/remediation.ts), rather than silently rewriting the customer's
// live config. A human still reviews and merges — that's the point, not a
// limitation.
//
// Requires GitHub access to whichever repo it's used against, with
// contents:write and pull-requests:write. Resolved per-request through
// src/lib/githubApp.ts's resolveGithubAuth(): a GitHub App installation
// token if the customer has installed the App on this repo, else the
// shared GITHUB_PAT — see that module's header for the blast-radius
// reasoning behind preferring the App path. Whichever path applies, the
// customer must have granted access first (installed the App, or added the
// Hebrides Cyber bot account as a collaborator for the PAT path).
//
// Rebuilt as a Next.js API route alongside run-scan — see that file's header
// for why.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { buildRemediationMarkdown } from "@/lib/remediation";
import { CONFIG_TARGETS, missingRemediableHeaders, type DesiredHeader } from "@/lib/configFixes";
import type { Finding } from "@/lib/scanners";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { lookupOsvFixInfo } from "@/lib/scanners/osv";
import { resolveGithubAuth } from "@/lib/githubApp";
import { checkRateLimit } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";

const bodySchema = z.object({
  scanId: z.string().min(1, "scanId is required"),
  githubRepo: z.string().regex(/^[\w.-]+\/[\w.-]+$/, "githubRepo must look like 'owner/repo'"),
  baseBranch: z.string().optional().default("main"),
});

const githubApi = "https://api.github.com";

function ghHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Remediation PRs can only be requested from a logged-in session, not with an API key." });
  }

  // Pro and up ("Dependency & CI/CD scanning" on /pricing). Connecting a repo
  // is already Pro-gated, but a connection outlives a downgrade or a cancelled
  // subscription, so the plan is checked here too, when the PR is opened.
  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") {
    return res.status(403).json({ error: "Remediation pull requests are a Pro-and-up feature.", code: "plan_required" });
  }

  // E-12 (docs/ENHANCEMENTS.md): real GitHub API calls per request, uncapped
  // before this.
  const limit = await checkRateLimit(caller.ownerId, "generate-fix-pr");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { scanId, githubRepo, baseBranch } = parsed;

  // The repo must be one the caller connected. Without this, the shared
  // GITHUB_PAT fallback in resolveGithubAuth would let any signed-in user
  // open branches and PRs on any repository that token can reach.
  const { data: connection, error: connectionError } = await supabaseAdmin
    .from("repo_connections")
    .select("github_repo")
    .eq("owner", caller.ownerId)
    .eq("github_repo", githubRepo)
    .limit(1)
    .maybeSingle();
  if (connectionError) return res.status(500).json({ error: "Could not verify the repository connection" });
  if (!connection) return res.status(403).json({ error: "That repository isn't connected to your account" });

  const { token } = await resolveGithubAuth(githubRepo);
  if (!token) {
    return res.status(501).json({ error: "No GitHub access configured for this deployment (neither a GitHub App installation nor GITHUB_PAT) — see .env.example." });
  }

  const { data: scan, error: scanError } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url")
    .eq("id", scanId)
    .maybeSingle();
  if (scanError || !scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "You do not own this scan" });

  const { data: result, error: resultError } = await supabaseAdmin
    .from("scan_results")
    .select("results, score")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (resultError || !result) return res.status(404).json({ error: "No results for this scan yet" });

  const findings = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const markdown = buildRemediationMarkdown(scan.target_url, findings, result.score ?? null);

  let prUrl: string;
  try {
    prUrl = await openRemediationPr(githubRepo, baseBranch, scanId, markdown, token);
  } catch (err) {
    return res.status(502).json({ error: `GitHub API error: ${(err as Error).message}` });
  }

  // Dependency version bumps are a second, independent PR (see
  // openDependencyBumpPr's header comment for why) opened on a best-effort
  // basis: it must never turn an otherwise-successful recommendations PR
  // into a failed request. If it can't run (no package.json, nothing safe to
  // bump, or a GitHub error), that's reported alongside the 200, not thrown.
  let dependencyBumpPrUrl: string | undefined;
  let dependencyBumpError: string | undefined;
  try {
    const bumpResult = await openDependencyBumpPr(githubRepo, baseBranch, scanId, token);
    if (bumpResult) dependencyBumpPrUrl = bumpResult.prUrl;
  } catch (err) {
    dependencyBumpError = `dependency bump PR failed: ${(err as Error).message}`;
  }

  // Config-header fixes — a third, independent best-effort PR, same contract
  // as the dependency bump above: it must never turn an otherwise-successful
  // request into a failure. It only acts when the scan's structured header
  // analysis shows a remediable header missing on the live site AND the repo
  // has a config file it can edit safely (see src/lib/configFixes.ts).
  let configFixPrUrl: string | undefined;
  let configFixError: string | undefined;
  let configFixNote: string | undefined;
  try {
    const headers = (result.results as { headers?: { status?: string; owasp?: { headers?: Array<{ name: string; present: boolean }> } } }).headers;
    const desired = headers?.status === "checked" && headers.owasp?.headers ? missingRemediableHeaders(headers.owasp.headers) : [];
    if (desired.length > 0) {
      const outcome = await openConfigFixPr(githubRepo, baseBranch, scanId, desired, token);
      if (outcome.prUrl) configFixPrUrl = outcome.prUrl;
      else if (outcome.note) configFixNote = outcome.note;
    }
  } catch (err) {
    configFixError = `config fix PR failed: ${(err as Error).message}`;
  }

  return res.status(200).json({ ok: true, prUrl, dependencyBumpPrUrl, dependencyBumpError, configFixPrUrl, configFixError, configFixNote });
}

async function openRemediationPr(repo: string, baseBranch: string, scanId: string, markdown: string, token: string): Promise<string> {
  // 1. Get the SHA of the base branch's HEAD commit.
  const baseRefRes = await fetch(`${githubApi}/repos/${repo}/git/ref/heads/${baseBranch}`, { headers: ghHeaders(token) });
  if (!baseRefRes.ok) throw new Error(`could not read base branch (${baseRefRes.status}) — check that the GitHub App is installed (or GITHUB_PAT's bot is a collaborator) on ${repo}`);
  const baseRef = (await baseRefRes.json()) as { object: { sha: string } };

  // 2. Create a new branch from that commit.
  const branchName = `hebridescyber/security-fixes-${scanId.slice(0, 8)}`;
  const createRefRes = await fetch(`${githubApi}/repos/${repo}/git/refs`, {
    method: "POST",
    headers: ghHeaders(token),
    body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: baseRef.object.sha }),
  });
  if (!createRefRes.ok && createRefRes.status !== 422) {
    // 422 usually means the branch already exists (e.g. re-running for the same scan) — safe to continue.
    throw new Error(`could not create branch (${createRefRes.status})`);
  }

  // 3. Create (or update) SECURITY-FIXES.md on that branch.
  const path = "SECURITY-FIXES.md";
  const existingRes = await fetch(`${githubApi}/repos/${repo}/contents/${path}?ref=${branchName}`, { headers: ghHeaders(token) });
  const existingSha = existingRes.ok ? ((await existingRes.json()) as { sha: string }).sha : undefined;

  const putRes = await fetch(`${githubApi}/repos/${repo}/contents/${path}`, {
    method: "PUT",
    headers: ghHeaders(token),
    body: JSON.stringify({
      message: "Add Hebrides Cyber security fix recommendations",
      content: Buffer.from(markdown, "utf-8").toString("base64"),
      branch: branchName,
      ...(existingSha ? { sha: existingSha } : {}),
    }),
  });
  if (!putRes.ok) throw new Error(`could not write ${path} (${putRes.status})`);

  // 4. Open the PR (or return the existing one if it's already open).
  const prRes = await fetch(`${githubApi}/repos/${repo}/pulls`, {
    method: "POST",
    headers: ghHeaders(token),
    body: JSON.stringify({
      title: "Security fixes from Hebrides Cyber scan",
      head: branchName,
      base: baseBranch,
      body: "Automated remediation suggestions — see SECURITY-FIXES.md. Nothing else in this repo was touched.",
    }),
  });
  if (prRes.status === 422) {
    const listRes = await fetch(`${githubApi}/repos/${repo}/pulls?head=${repo.split("/")[0]}:${branchName}`, { headers: ghHeaders(token) });
    const list = (await listRes.json()) as Array<{ html_url: string }>;
    if (list[0]) return list[0].html_url;
    throw new Error("PR creation returned 422 and no existing PR was found");
  }
  if (!prRes.ok) throw new Error(`could not open PR (${prRes.status})`);
  const pr = (await prRes.json()) as { html_url: string };
  return pr.html_url;
}

// ---------------------------------------------------------------------------
// Dependency version bumps — the half of "automated remediation PRs for safe
// minor/patch updates" that didn't exist before (openRemediationPr above only
// ever wrote a recommendations file, never touched a real dependency
// version). This is deliberately a SECOND, independent PR on its own branch,
// not folded into the SECURITY-FIXES.md one: that PR is a zero-risk read of
// recommendations a human skims; this one is a real change to a manifest
// file that could, if the safety gate below is ever wrong, break a build.
// Keeping them separate means a customer can ignore/close the bump PR
// without losing the recommendations one, and the reverse.
//
// SAFETY GATE (see also lookupOsvFixInfo's doc comment in scanners/osv.ts):
// a dependency is only bumped if ALL of the following hold —
//   1. OSV.dev names a specific, concrete (X.Y.Z, no prerelease/build tag)
//      fixed version for every vulnerability it reports at the currently
//      declared floor version. Any vuln without one (still unpatched
//      upstream, or only a `last_affected` event) means the whole lookup is
//      treated as "no safe target" — see lookupOsvFixInfo's own comment. A
//      fixed version that isn't plain X.Y.Z is skipped here (parseConcreteVersion).
//   2. The fixed version's major component matches the currently declared
//      version's major component. A major-version difference is never
//      auto-bumped, full stop — that's a human's call, not this feature's.
//   3. The declared range's own syntax is unambiguous: exactly `X.Y.Z`,
//      `^X.Y.Z`, or `~X.Y.Z` (parseDeclaredVersion). Compound ranges
//      (">=1.2.0 <2.0.0", "1.x || 2.x", etc.) are skipped outright — there is
//      no single unambiguous "bump the declared range" edit for those, and
//      dependencyManifest.ts's own minVersionFromRange approximation (which
//      silently drops everything after the first dotted version) is not
//      rigorous enough to reuse for a write path.
//   4. The declared range doesn't already permit the fixed version under
//      npm's own ^/~ resolution rules (rangeAlreadyPermits) — if it does,
//      the real fix is `npm install`, not a package.json edit, and
//      committing a no-op diff would be actively misleading.
//
// Anything that fails one of these gates is simply left out of this PR. It
// may still show up in the SECURITY-FIXES.md PR's recommendations (built
// from the scan's stored findings, which is a separate data source from the
// fresh package.json read here) — that's fine, that PR's whole point is
// "things a human should look at," including ones this feature won't touch.

type PackageJsonShape = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

type DependencySection = "dependencies" | "devDependencies";

type DependencyBumpCandidate = {
  name: string;
  section: DependencySection;
  oldRange: string;
  newRange: string;
  fixedVersion: string;
  cveIds: string[];
  osvIds: string[];
};

type DeclaredVersion = { prefix: "" | "^" | "~"; major: number; minor: number; patch: number; raw: string };
type ConcreteVersion = { major: number; minor: number; patch: number };

// Same ceiling as dependencyManifest.ts's MAX_PACKAGES_QUERIED, and for the
// same reason: bound worst-case OSV.dev round-trips for a pathological
// package.json rather than firing an unbounded number of requests.
const MAX_PACKAGES_QUERIED = 150;
const QUERY_CONCURRENCY = 10;

// 2026-09-19 incident: this whole request runs synchronously inside one
// Azure Static Web Apps Function invocation (see run-scan.ts's header for
// why that execution model already burned this app once for the scan
// pipeline). Each OSV.dev lookup below has its own 5s timeout
// (OSV_TIMEOUT_MS in scanners/osv.ts) but nothing previously bounded the
// TOTAL time this loop could run — a real repo's package.json (dozens of
// dependencies) at QUERY_CONCURRENCY=10 could take 150/10 * up-to-5s well
// past the platform's own execution ceiling, which kills the function
// before openRemediationPr/openDependencyBumpPr's own try/catch ever gets a
// chance to run — surfacing to the browser as a bare 502 with no JSON body,
// not the app's own graceful error response. This deadline makes the OSV
// phase itself best-effort in time, not just in outcome: once it's passed,
// remaining packages are treated as "no fix found" (skipped, not bumped)
// rather than letting the loop keep going toward the platform's hard kill.
const OSV_LOOKUP_DEADLINE_MS = 8_000;

/** Accepts only `X.Y.Z`, `^X.Y.Z`, or `~X.Y.Z` — anything else (compound
 *  ranges, `>=`, `||`, tags, workspace/git specifiers) returns null and the
 *  caller skips that dependency. See the module header for why this is
 *  stricter than dependencyManifest.ts's read-only approximation. */
function parseDeclaredVersion(range: string): DeclaredVersion | null {
  const m = /^(\^|~)?(\d+)\.(\d+)\.(\d+)$/.exec(range.trim());
  if (!m) return null;
  return { prefix: (m[1] as "^" | "~" | undefined) ?? "", major: Number(m[2]), minor: Number(m[3]), patch: Number(m[4]), raw: range.trim() };
}

function parseConcreteVersion(v: string): ConcreteVersion | null {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

function gte(a: ConcreteVersion, b: ConcreteVersion): boolean {
  if (a.major !== b.major) return a.major > b.major;
  if (a.minor !== b.minor) return a.minor > b.minor;
  return a.patch >= b.patch;
}

/** True if npm's own ^/~ resolution of the declared range would already
 *  reach `fixed` — i.e. there is nothing to edit in package.json, the real
 *  fix is `npm install`/a lockfile refresh. Mirrors npm's actual caret/tilde
 *  semantics (caret holds the leftmost non-zero component fixed; tilde holds
 *  major.minor fixed; a bare version permits only itself). */
function rangeAlreadyPermits(declared: DeclaredVersion, fixed: ConcreteVersion): boolean {
  if (!gte(fixed, declared)) return true; // declared floor is already >= fixed; nothing to do
  if (declared.prefix === "") return fixed.major === declared.major && fixed.minor === declared.minor && fixed.patch === declared.patch;
  if (declared.prefix === "~") return fixed.major === declared.major && fixed.minor === declared.minor;
  // caret: allowed range depends on the leftmost non-zero component (npm's own rule for 0.x ranges)
  if (declared.major > 0) return fixed.major === declared.major;
  if (declared.minor > 0) return fixed.major === 0 && fixed.minor === declared.minor;
  return fixed.major === 0 && fixed.minor === 0 && fixed.patch === declared.patch;
}

/**
 * `deadlineAt`/`fallback` bound total wall-clock time: once Date.now()
 * passes deadlineAt, any item not yet started is passed to `fallback(item)`
 * instead of `fn(item)` — see OSV_LOOKUP_DEADLINE_MS's comment above for why
 * this matters on a platform that kills the whole request past its own
 * ceiling. `fallback` takes the item (not a static value) so it can still
 * carry that item's own data through unchanged.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
  deadlineAt?: number,
  fallback?: (item: T) => R
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const i = index++;
      if (deadlineAt !== undefined && Date.now() > deadlineAt && fallback) {
        results[i] = fallback(items[i]);
        continue;
      }
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

/**
 * Exported for local verification without a GitHub token/repo — mirrors
 * dependencyManifest.ts's buildDependencyFindings in that respect: the part
 * of this feature that must be provable against real OSV.dev data alone,
 * with no network access to GitHub required.
 */
export async function buildDependencyBumpPlan(pkg: PackageJsonShape): Promise<{
  bumps: DependencyBumpCandidate[];
  skipped: { majorBumpRequired: string[]; noFixAvailable: string[]; alreadySatisfied: string[]; unsupportedRange: string[] };
}> {
  const sections: DependencySection[] = ["dependencies", "devDependencies"];
  const entries: Array<{ name: string; range: string; section: DependencySection }> = [];
  for (const section of sections) {
    for (const [name, range] of Object.entries(pkg[section] ?? {})) {
      entries.push({ name, range, section });
    }
  }

  const skipped = { majorBumpRequired: [] as string[], noFixAvailable: [] as string[], alreadySatisfied: [] as string[], unsupportedRange: [] as string[] };
  const queryable = entries.slice(0, MAX_PACKAGES_QUERIED);
  const parsed = queryable.map((e) => ({ ...e, declared: parseDeclaredVersion(e.range) }));

  for (const p of parsed) {
    if (!p.declared) skipped.unsupportedRange.push(`${p.name}@${p.range}`);
  }

  const withDeclared = parsed.filter((p): p is typeof p & { declared: DeclaredVersion } => p.declared !== null);

  const deadlineAt = Date.now() + OSV_LOOKUP_DEADLINE_MS;
  const checked = await mapWithConcurrency(
    withDeclared,
    QUERY_CONCURRENCY,
    async (p) => ({
      ...p,
      fixInfo: await lookupOsvFixInfo("npm", p.name, `${p.declared.major}.${p.declared.minor}.${p.declared.patch}`),
    }),
    deadlineAt,
    // Deadline fallback: treated identically to "nothing OSV flagged" (see
    // the noFixAvailable check just below) — never incorrectly reported as
    // vulnerable just because there wasn't time left to check it. Keeps
    // this item's own name/section/declared intact, only fixInfo is stubbed.
    (p) => ({ ...p, fixInfo: { cveIds: [], osvIds: [], fixedVersion: null } })
  );

  const bumps: DependencyBumpCandidate[] = [];
  for (const c of checked) {
    if (c.fixInfo.fixedVersion === null) {
      // Only worth noting if OSV actually flagged something for this
      // version — an empty result just means this dependency isn't
      // vulnerable at all, which isn't a "skip," it's a non-event.
      if (c.fixInfo.cveIds.length > 0 || c.fixInfo.osvIds.length > 0) {
        skipped.noFixAvailable.push(`${c.name}@${c.declared.raw}`);
      }
      continue;
    }

    const fixed = parseConcreteVersion(c.fixInfo.fixedVersion);
    if (!fixed) {
      // Load-bearing: lookupOsvFixInfo can name a prerelease or
      // ecosystem-suffixed fix ("2.0.0-rc.1") since it learned ECOSYSTEM
      // ranges; this write path only ever bumps to a plain X.Y.Z (gate 1).
      skipped.noFixAvailable.push(`${c.name}@${c.declared.raw}`);
      continue;
    }

    if (fixed.major !== c.declared.major) {
      skipped.majorBumpRequired.push(`${c.name} (${c.declared.raw} → ${c.fixInfo.fixedVersion})`);
      continue;
    }

    if (rangeAlreadyPermits(c.declared, fixed)) {
      skipped.alreadySatisfied.push(`${c.name} (${c.declared.raw} already permits ${c.fixInfo.fixedVersion})`);
      continue;
    }

    bumps.push({
      name: c.name,
      section: c.section,
      oldRange: c.declared.raw,
      newRange: `${c.declared.prefix}${c.fixInfo.fixedVersion}`,
      fixedVersion: c.fixInfo.fixedVersion,
      cveIds: c.fixInfo.cveIds,
      osvIds: c.fixInfo.osvIds,
    });
  }

  return { bumps, skipped };
}

/** Sniffs the indentation package.json already uses so re-serialising it
 *  doesn't produce a whole-file reformat diff. Falls back to 2 spaces, npm's
 *  own default, if nothing is found (e.g. a single-line/minified file). */
function detectIndent(raw: string): string {
  const m = raw.match(/\n([ \t]+)"/);
  return m ? m[1] : "  ";
}

function buildDependencyBumpPrBody(bumps: DependencyBumpCandidate[]): string {
  const rows = bumps
    .map((b) => {
      const cves = b.cveIds.length ? b.cveIds.join(", ") : "—";
      const advisories = b.osvIds.map((id) => `https://osv.dev/vulnerability/${id}`).join(" ") || "—";
      return `| \`${b.name}\` | \`${b.oldRange}\` | \`${b.newRange}\` | ${cves} | ${advisories} |`;
    })
    .join("\n");

  return `# Hebrides Cyber — Automated dependency version bumps

**This PR has not been reviewed by a human and has not been run against your test suite.**
Do not merge until your own CI/tests pass on this branch. Only \`package.json\`'s
declared version ranges were changed — no lockfile was touched, so run your
usual install step (e.g. \`npm install\`) on this branch to refresh it before
relying on the result.

Every bump below passed a conservative safety gate: OSV.dev names a specific
patched version, that version does **not** require a major-version bump from
what's currently declared, and the currently declared range didn't already
permit it (this file lists changes an \`npm install\` alone would not have
made).

| Package | Old range | New range | CVE(s) | Advisory |
|---|---|---|---|---|
${rows}

Nothing else in this repo was touched.

---

*Generated automatically from a Hebrides Cyber Security Score scan. See
https://hebridescyber.co.uk for details, or reply to your scan email with
questions.*
`;
}

/**
 * Opens a second PR, independent of openRemediationPr's SECURITY-FIXES.md
 * one, bumping only the dependencies that pass buildDependencyBumpPlan's
 * safety gate. Returns null (not an error) when there's no package.json, it
 * doesn't parse, or nothing qualifies — all expected, non-exceptional
 * outcomes for a repo that simply has nothing safe to bump right now.
 */
export async function openDependencyBumpPr(repo: string, baseBranch: string, scanId: string, token: string): Promise<{ prUrl: string; bumps: DependencyBumpCandidate[] } | null> {
  const pkgRes = await fetch(`${githubApi}/repos/${repo}/contents/package.json?ref=${baseBranch}`, { headers: ghHeaders(token) });
  if (!pkgRes.ok) return null; // no package.json at the repo root — nothing for this feature to do
  const pkgFile = (await pkgRes.json()) as { content?: string; encoding?: string };
  if (!pkgFile.content) return null;

  const rawPackageJson = Buffer.from(pkgFile.content, (pkgFile.encoding as BufferEncoding) ?? "base64").toString("utf-8");
  let pkg: PackageJsonShape;
  try {
    pkg = JSON.parse(rawPackageJson) as PackageJsonShape;
  } catch {
    return null; // malformed package.json isn't this feature's problem to fix
  }

  const { bumps } = await buildDependencyBumpPlan(pkg);
  if (bumps.length === 0) return null;

  // Re-parse fresh rather than reusing `pkg` so nothing buildDependencyBumpPlan
  // might read (but shouldn't mutate) can ever leak into the committed diff.
  const updated = JSON.parse(rawPackageJson) as Record<string, Record<string, string> | unknown>;
  for (const b of bumps) {
    const section = (updated[b.section] ?? {}) as Record<string, string>;
    section[b.name] = b.newRange;
    updated[b.section] = section;
  }
  const indent = detectIndent(rawPackageJson);
  const newRaw = JSON.stringify(updated, null, indent) + (rawPackageJson.endsWith("\n") ? "\n" : "");

  // 1. Base branch HEAD sha.
  const baseRefRes = await fetch(`${githubApi}/repos/${repo}/git/ref/heads/${baseBranch}`, { headers: ghHeaders(token) });
  if (!baseRefRes.ok) throw new Error(`could not read base branch (${baseRefRes.status}) — check that the GitHub App is installed (or GITHUB_PAT's bot is a collaborator) on ${repo}`);
  const baseRef = (await baseRefRes.json()) as { object: { sha: string } };

  // 2. A branch separate from openRemediationPr's — see module header.
  const branchName = `hebridescyber/dependency-bumps-${scanId.slice(0, 8)}`;
  const createRefRes = await fetch(`${githubApi}/repos/${repo}/git/refs`, {
    method: "POST",
    headers: ghHeaders(token),
    body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: baseRef.object.sha }),
  });
  if (!createRefRes.ok && createRefRes.status !== 422) {
    throw new Error(`could not create branch (${createRefRes.status})`);
  }

  // 3. Commit the bumped package.json on that branch.
  const path = "package.json";
  const existingRes = await fetch(`${githubApi}/repos/${repo}/contents/${path}?ref=${branchName}`, { headers: ghHeaders(token) });
  const existingSha = existingRes.ok ? ((await existingRes.json()) as { sha: string }).sha : undefined;

  const putRes = await fetch(`${githubApi}/repos/${repo}/contents/${path}`, {
    method: "PUT",
    headers: ghHeaders(token),
    body: JSON.stringify({
      message: `Bump ${bumps.length} dependenc${bumps.length === 1 ? "y" : "ies"} to patch known CVEs`,
      content: Buffer.from(newRaw, "utf-8").toString("base64"),
      branch: branchName,
      ...(existingSha ? { sha: existingSha } : {}),
    }),
  });
  if (!putRes.ok) throw new Error(`could not write ${path} (${putRes.status})`);

  // 4. Open the PR (or return the existing one if it's already open).
  const prRes = await fetch(`${githubApi}/repos/${repo}/pulls`, {
    method: "POST",
    headers: ghHeaders(token),
    body: JSON.stringify({
      title: `Security: bump ${bumps.length} dependenc${bumps.length === 1 ? "y" : "ies"} (Hebrides Cyber)`,
      head: branchName,
      base: baseBranch,
      body: buildDependencyBumpPrBody(bumps),
    }),
  });
  if (prRes.status === 422) {
    const listRes = await fetch(`${githubApi}/repos/${repo}/pulls?head=${repo.split("/")[0]}:${branchName}`, { headers: ghHeaders(token) });
    const list = (await listRes.json()) as Array<{ html_url: string }>;
    if (list[0]) return { prUrl: list[0].html_url, bumps };
    throw new Error("dependency-bump PR creation returned 422 and no existing PR was found");
  }
  if (!prRes.ok) throw new Error(`could not open dependency-bump PR (${prRes.status})`);
  const pr = (await prRes.json()) as { html_url: string };
  return { prUrl: pr.html_url, bumps };
}

// ---------------------------------------------------------------------------
// Config-header fixes — adds the no-regret security headers the scan found
// missing on the live site to whichever config file the repo actually uses,
// as a THIRD independent PR on its own branch (same reasoning as the
// dependency-bump PR: a zero-to-low-risk, reviewable change, kept separate so
// it never entangles the recommendations PR). Pure editing logic lives in
// src/lib/configFixes.ts; this only fetches, commits and opens the PR. It
// tries the config targets in priority order (safe structured data first, the
// Next.js code config last) and acts on the FIRST that yields a safe edit;
// files it understands but can't edit safely contribute a skip reason.
// ---------------------------------------------------------------------------
async function fetchRepoFile(repo: string, path: string, ref: string, token: string): Promise<string | null> {
  const res = await fetch(`${githubApi}/repos/${repo}/contents/${encodeURIComponent(path)}?ref=${ref}`, { headers: ghHeaders(token) });
  if (!res.ok) return null;
  const file = (await res.json()) as { content?: string; encoding?: string };
  if (!file.content) return null;
  return Buffer.from(file.content, (file.encoding as BufferEncoding) ?? "base64").toString("utf-8");
}

export async function openConfigFixPr(
  repo: string,
  baseBranch: string,
  scanId: string,
  desired: DesiredHeader[],
  token: string,
): Promise<{ prUrl?: string; note?: string }> {
  // Find the first config file present that we can edit safely.
  let chosen: { path: string; updated: string; applied: string[] } | null = null;
  const skips: string[] = [];
  for (const target of CONFIG_TARGETS) {
    const raw = await fetchRepoFile(repo, target.path, baseBranch, token);
    if (raw === null) continue; // not in this repo
    const result = target.edit(raw, desired);
    if (result.status === "edited") {
      chosen = { path: target.path, updated: result.updated, applied: result.applied };
      break;
    }
    if (result.status === "skip") skips.push(`${target.path}: ${result.reason}`);
    // "noop" — the file already sets these headers, so editing another file
    // wouldn't change what the live site serves; stop and report.
    if (result.status === "noop") return { note: `${target.path} already sets these headers — the gap is likely added downstream (a CDN or proxy stripping them), which a repo change can't fix.` };
  }
  if (!chosen) {
    if (skips.length > 0) return { note: `No config file could be edited safely: ${skips.join("; ")}.` };
    return { note: "No supported header-config file (staticwebapp.config.json, vercel.json, netlify.toml, _headers, next.config.*) found in the repo root." };
  }

  // 1. Base branch HEAD sha.
  const baseRefRes = await fetch(`${githubApi}/repos/${repo}/git/ref/heads/${baseBranch}`, { headers: ghHeaders(token) });
  if (!baseRefRes.ok) throw new Error(`could not read base branch (${baseRefRes.status}) — check that the GitHub App is installed (or GITHUB_PAT's bot is a collaborator) on ${repo}`);
  const baseRef = (await baseRefRes.json()) as { object: { sha: string } };

  // 2. A branch separate from the other two fix PRs.
  const branchName = `hebridescyber/security-headers-${scanId.slice(0, 8)}`;
  const createRefRes = await fetch(`${githubApi}/repos/${repo}/git/refs`, {
    method: "POST",
    headers: ghHeaders(token),
    body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: baseRef.object.sha }),
  });
  if (!createRefRes.ok && createRefRes.status !== 422) {
    throw new Error(`could not create branch (${createRefRes.status})`);
  }

  // 3. Commit the edited config file on that branch.
  const existingRes = await fetch(`${githubApi}/repos/${repo}/contents/${encodeURIComponent(chosen.path)}?ref=${branchName}`, { headers: ghHeaders(token) });
  const existingSha = existingRes.ok ? ((await existingRes.json()) as { sha: string }).sha : undefined;

  const putRes = await fetch(`${githubApi}/repos/${repo}/contents/${encodeURIComponent(chosen.path)}`, {
    method: "PUT",
    headers: ghHeaders(token),
    body: JSON.stringify({
      message: `Add ${chosen.applied.length} missing security header${chosen.applied.length === 1 ? "" : "s"} to ${chosen.path}`,
      content: Buffer.from(chosen.updated, "utf-8").toString("base64"),
      branch: branchName,
      ...(existingSha ? { sha: existingSha } : {}),
    }),
  });
  if (!putRes.ok) throw new Error(`could not write ${chosen.path} (${putRes.status})`);

  // 4. Open the PR (or return the existing one if it's already open).
  const prRes = await fetch(`${githubApi}/repos/${repo}/pulls`, {
    method: "POST",
    headers: ghHeaders(token),
    body: JSON.stringify({
      title: `Security: add ${chosen.applied.length} missing header${chosen.applied.length === 1 ? "" : "s"} (Hebrides Cyber)`,
      head: branchName,
      base: baseBranch,
      body: buildConfigFixPrBody(chosen.path, chosen.applied),
    }),
  });
  if (prRes.status === 422) {
    const listRes = await fetch(`${githubApi}/repos/${repo}/pulls?head=${repo.split("/")[0]}:${branchName}`, { headers: ghHeaders(token) });
    const list = (await listRes.json()) as Array<{ html_url: string }>;
    if (list[0]) return { prUrl: list[0].html_url };
    throw new Error("config-fix PR creation returned 422 and no existing PR was found");
  }
  if (!prRes.ok) throw new Error(`could not open config-fix PR (${prRes.status})`);
  const pr = (await prRes.json()) as { html_url: string };
  return { prUrl: pr.html_url };
}

export function buildConfigFixPrBody(path: string, applied: string[]): string {
  return `# Hebrides Cyber — security header fixes

Adds the following security header${applied.length === 1 ? "" : "s"} to \`${path}\`, found missing on the live site by the scan:

${applied.map((h) => `- \`${h}\``).join("\n")}

Only \`${path}\` is changed. These are conservative, no-regret defaults (for example \`Strict-Transport-Security\` without \`preload\`, \`X-Frame-Options: SAMEORIGIN\` rather than \`DENY\`) — review them against your own requirements, and do not merge until your own CI and tests pass on this branch. Content-Security-Policy and cookie flags are intentionally not auto-edited; see the scan's remediation guidance for those.`;
}
