// Hebrides Cyber Security Scan — GitHub Action entry point.
//
// Deliberately dependency-free: no @actions/core, no @actions/github, no
// npm install step, no node_modules to commit. Just the GitHub Actions
// runner's documented raw protocol (INPUT_* env vars, ::error::/::notice::
// workflow commands, appending to $GITHUB_OUTPUT/$GITHUB_STEP_SUMMARY) and
// Node 20's built-in fetch. A small action doing one HTTP call doesn't
// justify the dependency surface, and this way there's nothing to `npm ci`
// before the action can run.
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Has the owner triaged this finding — accepted the risk (or authorised it),
 * marked it a false positive, or snoozed it — with that decision still in
 * effect? The API only reports triage that's active, but the expiry is
 * checked here too so a report fetched just before a snooze ends can't wave
 * a finding through after it.
 */
function isTriaged(finding, now = Date.now()) {
  const triage = finding && finding.triage;
  if (!triage || typeof triage !== "object" || !triage.state) return false;
  if (triage.expires_at === null || triage.expires_at === undefined) return true;
  const expires = Date.parse(triage.expires_at);
  return !Number.isNaN(expires) && expires > now;
}

/**
 * The findings that decide pass/fail: new since the previous scan, at or
 * above the threshold, and not triaged by the owner.
 */
function blockingFindings(findings, failOn, now = Date.now()) {
  if (failOn === "none") return [];
  const threshold = SEVERITY_RANK[failOn];
  return (findings || []).filter(
    (f) => f.status === "new" && (SEVERITY_RANK[f.severity] ?? 0) >= threshold && !isTriaged(f, now)
  );
}

// GitHub's documented input->env-var conversion: upper-case, spaces become
// underscores, hyphens are left as literal hyphens (not valid in a shell
// variable name, but perfectly fine as a JS object key via bracket access —
// this is exactly what @actions/core's getInput() hides from you).
function getInput(name, { required = false, defaultValue = "" } = {}) {
  const key = `INPUT_${name.toUpperCase().replace(/ /g, "_")}`;
  const value = (process.env[key] ?? "").trim();
  if (!value) {
    if (required) fail(`Input required and not supplied: ${name}`);
    return defaultValue;
  }
  return value;
}

function appendToFile(envVarName, line) {
  const path = process.env[envVarName];
  if (!path) return; // not running under a real Actions runner (e.g. local test)
  fs.appendFileSync(path, line.endsWith("\n") ? line : `${line}\n`);
}

function setOutput(name, value) {
  appendToFile("GITHUB_OUTPUT", `${name}=${value}`);
}

function notice(message) {
  console.log(`::notice::${message}`);
}

function warning(message) {
  console.log(`::warning::${message}`);
}

function fail(message) {
  console.log(`::error::${message}`);
  process.exitCode = 1;
  throw new ActionFailure(message);
}

class ActionFailure extends Error {}

/**
 * fetch() with a timeout that can't keep the process alive. AbortSignal.
 * timeout()'s internal timer isn't unref'd, so a long timeout (this one is
 * generous on purpose — a full scan can genuinely take a while) leaves Node
 * waiting on that timer even after the request has already finished,
 * instead of exiting the moment the action's work is done.
 */
function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

const POLL_INTERVAL_MS = 5_000;
const POLL_BUDGET_MS = 9 * 60 * 1000; // overall ceiling for the polling phase

/**
 * POST /api/v1/scans queues the scan and returns almost immediately
 * (202 { scan_id, status: "queued" }) rather than the finished report — see
 * that route's header comment for why a synchronous "run the whole check
 * suite inline" design isn't safe on the platform it deploys to. Poll
 * GET /api/v1/scans/{id} (already returns a pending shape with `status`
 * before results exist — no server-side change was needed for this) until
 * status is "completed" or "failed".
 */
async function pollUntilDone(apiBaseUrl, apiKey, scanId) {
  const deadline = Date.now() + POLL_BUDGET_MS;
  while (Date.now() < deadline) {
    const res = await fetchWithTimeout(
      `${apiBaseUrl}/api/v1/scans/${scanId}`,
      { headers: { Authorization: `Bearer ${apiKey}` } },
      15_000
    );
    const body = await res.json().catch(() => null);
    if (!res.ok || !body) {
      fail(`Could not check scan status (HTTP ${res.status}): ${body?.error ?? "no response body"}`);
      return null;
    }
    if (body.status === "completed") return body;
    if (body.status === "failed") {
      fail(`Scan failed while running (scan ${scanId}).`);
      return null;
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  fail(`Scan ${scanId} did not complete within ${Math.round(POLL_BUDGET_MS / 60000)} minutes.`);
  return null;
}

// ---- Dependency check (mode: dependencies) ---------------------------------------
//
// On a pull request: read each changed lockfile on the base and the head,
// send both to POST /api/v1/dependency-diff, and report only the vulnerable
// packages the PR introduces. Needs `actions/checkout` with `fetch-depth: 0`
// (git has to see the base commit). No GitHub App: the comment is posted with
// the workflow's own GITHUB_TOKEN.

const COMMENT_MARKER = "<!-- hebrides-cyber-dependency-check -->";

// Lockfile name -> the manifest that lets its parser tell direct from
// transitive packages. Mirrors LOCKFILES in src/lib/scanners/dependencyLockfiles.ts.
const LOCKFILE_COMPANIONS = {
  "npm-shrinkwrap.json": "package.json",
  "package-lock.json": "package.json",
  "pnpm-lock.yaml": null,
  "yarn.lock": "package.json",
  "poetry.lock": "pyproject.toml",
  "Pipfile.lock": null,
  "composer.lock": "composer.json",
  "go.sum": "go.mod",
  "gradle.lockfile": null,
  "Gemfile.lock": null,
  "Cargo.lock": null,
  "packages.lock.json": null,
};

const baseName = (p) => String(p).split("/").pop();
const dirName = (p) => (String(p).includes("/") ? String(p).slice(0, String(p).lastIndexOf("/") + 1) : "");

/** The supported lockfiles among changed paths (monorepos have several). */
function lockfilesIn(changedPaths) {
  return (changedPaths || []).filter((p) => Object.prototype.hasOwnProperty.call(LOCKFILE_COMPANIONS, baseName(p)) && !String(p).includes("node_modules/"));
}

/** Introduced vulnerable packages at or above the threshold. */
function blockingVulnerabilities(vulnerabilities, failOn) {
  if (failOn === "none") return [];
  const threshold = SEVERITY_RANK[failOn];
  return (vulnerabilities || []).filter((v) => (SEVERITY_RANK[v.severity] ?? 0) >= threshold);
}

const mdEscape = (text) => String(text).replace(/[|\\`*_<>]/g, (c) => `\\${c}`);

/** The PR comment: the introduced vulnerable packages and what to do about each. */
function buildDependencyComment(result, failOn) {
  const vulns = result.vulnerabilities || [];
  const blocking = new Set(blockingVulnerabilities(vulns, failOn));
  const lines = [COMMENT_MARKER, "### Hebrides Cyber — dependency check", ""];

  if (vulns.length === 0 && result.complete) {
    lines.push(`No known-vulnerable packages introduced by this pull request (${result.packages_added} package${result.packages_added === 1 ? "" : "s"} added).`);
  } else if (vulns.length > 0) {
    lines.push(`This pull request introduces **${vulns.length}** known-vulnerable package${vulns.length === 1 ? "" : "s"}${blocking.size ? ` — ${blocking.size} at or above \`${failOn}\`` : ""}.`, "");
    lines.push("| Severity | Package | Advisories | Fixed in | Introduced via |", "|---|---|---|---|---|");
    for (const v of vulns) {
      const ids = v.advisories.map((a) => (a.cve_ids[0] || a.id)).slice(0, 4).join(", ");
      const via = v.direct ? "direct dependency" : v.introduced_via && v.introduced_via.length ? v.introduced_via.join(" → ") : "transitive";
      lines.push(`| ${v.severity}${blocking.has(v) ? " ⛔" : ""} | \`${mdEscape(v.name)}@${mdEscape(v.version)}\`${v.dev ? " (dev)" : ""} | ${mdEscape(ids)} | ${v.fixed_version ? `\`${mdEscape(v.fixed_version)}\`` : "no fix named"} | ${mdEscape(via)} |`);
    }
  }
  if (!result.complete) {
    lines.push("", "**Not everything could be checked:** " + (result.notes || []).join(" "));
    for (const f of result.files || []) if (f.status === "error") lines.push(`- ${f.error}`);
  }
  return lines.join("\n");
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
}

/** File content at a commit, or null if it doesn't exist there. */
function gitShow(commit, path) {
  try {
    return git(["show", `${commit}:${path}`]);
  } catch {
    return null;
  }
}

async function upsertPullRequestComment(token, repo, number, body, apiUrl) {
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" };
  const base = `${apiUrl}/repos/${repo}/issues`;
  const list = await fetchWithTimeout(`${base}/${number}/comments?per_page=100`, { headers }, 15_000);
  if (!list.ok) throw new Error(`could not list comments (HTTP ${list.status})`);
  const existing = (await list.json()).find((c) => typeof c.body === "string" && c.body.includes(COMMENT_MARKER));
  const res = existing
    ? await fetchWithTimeout(`${base}/comments/${existing.id}`, { method: "PATCH", headers, body: JSON.stringify({ body }) }, 15_000)
    : await fetchWithTimeout(`${base}/${number}/comments`, { method: "POST", headers, body: JSON.stringify({ body }) }, 15_000);
  if (!res.ok) throw new Error(`could not post the comment (HTTP ${res.status})`);
}

async function runDependencies() {
  const apiKey = getInput("api-key", { required: true });
  const failOn = getInput("fail-on", { defaultValue: "high" }).toLowerCase();
  const apiBaseUrl = getInput("api-base-url", { defaultValue: "https://hebridescyber.com" }).replace(/\/$/, "");
  const githubToken = getInput("github-token");
  if (failOn !== "none" && !(failOn in SEVERITY_RANK)) {
    fail(`fail-on must be one of critical, high, medium, low, none — got "${failOn}"`);
    return;
  }

  const eventPath = process.env.GITHUB_EVENT_PATH;
  const event = eventPath && fs.existsSync(eventPath) ? JSON.parse(fs.readFileSync(eventPath, "utf8")) : null;
  const pr = event && event.pull_request;
  if (!pr) {
    notice("mode: dependencies only runs on pull_request events — nothing to check.");
    return;
  }

  let changed;
  let mergeBase;
  try {
    mergeBase = git(["merge-base", pr.base.sha, pr.head.sha]).trim();
    changed = git(["diff", "--name-only", "--no-renames", mergeBase, pr.head.sha]).split("\n").filter(Boolean);
  } catch (err) {
    fail(`Could not compare the pull request's commits (${String(err.message).split("\n")[0]}). Use actions/checkout with fetch-depth: 0.`);
    return;
  }

  const lockfiles = lockfilesIn(changed);
  if (lockfiles.length === 0) {
    notice("No lockfile changed in this pull request.");
    setOutput("new-vulnerable-packages", "0");
    return;
  }

  const files = lockfiles.slice(0, 20).map((path) => {
    const companion = LOCKFILE_COMPANIONS[baseName(path)];
    const companionPath = companion ? `${dirName(path)}${companion}` : null;
    return {
      name: path,
      base: gitShow(mergeBase, path),
      head: gitShow(pr.head.sha, path),
      base_companion: companionPath ? gitShow(mergeBase, companionPath) : null,
      head_companion: companionPath ? gitShow(pr.head.sha, companionPath) : null,
    };
  });
  if (lockfiles.length > files.length) warning(`${lockfiles.length} lockfiles changed; only the first ${files.length} were checked.`);

  console.log(`Checking ${files.length} changed lockfile(s): ${files.map((f) => f.name).join(", ")}`);

  let res;
  try {
    res = await fetchWithTimeout(
      `${apiBaseUrl}/api/v1/dependency-diff`,
      { method: "POST", headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" }, body: JSON.stringify({ files }) },
      120_000
    );
  } catch (err) {
    fail(`Could not reach the Hebrides Cyber API: ${err.message}`);
    return;
  }
  const result = await res.json().catch(() => null);
  if (!res.ok || !result) {
    fail(`Dependency check failed (HTTP ${res.status}): ${(result && result.error) || "no response body"}`);
    return;
  }

  const vulns = result.vulnerabilities || [];
  setOutput("new-vulnerable-packages", String(vulns.length));
  const comment = buildDependencyComment(result, failOn);
  appendToFile("GITHUB_STEP_SUMMARY", comment.replace(COMMENT_MARKER, ""));

  const repo = process.env.GITHUB_REPOSITORY;
  if (githubToken && repo) {
    try {
      await upsertPullRequestComment(githubToken, repo, pr.number, comment, process.env.GITHUB_API_URL || "https://api.github.com");
    } catch (err) {
      // Pull requests from forks get a read-only token: say so, don't fail the check for it.
      warning(`Couldn't post the pull-request comment: ${err.message}. The result is in the job summary.`);
    }
  }

  for (const v of vulns) warning(`[${v.severity}] ${v.name}@${v.version} — ${v.advisories.map((a) => a.cve_ids[0] || a.id).join(", ")}${v.fixed_version ? ` (fixed in ${v.fixed_version})` : ""}`);

  const blocking = blockingVulnerabilities(vulns, failOn);
  if (blocking.length > 0) {
    fail(`${blocking.length} newly introduced vulnerable package(s) at or above "${failOn}" severity.`);
    return;
  }
  if (!result.complete && failOn !== "none") {
    fail(`The dependency check couldn't cover everything (${(result.notes || []).join(" ")}) — not passing it as clean.`);
    return;
  }
  notice(vulns.length === 0 ? "No known-vulnerable packages introduced." : `${vulns.length} vulnerable package(s) introduced, none at or above "${failOn}".`);
}

async function runScan() {
  const apiKey = getInput("api-key", { required: true });
  const targetUrl = getInput("target-url", { required: true });
  const failOn = getInput("fail-on", { defaultValue: "high" }).toLowerCase();
  const apiBaseUrl = getInput("api-base-url", { defaultValue: "https://hebridescyber.com" }).replace(/\/$/, "");

  if (failOn !== "none" && !(failOn in SEVERITY_RANK)) {
    fail(`fail-on must be one of critical, high, medium, low, none — got "${failOn}"`);
    return;
  }

  console.log(`Scanning ${targetUrl}...`);

  let res;
  try {
    res = await fetchWithTimeout(
      `${apiBaseUrl}/api/v1/scans`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl }),
      },
      // Just an enqueue now — should return almost instantly.
      30_000
    );
  } catch (err) {
    fail(`Could not reach the Hebrides Cyber API: ${err.message}`);
    return;
  }

  const queued = await res.json().catch(() => null);
  if (!res.ok || !queued) {
    fail(`Scan failed (HTTP ${res.status}): ${queued?.error ?? "no response body"}`);
    return;
  }

  console.log(`Queued (scan ${queued.scan_id}) — polling for completion...`);
  const body = await pollUntilDone(apiBaseUrl, apiKey, queued.scan_id);
  if (!body) return; // pollUntilDone already called fail()

  const {
    score,
    scan_id: scanId,
    compared_to_previous_scan: compared,
    new_finding_count: newFindingCount,
    findings = [],
  } = body;

  setOutput("score", score ?? "");
  setOutput("compared-to-previous-scan", String(Boolean(compared)));
  setOutput("new-finding-count", newFindingCount ?? "");
  setOutput("report-url", `${apiBaseUrl}/dashboard/scans/${scanId}`);

  console.log(`Security score: ${score}/100`);

  if (!compared) {
    notice("First scan of this target — no baseline to compare against yet. Nothing to gate on.");
    return;
  }

  const newFindings = findings.filter((f) => f.status === "new");
  for (const f of newFindings) {
    if (isTriaged(f)) notice(`NEW [${f.severity}] ${f.title} — triaged (${f.triage.state}), not counted`);
    else warning(`NEW [${f.severity}] ${f.title}`);
  }

  if (failOn === "none") {
    notice(`${newFindings.length} new finding(s) since the last scan — not failing (fail-on: none).`);
    return;
  }

  const blocking = blockingFindings(findings, failOn);

  if (blocking.length > 0) {
    fail(`${blocking.length} new finding(s) at or above "${failOn}" severity introduced since the last scan.`);
    return;
  }

  notice(`No untriaged new findings at or above "${failOn}" severity. (${newFindings.length} new finding(s) below threshold or triaged.)`);
}

async function main() {
  const mode = getInput("mode", { defaultValue: "scan" }).toLowerCase();
  if (mode === "dependencies") return runDependencies();
  if (mode !== "scan") {
    fail(`mode must be "scan" or "dependencies" — got "${mode}"`);
    return;
  }
  return runScan();
}

module.exports = { isTriaged, blockingFindings, lockfilesIn, blockingVulnerabilities, buildDependencyComment, LOCKFILE_COMPANIONS };

// Run only as the action's entry point — requiring this file (the unit tests
// do) must not start a scan.
if (require.main === module) {
  main().catch((err) => {
    if (!(err instanceof ActionFailure)) {
      console.log(`::error::${err.stack || err.message}`);
    }
    process.exitCode = 1;
  });
}
