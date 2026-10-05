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

async function main() {
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

module.exports = { isTriaged, blockingFindings };

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
