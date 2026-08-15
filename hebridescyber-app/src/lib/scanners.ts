// Scanner functions used by BOTH `src/functions/run-scan/index.ts` (the
// real HTTP-triggered path) and `src/scripts/scan-local.ts` (the CLI dev
// tool), so the two never drift apart.
//
// Status of each check, honestly:
//   - checkHeaders, checkTls   : REAL — live fetch/TLS inspection of the
//                                 target, no API keys required.
//   - checkDependencies        : REAL, but limited — passive fingerprinting
//                                 of the HTML response, not a true SCA scan
//                                 against a package manifest. See its TODO.
//   - checkPlaywrightPageLoad  : REAL — launches headless Chromium.
//   - checkZap                 : REAL if ZAP_API_URL is configured (kicks
//                                 off a scan, does not wait for results —
//                                 see its TODO), otherwise a stub.
//   - checkOpenPorts           : REAL if the `nmap` binary is present on
//                                 PATH (it is NOT installed by default in
//                                 Azure Functions' consumption plan — see
//                                 its TODO), otherwise a stub.
//   - generateAiSummary        : REAL if AZURE_OPENAI_ENDPOINT/KEY are
//                                 configured, otherwise falls back to a
//                                 deterministic templated summary.
//
// Tooling choice: OWASP ZAP and Nmap were picked deliberately over
// proprietary/commercial scanners (Burp Suite, Pentera, NodeZero, etc.) —
// both are free, open-source, and are the de facto standard tools in their
// category (network discovery and web app scanning respectively), which
// keeps this stack cheap to run and easy for a customer to audit/replicate
// themselves if they want to.

import { connect as tlsConnect } from "node:tls";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chromium } from "playwright";

const execFileAsync = promisify(execFile);

export type ScanResults = {
  target_url: string;
  checked_at: string;
  tls: Awaited<ReturnType<typeof checkTls>>;
  headers: Awaited<ReturnType<typeof checkHeaders>>;
  dependencies: Awaited<ReturnType<typeof checkDependencies>>;
  playwright: Awaited<ReturnType<typeof checkPlaywrightPageLoad>>;
  zap: Awaited<ReturnType<typeof checkZap>>;
  ports: Awaited<ReturnType<typeof checkOpenPorts>>;
};

export type Finding = {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
};

/**
 * Runs every scanner step. tls/headers/dependencies run in parallel since
 * they're independent, read-only HTTP/DNS calls; playwright and zap run
 * after, since they're heavier and (for zap) may kick off async server-side
 * work that shouldn't race the others.
 *
 * TODO: move checkPlaywrightPageLoad and checkZap into an isolated,
 * ephemeral container (Azure Container Instances) rather than running them
 * inline in whatever process calls runAllChecks — see docs/security.md.
 */
export async function runAllChecks(targetUrl: string): Promise<ScanResults> {
  const [tls, headers, dependencies] = await Promise.all([
    checkTls(targetUrl),
    checkHeaders(targetUrl),
    checkDependencies(targetUrl),
  ]);
  const playwright = await checkPlaywrightPageLoad(targetUrl);
  const zap = await checkZap(targetUrl);
  const ports = await checkOpenPorts(targetUrl);

  return {
    target_url: targetUrl,
    checked_at: new Date().toISOString(),
    tls,
    headers,
    dependencies,
    playwright,
    zap,
    ports,
  };
}

// ---- TLS ----------------------------------------------------------------
// Real check: opens a raw TLS socket to the host and reads the negotiated
// protocol version and certificate expiry. Not as thorough as SSL Labs
// (no cipher suite grading, no chain-of-trust validation beyond what
// Node's default CA store does), but genuinely inspects the live target.
export async function checkTls(targetUrl: string) {
  const host = new URL(targetUrl).hostname;
  const isHttps = new URL(targetUrl).protocol === "https:";

  if (!isHttps) {
    return {
      status: "checked" as const,
      isHttps: false,
      note: "Target is not served over HTTPS at all.",
    };
  }

  try {
    const info = await new Promise<{ protocol: string | null; validTo: string }>((resolve, reject) => {
      const socket = tlsConnect({ host, port: 443, servername: host, timeout: 8000 }, () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        socket.end();
        resolve({ protocol, validTo: cert?.valid_to ?? "unknown" });
      });
      socket.on("timeout", () => {
        socket.destroy();
        reject(new Error("TLS connection timed out"));
      });
      socket.on("error", reject);
    });

    const daysUntilExpiry =
      info.validTo === "unknown" ? null : Math.round((new Date(info.validTo).getTime() - Date.now()) / 86_400_000);
    const weakProtocol = info.protocol !== null && ["TLSv1", "TLSv1.1"].includes(info.protocol);

    return {
      status: "checked" as const,
      isHttps: true,
      protocol: info.protocol,
      certificateExpiresAt: info.validTo,
      daysUntilExpiry,
      weakProtocol,
    };
  } catch (err) {
    return {
      status: "error" as const,
      isHttps: true,
      note: `TLS check failed: ${(err as Error).message}`,
    };
  }
}

// ---- Security headers -----------------------------------------------------
// Real check: fetches the target and inspects the actual response headers.
const REQUIRED_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
];

export async function checkHeaders(targetUrl: string) {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(8000) });
    const missing = REQUIRED_HEADERS.filter((h) => !res.headers.has(h));
    return {
      status: "checked" as const,
      httpStatus: res.status,
      missing,
      present: REQUIRED_HEADERS.filter((h) => res.headers.has(h)),
    };
  } catch (err) {
    return {
      status: "error" as const,
      missing: REQUIRED_HEADERS, // unknown = treat as missing so findings still surface something actionable
      note: `Header check failed: ${(err as Error).message}`,
    };
  }
}

// ---- Dependency / technology fingerprinting -------------------------------
// Real-but-limited check: fetches the page HTML and looks for version
// strings of common front-end libraries / CMSes in the markup, comparing
// against a small local table of known-outdated major versions.
//
// TODO: this cannot see server-side dependencies (npm packages, OS
// packages) at all — it only sees what's exposed in the HTML/script tags.
// For real SCA coverage, this needs to become a separate flow that accepts
// a repo URL or package.json/lockfile upload and runs `npm audit --json`
// or calls the Snyk API — a genuinely different product surface from
// "scan this live URL", not just a bigger version of this function.
const OUTDATED_PATTERNS: Array<{ name: string; pattern: RegExp; maxSafeMajor: number }> = [
  { name: "jQuery", pattern: /jquery[-.]?(\d+)\.(\d+)\.(\d+)/i, maxSafeMajor: 3 },
  { name: "WordPress", pattern: /wp-content|generator" content="WordPress (\d+)\.(\d+)/i, maxSafeMajor: 6 },
  { name: "Bootstrap", pattern: /bootstrap[-.]?(\d+)\.(\d+)\.(\d+)/i, maxSafeMajor: 5 },
];

export async function checkDependencies(targetUrl: string) {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(8000) });
    const html = await res.text();

    const vulnerablePackages: Array<{ name: string; detectedVersion: string }> = [];
    for (const { name, pattern, maxSafeMajor } of OUTDATED_PATTERNS) {
      const match = html.match(pattern);
      if (match && match[1] && Number(match[1]) < maxSafeMajor) {
        vulnerablePackages.push({ name, detectedVersion: match.slice(1).filter(Boolean).join(".") });
      }
    }

    return {
      status: "checked" as const,
      method: "passive-html-fingerprint" as const,
      vulnerablePackages,
      note: "Passive fingerprinting only — does not cover server-side/npm dependencies. See TODO in src/lib/scanners.ts.",
    };
  } catch (err) {
    return {
      status: "error" as const,
      method: "passive-html-fingerprint" as const,
      vulnerablePackages: [] as Array<{ name: string; detectedVersion: string }>,
      note: `Dependency fingerprint check failed: ${(err as Error).message}`,
    };
  }
}

// ---- Headless page load ----------------------------------------------------
// Real check: launches Chromium via Playwright, loads the page, and
// captures console errors and the final HTTP status.
export async function checkPlaywrightPageLoad(targetUrl: string) {
  let browser;
  try {
    browser = await chromium.launch();
    const page = await browser.newPage();
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });

    const response = await page.goto(targetUrl, { waitUntil: "load", timeout: 15000 });
    const title = await page.title();

    return {
      status: "checked" as const,
      loadedOk: Boolean(response?.ok()),
      httpStatus: response?.status() ?? null,
      title,
      consoleErrorCount: consoleErrors.length,
      consoleErrors: consoleErrors.slice(0, 10), // cap so results stay a reasonable size
    };
  } catch (err) {
    return {
      status: "error" as const,
      loadedOk: false,
      note: `Headless page load failed: ${(err as Error).message}`,
    };
  } finally {
    await browser?.close();
  }
}

// ---- OWASP ZAP ------------------------------------------------------------
// Real integration IF a ZAP daemon is reachable at ZAP_API_URL (e.g. a
// `zaproxy/zap-stable` container with the API enabled) — kicks off a
// baseline spider scan and returns immediately with a scan ID.
//
// TODO: ZAP scans run asynchronously server-side and can take minutes.
// This function does not poll for completion or attach results back to
// the `scans` row — that requires a follow-up job (e.g. a second Function
// on a timer, or a queue message) that polls `/JSON/ascan/view/status/`
// and writes the alerts into scan_results once done. Only run this against
// targets with explicit signed consent — see docs/security.md.
export async function checkZap(targetUrl: string) {
  const zapApiUrl = process.env.ZAP_API_URL;
  if (!zapApiUrl) {
    return {
      status: "not_configured" as const,
      alerts: [] as unknown[],
      note: "ZAP_API_URL is not set — set it to a reachable ZAP daemon to enable this check.",
    };
  }

  try {
    const scanRes = await fetch(
      `${zapApiUrl}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}`,
      { signal: AbortSignal.timeout(8000) }
    );
    const scanBody = (await scanRes.json()) as { scan?: string };
    return {
      status: "started" as const,
      zapScanId: scanBody.scan ?? null,
      alerts: [] as unknown[],
      note: "ZAP spider scan started — results are not polled/attached yet, see TODO above.",
    };
  } catch (err) {
    return {
      status: "error" as const,
      alerts: [] as unknown[],
      note: `Failed to reach ZAP at ${zapApiUrl}: ${(err as Error).message}`,
    };
  }
}

// ---- Open ports (Nmap) ------------------------------------------------------
// Real check IF the `nmap` binary is available on PATH — runs a fast
// (`-F`, top 100 ports) TCP scan and parses which are open. Nmap is the
// de facto standard tool for this category, chosen over a hand-rolled
// TCP-connect scanner for accuracy and speed.
//
// TODO: Azure Functions' default Linux consumption plan image does not
// include nmap — either switch to a custom container image with it
// installed, or (better, per docs/security.md) run this specific check in
// an isolated Azure Container Instance rather than the Function host, both
// for the missing binary and so a scan can't tie up the Function's own
// network egress.
const RISKY_PORTS: Record<number, string> = {
  21: "FTP — usually unencrypted, avoid if possible",
  23: "Telnet — unencrypted remote access, should not be internet-facing",
  3389: "RDP — high-value target for brute force, restrict to VPN/allowlist",
  3306: "MySQL — should not be directly internet-facing",
  5432: "PostgreSQL — should not be directly internet-facing",
};

export async function checkOpenPorts(targetUrl: string) {
  const host = new URL(targetUrl).hostname;

  try {
    // Fail fast if nmap isn't installed, rather than letting execFile's
    // ENOENT bubble up as a generic error later.
    await execFileAsync("nmap", ["--version"], { timeout: 5000 });
  } catch {
    return {
      status: "not_configured" as const,
      openPorts: [] as number[],
      note: "nmap is not installed on this host — see TODO in src/lib/scanners.ts.",
    };
  }

  try {
    const { stdout } = await execFileAsync("nmap", ["-F", "-T4", host], { timeout: 30000 });
    const openPorts = [...stdout.matchAll(/^(\d+)\/tcp\s+open/gm)].map((m) => Number(m[1]));
    const risky = openPorts.filter((p) => p in RISKY_PORTS).map((p) => ({ port: p, reason: RISKY_PORTS[p] }));

    return { status: "checked" as const, openPorts, risky };
  } catch (err) {
    return {
      status: "error" as const,
      openPorts: [] as number[],
      note: `nmap scan failed: ${(err as Error).message}`,
    };
  }
}

// ---- Findings + summary -----------------------------------------------------

/**
 * Deterministic findings + summary derived purely from the check results —
 * no network/API calls. Used as the fallback when Azure OpenAI isn't
 * configured, and directly by anything that wants synchronous, reproducible
 * output (e.g. tests).
 */
export function summariseResults(results: ScanResults): { summary: string; findings: Finding[] } {
  const findings: Finding[] = [];

  if (results.tls.status === "checked" && !results.tls.isHttps) {
    findings.push({
      severity: "critical",
      title: "Site is not served over HTTPS",
      detail: "All traffic, including any login forms, is unencrypted. Obtain and install a TLS certificate.",
    });
  }
  if (results.tls.status === "checked" && results.tls.isHttps && results.tls.weakProtocol) {
    findings.push({
      severity: "high",
      title: `Weak TLS protocol negotiated (${results.tls.protocol})`,
      detail: "Disable TLS 1.0/1.1 on the server and require TLS 1.2+.",
    });
  }
  if (results.tls.status === "checked" && results.tls.isHttps && (results.tls.daysUntilExpiry ?? 999) < 21) {
    findings.push({
      severity: "high",
      title: "TLS certificate expiring soon",
      detail: `Certificate expires ${results.tls.certificateExpiresAt} — renew before it lapses.`,
    });
  }
  if (results.headers.missing.length > 0) {
    findings.push({
      severity: "high",
      title: `Missing security headers: ${results.headers.missing.join(", ")}`,
      detail: "Add these HTTP response headers to reduce session hijack and clickjacking risk.",
    });
  }
  if (results.dependencies.vulnerablePackages.length > 0) {
    findings.push({
      severity: "critical",
      title: `${results.dependencies.vulnerablePackages.length} outdated front-end libraries detected`,
      detail: results.dependencies.vulnerablePackages.map((p) => `${p.name} ${p.detectedVersion}`).join(", "),
    });
  }
  if (results.playwright.status === "checked" && !results.playwright.loadedOk) {
    findings.push({
      severity: "medium",
      title: "Page did not return a healthy HTTP status",
      detail: `Headless load returned status ${results.playwright.httpStatus}.`,
    });
  }
  if (results.playwright.status === "checked" && results.playwright.consoleErrorCount > 0) {
    findings.push({
      severity: "low",
      title: `${results.playwright.consoleErrorCount} browser console errors on load`,
      detail: "Review console output for broken scripts or failed requests.",
    });
  }

  if (results.ports.status === "checked" && results.ports.risky.length > 0) {
    findings.push({
      severity: "high",
      title: `${results.ports.risky.length} risky open port(s) detected`,
      detail: results.ports.risky.map((r) => `${r.port}: ${r.reason}`).join("; "),
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      title: "No issues found by the automated checks",
      detail: "Passive checks only — see src/lib/scanners.ts for what each check does and does not cover.",
    });
  }

  const topTitles = findings.slice(0, 3).map((f) => f.title).join("; ");
  const summary = buildDeterministicSummary(results.target_url, topTitles);

  return { summary, findings };
}

function buildDeterministicSummary(targetUrl: string, topTitles: string): string {
  return `Security Score summary for ${targetUrl}: ${topTitles}.`;
}

/**
 * Produces the executive summary shown in the dashboard/report. Calls
 * Azure OpenAI if AZURE_OPENAI_ENDPOINT/AZURE_OPENAI_KEY/AZURE_OPENAI_DEPLOYMENT
 * are set; otherwise (or on any error) falls back to the deterministic
 * templated summary from summariseResults() so this never blocks a scan.
 */
export async function generateAiSummary(results: ScanResults, findings: Finding[]): Promise<string> {
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  const fallback = buildDeterministicSummary(
    results.target_url,
    findings.slice(0, 3).map((f) => f.title).join("; ")
  );

  if (!endpoint || !apiKey || !deployment) {
    return fallback;
  }

  try {
    const res = await fetch(
      `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "api-key": apiKey },
        signal: AbortSignal.timeout(15000),
        body: JSON.stringify({
          messages: [
            {
              role: "system",
              content:
                "You write 2-3 sentence plain-English executive summaries of website security scan findings " +
                "for small business owners who are not technical. Be direct about risk, avoid jargon.",
            },
            {
              role: "user",
              content: `Target: ${results.target_url}\nFindings:\n${findings
                .map((f) => `- [${f.severity}] ${f.title}: ${f.detail}`)
                .join("\n")}`,
            },
          ],
          max_tokens: 200,
          temperature: 0.3,
        }),
      }
    );

    if (!res.ok) return fallback;
    const body = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    return body.choices?.[0]?.message?.content?.trim() || fallback;
  } catch {
    return fallback;
  }
}

/** Rough 0-100 score derived from findings severity, for the dashboard badge. */
export function scoreFromFindings(findings: Finding[]): number {
  const penalties: Record<Finding["severity"], number> = {
    critical: 30,
    high: 15,
    medium: 8,
    low: 3,
    info: 0,
  };
  const total = findings.reduce((sum, f) => sum + penalties[f.severity], 0);
  return Math.max(0, 100 - total);
}
