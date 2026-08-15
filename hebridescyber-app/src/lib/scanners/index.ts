// Main scanner orchestration. Imports all check modules and runs them in
// parallel where possible. Exports the same public API surface as the old
// single-file scanners.ts so run-scan/index.ts needs no import changes.
import { checkTls, type TlsResult } from "./tls";
import { checkHeaders, type HeadersResult } from "./headers";
import { checkDns, type DnsResult } from "./dns";
import { checkExposure, type ExposureResult } from "./exposure";
import { checkFingerprint, type FingerprintResult } from "./fingerprint";
import { checkOpenPorts, type PortsResult } from "./ports";
import { checkPlaywrightPageLoad, type PlaywrightResult } from "./playwright";

export type { TlsResult, HeadersResult, DnsResult, ExposureResult, FingerprintResult, PortsResult, PlaywrightResult };

export type ScanResults = {
  target_url: string;
  checked_at: string;
  tls: TlsResult;
  headers: HeadersResult;
  dns: DnsResult;
  exposure: ExposureResult;
  fingerprint: FingerprintResult;
  ports: PortsResult;
  playwright: PlaywrightResult;
  // Optional: ZAP stays available if ZAP_API_URL is set
  zap: ZapResult;
};

export type Finding = {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
};

// ---- ZAP (optional — requires running ZAP daemon) -------------------------

export type ZapResult =
  | { status: "not_configured"; note: string }
  | { status: "started"; zapScanId: string | null; note: string }
  | { status: "error"; note: string };

async function checkZap(targetUrl: string): Promise<ZapResult> {
  const zapApiUrl = process.env.ZAP_API_URL;
  if (!zapApiUrl) {
    return { status: "not_configured", note: "ZAP_API_URL is not set — skipping active web application scan" };
  }
  try {
    const res = await fetch(`${zapApiUrl}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}`, {
      signal: AbortSignal.timeout(8000),
    });
    const body = (await res.json()) as { scan?: string };
    return { status: "started", zapScanId: body.scan ?? null, note: "ZAP spider scan started" };
  } catch (err) {
    return { status: "error", note: `Failed to reach ZAP at ${zapApiUrl}: ${(err as Error).message}` };
  }
}

// ---- Orchestration ---------------------------------------------------------

/**
 * Runs all scanner checks. TLS, headers, DNS, exposure, fingerprint, and
 * port probes run in parallel (independent, read-only). Playwright (heavy)
 * and ZAP (async server-side) run after.
 */
export async function runAllChecks(targetUrl: string): Promise<ScanResults> {
  const [tls, headers, dns, exposure, fingerprint, ports] = await Promise.all([
    checkTls(targetUrl),
    checkHeaders(targetUrl),
    checkDns(targetUrl),
    checkExposure(targetUrl),
    checkFingerprint(targetUrl),
    checkOpenPorts(targetUrl),
  ]);

  const playwright = await checkPlaywrightPageLoad(targetUrl);
  const zap = await checkZap(targetUrl);

  return {
    target_url: targetUrl,
    checked_at: new Date().toISOString(),
    tls,
    headers,
    dns,
    exposure,
    fingerprint,
    ports,
    playwright,
    zap,
  };
}

// ---- Findings derivation ---------------------------------------------------

export function summariseResults(results: ScanResults): { summary: string; findings: Finding[] } {
  const findings: Finding[] = [];

  // --- TLS ------------------------------------------------------------------
  if (results.tls.status === "checked" && !results.tls.isHttps) {
    findings.push({ severity: "critical", title: "Site is not served over HTTPS", detail: "All traffic is unencrypted. Install a TLS certificate immediately." });
  }
  if (results.tls.status === "checked" && results.tls.isHttps) {
    if (results.tls.weakProtocol) {
      findings.push({ severity: "high", title: `Weak TLS protocol (${results.tls.protocol})`, detail: "Disable TLS 1.0/1.1 on the server — require TLS 1.2+." });
    }
    if ((results.tls.daysUntilExpiry ?? 999) < 21) {
      findings.push({ severity: "high", title: "TLS certificate expiring soon", detail: `Certificate expires ${results.tls.certificateExpiresAt} — renew before it lapses.` });
    }
    if (results.tls.selfSigned) {
      findings.push({ severity: "high", title: "Self-signed TLS certificate", detail: "Browsers will show a scary warning. Obtain a certificate from a trusted CA (e.g. Let's Encrypt)." });
    }
    if (!results.tls.hsts.present) {
      findings.push({ severity: "medium", title: "HSTS header missing", detail: "Without Strict-Transport-Security, browsers may connect over HTTP first. Add: max-age=31536000; includeSubDomains" });
    } else if (!results.tls.hsts.adequate) {
      findings.push({ severity: "low", title: "HSTS max-age too short", detail: `Current max-age ${results.tls.hsts.maxAge}s is below the 180-day (15552000s) recommended minimum.` });
    }
  }

  // --- Headers --------------------------------------------------------------
  if (results.headers.status === "checked") {
    const missingCritical = results.headers.owasp.headers
      .filter((h) => !h.present && ["strict-transport-security", "content-security-policy", "x-content-type-options"].includes(h.name))
      .map((h) => h.name);
    if (missingCritical.length > 0) {
      findings.push({ severity: "high", title: `Missing critical security headers`, detail: missingCritical.join(", ") });
    }
    const missingOthers = results.headers.owasp.headers
      .filter((h) => !h.present && !missingCritical.includes(h.name))
      .map((h) => h.name);
    if (missingOthers.length > 0) {
      findings.push({ severity: "medium", title: `Missing recommended headers (${missingOthers.length})`, detail: missingOthers.join(", ") });
    }
    if (results.headers.csp.grade === "F") {
      findings.push({ severity: "high", title: "Content Security Policy absent or ineffective", detail: results.headers.csp.issues.join("; ") });
    } else if (results.headers.csp.grade === "C") {
      findings.push({ severity: "medium", title: "Weak Content Security Policy", detail: results.headers.csp.issues.join("; ") });
    }
    for (const cookie of results.headers.cookies) {
      if (cookie.issues.length > 0) {
        findings.push({ severity: "medium", title: `Cookie "${cookie.name}" has insecure flags`, detail: cookie.issues.join("; ") });
      }
    }
    if (results.headers.cors.wildcardOrigin) {
      findings.push({ severity: "high", title: "CORS wildcard origin", detail: "Access-Control-Allow-Origin: * allows any site to read cross-origin responses." });
    }
    const infoIssues = results.headers.infoDisclosure.issues;
    if (infoIssues.length > 0) {
      findings.push({ severity: "low", title: "Headers reveal server technology details", detail: infoIssues.join("; ") });
    }
  }

  // --- DNS ------------------------------------------------------------------
  if (results.dns.status === "checked") {
    if (!results.dns.spf.present) {
      findings.push({ severity: "high", title: "No SPF record", detail: "Email from this domain can be spoofed. Add an SPF TXT record." });
    } else if (results.dns.spf.issues.length > 0) {
      findings.push({ severity: "medium", title: "SPF misconfiguration", detail: results.dns.spf.issues.join("; ") });
    }
    if (!results.dns.dmarc.present) {
      findings.push({ severity: "high", title: "No DMARC record", detail: "Without DMARC, email spoofing is undetected. Add a _dmarc TXT record." });
    } else if (results.dns.dmarc.policy === "none") {
      findings.push({ severity: "medium", title: "DMARC policy is 'none' — no enforcement", detail: "Spoofed emails are not rejected. Upgrade to p=quarantine or p=reject." });
    }
    if (!results.dns.caa.present) {
      findings.push({ severity: "low", title: "No CAA records", detail: "Any CA can issue certificates for this domain. Add CAA records to restrict to your provider." });
    }
    if (!results.dns.dnssec.likelySigned) {
      findings.push({ severity: "info", title: "DNSSEC not detected", detail: results.dns.dnssec.note });
    }
  }

  // --- Exposure -------------------------------------------------------------
  if (results.exposure.status === "checked") {
    for (const file of results.exposure.exposed) {
      findings.push({ severity: file.severity, title: `${file.name} accessible at ${file.path}`, detail: file.hint });
    }
    if (!results.exposure.securityTxt) {
      findings.push({ severity: "info", title: "No security.txt found", detail: "Add /.well-known/security.txt with a contact address so researchers can report vulnerabilities." });
    }
  }

  // --- Fingerprint ----------------------------------------------------------
  if (results.fingerprint.status === "checked") {
    for (const risky of results.fingerprint.riskySoftware) {
      findings.push({ severity: "high", title: `Outdated library: ${risky.name} ${risky.version}`, detail: risky.reason });
    }
    const techList = results.fingerprint.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""}`).join(", ");
    if (techList) {
      findings.push({ severity: "info", title: `Detected technologies: ${techList}`, detail: "Technology stack fingerprinted from headers and page source." });
    }
  }

  // --- Playwright -----------------------------------------------------------
  if (results.playwright.status === "checked") {
    if (!results.playwright.loadedOk) {
      findings.push({ severity: "medium", title: "Page returned unhealthy HTTP status", detail: `Headless load returned status ${results.playwright.httpStatus}.` });
    }
    if (results.playwright.mixedContentUrls.length > 0) {
      findings.push({ severity: "high", title: "Mixed content detected", detail: `HTTP resources loaded on HTTPS page: ${results.playwright.mixedContentUrls.slice(0, 3).join(", ")}` });
    }
    if (results.playwright.consoleErrors.length > 0) {
      findings.push({ severity: "low", title: `${results.playwright.consoleErrors.length} browser console error(s)`, detail: "Review browser console output for broken scripts or failed requests." });
    }
  }

  // --- Ports ----------------------------------------------------------------
  if (results.ports.status === "checked" && results.ports.riskyPorts.length > 0) {
    for (const p of results.ports.riskyPorts) {
      findings.push({ severity: p.risk as Finding["severity"], title: `Port ${p.port} (${p.service}) open`, detail: p.reason });
    }
  }

  if (findings.length === 0) {
    findings.push({ severity: "info", title: "No issues found by automated checks", detail: "Passive and active checks completed — no findings. Manual review recommended for business logic flaws." });
  }

  const topTitles = findings.slice(0, 3).map((f) => f.title).join("; ");
  const summary = `Security scan of ${results.target_url}: ${topTitles}.`;
  return { summary, findings };
}

export function scoreFromFindings(findings: Finding[]): number {
  const penalties: Record<Finding["severity"], number> = { critical: 30, high: 15, medium: 7, low: 2, info: 0 };
  return Math.max(0, 100 - findings.reduce((sum, f) => sum + penalties[f.severity], 0));
}

export async function generateAiSummary(results: ScanResults, findings: Finding[]): Promise<string> {
  const { summary: fallback } = summariseResults(results);
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  if (!endpoint || !apiKey || !deployment) return fallback;

  try {
    const res = await fetch(
      `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "api-key": apiKey },
        signal: AbortSignal.timeout(15_000),
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
              content: `Target: ${results.target_url}\nFindings:\n${findings.map((f) => `- [${f.severity}] ${f.title}: ${f.detail}`).join("\n")}`,
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
