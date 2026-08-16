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
import { checkRecon, type ReconResult } from "./recon";
import { checkWebApp, type WebAppResult } from "./webapp";
import * as FIX from "./remediationText";

export type {
  TlsResult, HeadersResult, DnsResult, ExposureResult, FingerprintResult,
  PortsResult, PlaywrightResult, ReconResult, WebAppResult,
};

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
  recon: ReconResult;
  webapp: WebAppResult;
  // Optional: ZAP stays available if ZAP_API_URL is set
  zap: ZapResult;
};

export type Finding = {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  /**
   * Markdown fix instructions. Optional because scans stored before this field
   * existed deserialise without it — the report UI must tolerate its absence.
   */
  remediation?: string;
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
  const [tls, headers, dns, exposure, fingerprint, ports, recon] = await Promise.all([
    checkTls(targetUrl),
    checkHeaders(targetUrl),
    checkDns(targetUrl),
    checkExposure(targetUrl),
    checkFingerprint(targetUrl),
    checkOpenPorts(targetUrl),
    checkRecon(targetUrl),
  ]);

  // WordPress deep scan only runs if fingerprint detected WordPress
  const isWordPress =
    fingerprint.status === "checked" &&
    fingerprint.technologies.some((t) => t.name === "WordPress");

  const [playwright, webapp, zap] = await Promise.all([
    checkPlaywrightPageLoad(targetUrl),
    checkWebApp(targetUrl, isWordPress),
    checkZap(targetUrl),
  ]);

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
    recon,
    webapp,
    zap,
  };
}

// ---- Findings derivation ---------------------------------------------------

export function summariseResults(results: ScanResults): { summary: string; findings: Finding[] } {
  const findings: Finding[] = [];

  // --- TLS ------------------------------------------------------------------
  if (results.tls.status === "checked" && !results.tls.isHttps) {
    findings.push({ severity: "critical", title: "Site is not served over HTTPS", detail: "All traffic is unencrypted. Install a TLS certificate immediately.", remediation: FIX.NO_HTTPS });
  }
  if (results.tls.status === "checked" && results.tls.isHttps) {
    if (results.tls.weakProtocol) {
      findings.push({ severity: "high", title: `Weak TLS protocol (${results.tls.protocol})`, detail: "Disable TLS 1.0/1.1 on the server — require TLS 1.2+.", remediation: FIX.WEAK_TLS });
    }
    if ((results.tls.daysUntilExpiry ?? 999) < 21) {
      findings.push({ severity: "high", title: "TLS certificate expiring soon", detail: `Certificate expires ${results.tls.certificateExpiresAt} — renew before it lapses.`, remediation: FIX.CERT_EXPIRING });
    }
    if (results.tls.selfSigned) {
      findings.push({ severity: "high", title: "Self-signed TLS certificate", detail: "Browsers will show a scary warning. Obtain a certificate from a trusted CA (e.g. Let's Encrypt).", remediation: FIX.SELF_SIGNED });
    }
    if (!results.tls.hsts.present) {
      findings.push({ severity: "medium", title: "HSTS header missing", detail: "Without Strict-Transport-Security, browsers may connect over HTTP first. Add: max-age=31536000; includeSubDomains", remediation: FIX.HSTS_MISSING });
    } else if (!results.tls.hsts.adequate) {
      findings.push({ severity: "low", title: "HSTS max-age too short", detail: `Current max-age ${results.tls.hsts.maxAge}s is below the 180-day (15552000s) recommended minimum.`, remediation: FIX.HSTS_SHORT });
    }
  }

  // --- Headers --------------------------------------------------------------
  if (results.headers.status === "checked") {
    const missingCritical = results.headers.owasp.headers
      .filter((h) => !h.present && ["strict-transport-security", "content-security-policy", "x-content-type-options"].includes(h.name))
      .map((h) => h.name);
    if (missingCritical.length > 0) {
      findings.push({ severity: "high", title: `Missing critical security headers`, detail: missingCritical.join(", "), remediation: FIX.headerRemediation(missingCritical) });
    }
    const missingOthers = results.headers.owasp.headers
      .filter((h) => !h.present && !missingCritical.includes(h.name))
      .map((h) => h.name);
    if (missingOthers.length > 0) {
      findings.push({ severity: "medium", title: `Missing recommended headers (${missingOthers.length})`, detail: missingOthers.join(", "), remediation: FIX.headerRemediation(missingOthers) });
    }
    if (results.headers.csp.grade === "F") {
      findings.push({ severity: "high", title: "Content Security Policy absent or ineffective", detail: results.headers.csp.issues.join("; "), remediation: FIX.CSP_MISSING });
    } else if (results.headers.csp.grade === "C") {
      findings.push({ severity: "medium", title: "Weak Content Security Policy", detail: results.headers.csp.issues.join("; "), remediation: FIX.CSP_WEAK });
    }
    for (const cookie of results.headers.cookies) {
      if (cookie.issues.length > 0) {
        findings.push({ severity: "medium", title: `Cookie "${cookie.name}" has insecure flags`, detail: cookie.issues.join("; "), remediation: FIX.COOKIE_FLAGS });
      }
    }
    if (results.headers.cors.wildcardOrigin) {
      findings.push({ severity: "high", title: "CORS wildcard origin", detail: "Access-Control-Allow-Origin: * allows any site to read cross-origin responses.", remediation: FIX.CORS_WILDCARD });
    }
    const infoIssues = results.headers.infoDisclosure.issues;
    if (infoIssues.length > 0) {
      findings.push({ severity: "low", title: "Headers reveal server technology details", detail: infoIssues.join("; "), remediation: FIX.INFO_DISCLOSURE });
    }
  }

  // --- DNS ------------------------------------------------------------------
  if (results.dns.status === "checked") {
    if (!results.dns.spf.present) {
      findings.push({ severity: "high", title: "No SPF record", detail: "Email from this domain can be spoofed. Add an SPF TXT record.", remediation: FIX.SPF_MISSING });
    } else if (results.dns.spf.issues.length > 0) {
      findings.push({ severity: "medium", title: "SPF misconfiguration", detail: results.dns.spf.issues.join("; "), remediation: FIX.SPF_ISSUES });
    }
    if (!results.dns.dmarc.present) {
      findings.push({ severity: "high", title: "No DMARC record", detail: "Without DMARC, email spoofing is undetected. Add a _dmarc TXT record.", remediation: FIX.DMARC_MISSING });
    } else if (results.dns.dmarc.policy === "none") {
      findings.push({ severity: "medium", title: "DMARC policy is 'none' — no enforcement", detail: "Spoofed emails are not rejected. Upgrade to p=quarantine or p=reject.", remediation: FIX.DMARC_NONE });
    }
    if (!results.dns.caa.present) {
      findings.push({ severity: "low", title: "No CAA records", detail: "Any CA can issue certificates for this domain. Add CAA records to restrict to your provider.", remediation: FIX.CAA_MISSING });
    }
    if (!results.dns.dnssec.likelySigned) {
      findings.push({ severity: "info", title: "DNSSEC not detected", detail: results.dns.dnssec.note, remediation: FIX.DNSSEC_MISSING });
    }
  }

  // --- Exposure -------------------------------------------------------------
  if (results.exposure.status === "checked") {
    for (const file of results.exposure.exposed) {
      findings.push({ severity: file.severity, title: `${file.name} accessible at ${file.path}`, detail: file.hint, remediation: FIX.EXPOSED_FILE });
    }
    if (!results.exposure.securityTxt) {
      findings.push({ severity: "info", title: "No security.txt found", detail: "Add /.well-known/security.txt with a contact address so researchers can report vulnerabilities.", remediation: FIX.SECURITY_TXT_MISSING });
    }
  }

  // --- Fingerprint ----------------------------------------------------------
  if (results.fingerprint.status === "checked") {
    for (const risky of results.fingerprint.riskySoftware) {
      findings.push({ severity: "high", title: `Outdated library: ${risky.name} ${risky.version}`, detail: risky.reason, remediation: FIX.OUTDATED_LIBRARY });
    }
    const techList = results.fingerprint.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""}`).join(", ");
    if (techList) {
      findings.push({ severity: "info", title: `Detected technologies: ${techList}`, detail: "Technology stack fingerprinted from headers and page source.", remediation: FIX.TECH_DETECTED });
    }
  }

  // --- Playwright -----------------------------------------------------------
  if (results.playwright.status === "checked") {
    if (!results.playwright.loadedOk) {
      findings.push({ severity: "medium", title: "Page returned unhealthy HTTP status", detail: `Headless load returned status ${results.playwright.httpStatus}.`, remediation: FIX.UNHEALTHY_STATUS });
    }
    if (results.playwright.mixedContentUrls.length > 0) {
      findings.push({ severity: "high", title: "Mixed content detected", detail: `HTTP resources loaded on HTTPS page: ${results.playwright.mixedContentUrls.slice(0, 3).join(", ")}`, remediation: FIX.MIXED_CONTENT });
    }
    if (results.playwright.consoleErrors.length > 0) {
      findings.push({ severity: "low", title: `${results.playwright.consoleErrors.length} browser console error(s)`, detail: "Review browser console output for broken scripts or failed requests.", remediation: FIX.CONSOLE_ERRORS });
    }
  }

  // --- Ports ----------------------------------------------------------------
  if (results.ports.status === "checked" && results.ports.riskyPorts.length > 0) {
    for (const p of results.ports.riskyPorts) {
      findings.push({ severity: p.risk as Finding["severity"], title: `Port ${p.port} (${p.service}) open`, detail: p.reason, remediation: FIX.OPEN_PORT });
    }
  }

  // --- Recon ----------------------------------------------------------------
  if (results.recon.status === "checked") {
    const { shodan, subdomains } = results.recon;
    if (shodan && shodan.cves.length > 0) {
      findings.push({
        severity: "high",
        title: `${shodan.cves.length} CVE(s) associated with this IP (Shodan)`,
        detail: `Shodan InternetDB reports: ${shodan.cves.slice(0, 5).join(", ")}${shodan.cves.length > 5 ? ` (+${shodan.cves.length - 5} more)` : ""}`,
        remediation: FIX.SHODAN_CVES,
      });
    }
    if (subdomains.length > 0) {
      findings.push({
        severity: "info",
        title: `${subdomains.length} subdomain(s) found via Certificate Transparency`,
        detail: `crt.sh enumerated: ${subdomains.slice(0, 5).map((s) => s.name).join(", ")}${subdomains.length > 5 ? ` (+${subdomains.length - 5} more)` : ""}`,
        remediation: FIX.SUBDOMAINS_FOUND,
      });
    }
  }

  // --- Web App (robots / methods / disclosure / WP / CORS / JS libs) --------
  if (results.webapp.status === "checked") {
    const { robots, httpMethods, errorDisclosure, wordpress, corsReflected, jsLibraries } = results.webapp;

    // robots.txt interesting paths
    if (robots?.accessible && robots.interestingPaths.length > 0) {
      findings.push({
        severity: "info",
        title: `robots.txt disallows ${robots.interestingPaths.length} sensitive path(s)`,
        detail: `Interesting disallowed paths: ${robots.interestingPaths.slice(0, 5).join(", ")}. These paths may be worth investigating manually.`,
        remediation: FIX.ROBOTS_PATHS,
      });
    }

    // Dangerous HTTP methods
    if (httpMethods.dangerousMethods.length > 0) {
      findings.push({
        severity: "medium",
        title: `Dangerous HTTP methods enabled: ${httpMethods.dangerousMethods.join(", ")}`,
        detail: `Server advertises ${httpMethods.allowHeader}. Methods like PUT/DELETE can enable unauthorised file modifications if not restricted.`,
        remediation: FIX.DANGEROUS_METHODS,
      });
    }

    // Error page disclosure
    if (errorDisclosure.disclosesFramework) {
      findings.push({
        severity: "low",
        title: "Error page reveals internal framework details",
        detail: `Detected: ${errorDisclosure.disclosedStrings.join("; ")}. Configure custom error pages to avoid information leakage.`,
        remediation: FIX.ERROR_DISCLOSURE,
      });
    }

    // WordPress findings
    if (wordpress) {
      if (wordpress.xmlRpcEnabled) {
        findings.push({
          severity: "medium",
          title: "WordPress XML-RPC endpoint accessible (/xmlrpc.php)",
          detail: "XML-RPC enables brute-force attacks via multicall. Disable it unless required by a plugin.",
          remediation: FIX.WP_XMLRPC,
        });
      }
      if (wordpress.userEnumerationPossible) {
        findings.push({
          severity: "medium",
          title: "WordPress user enumeration via REST API (/wp-json/wp/v2/users)",
          detail: `${wordpress.enumeratedUsers.length} user(s) exposed: ${wordpress.enumeratedUsers.join(", ")}. Disable the users endpoint or restrict with authentication.`,
          remediation: FIX.WP_USER_ENUM,
        });
      }
      if (wordpress.debugLogAccessible) {
        findings.push({
          severity: "high",
          title: "WordPress debug log publicly accessible (/wp-content/debug.log)",
          detail: "Debug logs may contain credentials, file paths, and stack traces. Remove or restrict access immediately.",
          remediation: FIX.WP_DEBUG_LOG,
        });
      }
      if (wordpress.readmeAccessible) {
        findings.push({
          severity: "low",
          title: "WordPress readme.html accessible (version disclosure)",
          detail: "readme.html reveals the WordPress version to attackers. Delete or block this file.",
          remediation: FIX.WP_README,
        });
      }
      if (wordpress.wpCronAccessible) {
        findings.push({
          severity: "info",
          title: "WordPress wp-cron.php is accessible",
          detail: "wp-cron.php can be used for DoS via repeated HTTP calls. Consider disabling it and using a real cron job.",
          remediation: FIX.WP_CRON,
        });
      }
    }

    // CORS reflected-origin
    if (corsReflected.reflectsOrigin) {
      if (corsReflected.credentialsAllowed) {
        findings.push({
          severity: "critical",
          title: "CORS reflects arbitrary Origin with credentials allowed",
          detail: `The server reflects Origin: ${corsReflected.testedOrigin} and sets Access-Control-Allow-Credentials: true. This allows cross-origin requests to read authenticated responses — a critical misconfiguration.`,
          remediation: FIX.CORS_REFLECTED,
        });
      } else {
        findings.push({
          severity: "high",
          title: "CORS reflects arbitrary Origin header",
          detail: `The server mirrors back any Origin header as Access-Control-Allow-Origin. Any attacker-controlled site can read cross-origin responses.`,
          remediation: FIX.CORS_REFLECTED,
        });
      }
    }

    // JS library vulnerabilities
    for (const lib of jsLibraries) {
      if (lib.isVulnerable) {
        findings.push({
          severity: "medium",
          title: `Vulnerable JS library: ${lib.name} ${lib.version}`,
          detail: lib.reason,
          remediation: FIX.OUTDATED_LIBRARY,
        });
      }
    }
  }

  if (findings.length === 0) {
    findings.push({ severity: "info", title: "No issues found by automated checks", detail: "Passive and active checks completed — no findings. Manual review recommended for business logic flaws.", remediation: FIX.NO_ISSUES });
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
