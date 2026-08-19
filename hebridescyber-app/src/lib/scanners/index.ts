// Main scanner orchestration. Imports all check modules and runs them in
// parallel where possible. Exports the same public API surface as the old
// single-file scanners.ts so run-scan/index.ts needs no import changes.
import { checkTls, type TlsResult } from "./tls";
import { checkHeaders, type HeadersResult } from "./headers";
import { checkDns, type DnsResult } from "./dns";
import { checkExposure, type ExposureResult } from "./exposure";
import { checkDirectoryListing, type DirectoryListingResult } from "./directoryListing";
import { checkCloudMisconfig, type CloudMisconfigResult } from "./cloudMisconfig";
import { checkFingerprint, type FingerprintResult } from "./fingerprint";
import { checkOpenPorts, type PortsResult } from "./ports";
import { checkPlaywrightPageLoad, type PlaywrightResult } from "./playwright";
import { checkRecon, type ReconResult } from "./recon";
import { checkWebApp, type WebAppResult } from "./webapp";
import { checkSafeBrowsing, type SafeBrowsingResult } from "./safeBrowsing";
import { checkWaybackDiscovery, type WaybackDiscoveryResult } from "./waybackDiscovery";
import { checkHibp, hibpBreachSeverity, type HibpResult } from "./hibp";
import { checkWpVulnDb, wpVulnSeverity, type WpVulnDbResult } from "./wpvdb";
import * as FIX from "./remediationText";

export type {
  TlsResult, HeadersResult, DnsResult, ExposureResult, FingerprintResult,
  PortsResult, PlaywrightResult, ReconResult, WebAppResult, DirectoryListingResult,
  CloudMisconfigResult, SafeBrowsingResult, WaybackDiscoveryResult, HibpResult, WpVulnDbResult,
};

export type ScanResults = {
  target_url: string;
  checked_at: string;
  tls: TlsResult;
  headers: HeadersResult;
  dns: DnsResult;
  exposure: ExposureResult;
  directoryListing: DirectoryListingResult;
  cloudMisconfig: CloudMisconfigResult;
  fingerprint: FingerprintResult;
  ports: PortsResult;
  playwright: PlaywrightResult;
  recon: ReconResult;
  webapp: WebAppResult;
  safeBrowsing: SafeBrowsingResult;
  waybackDiscovery: WaybackDiscoveryResult;
  hibp: HibpResult;
  wpVulnDb: WpVulnDbResult;
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
  /**
   * Stable identity for this finding, independent of the human-readable title
   * (which often embeds a count or list that changes run to run — e.g.
   * "Missing recommended headers (3)"). Format: "<module>.<check-name>" for a
   * finding pushed unconditionally by one code location, or
   * "<module>.<check-name>:<key>" for one pushed in a loop, where <key> is the
   * loop's natural identifier (a cookie name, file path, port number, library
   * name). This is what src/lib/findingsDiff.ts matches on to tell "new" from
   * "unchanged" between two scans of the same target.
   *
   * Optional because scans stored before this field existed deserialise
   * without it — those findings simply never match anything in a diff, which
   * is the conservatively correct behaviour (we can't know if an untagged old
   * finding is "the same" as a new tagged one).
   */
  checkId?: string;
  /**
   * Real CVE identifiers for this finding, when known. Only populated for
   * vulnerable-JS-library findings today (src/lib/scanners/webapp.ts, via
   * src/lib/scanners/osv.ts) — see that module for why this isn't attempted
   * for every finding type. Absent (not empty array) when no CVE lookup was
   * even attempted for this finding, so a consumer can distinguish "we
   * checked and found nothing" from "we never checked" if that ever matters.
   */
  cveIds?: string[];
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
  const [tls, headers, dns, exposure, directoryListing, cloudMisconfig, fingerprint, ports, recon, safeBrowsing, waybackDiscovery, hibp] =
    await Promise.all([
      checkTls(targetUrl),
      checkHeaders(targetUrl),
      checkDns(targetUrl),
      checkExposure(targetUrl),
      checkDirectoryListing(targetUrl),
      checkCloudMisconfig(targetUrl),
      checkFingerprint(targetUrl),
      checkOpenPorts(targetUrl),
      checkRecon(targetUrl),
      checkSafeBrowsing(targetUrl),
      checkWaybackDiscovery(targetUrl),
      checkHibp(targetUrl),
    ]);

  // CMS deep scans only run for the CMS fingerprint.ts actually detected.
  const detectedTechs = fingerprint.status === "checked" ? fingerprint.technologies : [];
  const cms = {
    isWordPress: detectedTechs.some((t) => t.name === "WordPress"),
    isJoomla: detectedTechs.some((t) => t.name === "Joomla"),
    isDrupal: detectedTechs.some((t) => t.name === "Drupal"),
  };

  const [playwright, webapp, zap] = await Promise.all([
    checkPlaywrightPageLoad(targetUrl),
    checkWebApp(targetUrl, cms),
    checkZap(targetUrl),
  ]);

  // Depends on webapp's WordPress plugin detection, so it can't join the
  // Promise.all batches above — those run before webapp exists.
  const wpVulnDb = await checkWpVulnDb(
    webapp.status === "checked" && webapp.wordpress ? webapp.wordpress.plugins : []
  );

  return {
    target_url: targetUrl,
    checked_at: new Date().toISOString(),
    tls,
    headers,
    dns,
    exposure,
    directoryListing,
    cloudMisconfig,
    fingerprint,
    ports,
    playwright,
    recon,
    webapp,
    safeBrowsing,
    waybackDiscovery,
    hibp,
    wpVulnDb,
    zap,
  };
}

// ---- Findings derivation ---------------------------------------------------

export function summariseResults(results: ScanResults): { summary: string; findings: Finding[] } {
  const findings: Finding[] = [];

  // --- TLS ------------------------------------------------------------------
  if (results.tls.status === "checked" && !results.tls.isHttps) {
    findings.push({ checkId: "tls.no-https", severity: "critical", title: "Site is not served over HTTPS", detail: "All traffic is unencrypted. Install a TLS certificate immediately.", remediation: FIX.NO_HTTPS });
  }
  if (results.tls.status === "checked" && results.tls.isHttps) {
    if (results.tls.weakProtocol) {
      findings.push({ checkId: "tls.weak-protocol", severity: "high", title: `Weak TLS protocol (${results.tls.protocol})`, detail: "Disable TLS 1.0/1.1 on the server — require TLS 1.2+.", remediation: FIX.WEAK_TLS });
    }
    if ((results.tls.daysUntilExpiry ?? 999) < 21) {
      findings.push({ checkId: "tls.cert-expiring", severity: "high", title: "TLS certificate expiring soon", detail: `Certificate expires ${results.tls.certificateExpiresAt} — renew before it lapses.`, remediation: FIX.CERT_EXPIRING });
    }
    if (results.tls.selfSigned) {
      findings.push({ checkId: "tls.self-signed", severity: "high", title: "Self-signed TLS certificate", detail: "Browsers will show a scary warning. Obtain a certificate from a trusted CA (e.g. Let's Encrypt).", remediation: FIX.SELF_SIGNED });
    }
    if (!results.tls.hsts.present) {
      findings.push({ checkId: "tls.hsts-missing", severity: "medium", title: "HSTS header missing", detail: "Without Strict-Transport-Security, browsers may connect over HTTP first. Add: max-age=31536000; includeSubDomains", remediation: FIX.HSTS_MISSING });
    } else if (!results.tls.hsts.adequate) {
      findings.push({ checkId: "tls.hsts-short", severity: "low", title: "HSTS max-age too short", detail: `Current max-age ${results.tls.hsts.maxAge}s is below the 180-day (15552000s) recommended minimum.`, remediation: FIX.HSTS_SHORT });
    }
  }

  // --- Headers --------------------------------------------------------------
  if (results.headers.status === "checked") {
    const missingCritical = results.headers.owasp.headers
      .filter((h) => !h.present && ["strict-transport-security", "content-security-policy", "x-content-type-options"].includes(h.name))
      .map((h) => h.name);
    if (missingCritical.length > 0) {
      findings.push({ checkId: "headers.missing-critical", severity: "high", title: `Missing critical security headers`, detail: missingCritical.join(", "), remediation: FIX.headerRemediation(missingCritical) });
    }
    const missingOthers = results.headers.owasp.headers
      .filter((h) => !h.present && !missingCritical.includes(h.name))
      .map((h) => h.name);
    if (missingOthers.length > 0) {
      findings.push({ checkId: "headers.missing-recommended", severity: "medium", title: `Missing recommended headers (${missingOthers.length})`, detail: missingOthers.join(", "), remediation: FIX.headerRemediation(missingOthers) });
    }
    if (results.headers.csp.grade === "F") {
      findings.push({ checkId: "headers.csp-absent", severity: "high", title: "Content Security Policy absent or ineffective", detail: results.headers.csp.issues.join("; "), remediation: FIX.CSP_MISSING });
    } else if (results.headers.csp.grade === "C") {
      findings.push({ checkId: "headers.csp-weak", severity: "medium", title: "Weak Content Security Policy", detail: results.headers.csp.issues.join("; "), remediation: FIX.CSP_WEAK });
    }
    for (const cookie of results.headers.cookies) {
      if (cookie.issues.length > 0) {
        findings.push({ checkId: `headers.cookie-flags:${cookie.name}`, severity: "medium", title: `Cookie "${cookie.name}" has insecure flags`, detail: cookie.issues.join("; "), remediation: FIX.COOKIE_FLAGS });
      }
    }
    if (results.headers.cors.wildcardOrigin) {
      findings.push({ checkId: "headers.cors-wildcard", severity: "high", title: "CORS wildcard origin", detail: "Access-Control-Allow-Origin: * allows any site to read cross-origin responses.", remediation: FIX.CORS_WILDCARD });
    }
    const infoIssues = results.headers.infoDisclosure.issues;
    if (infoIssues.length > 0) {
      findings.push({ checkId: "headers.info-disclosure", severity: "low", title: "Headers reveal server technology details", detail: infoIssues.join("; "), remediation: FIX.INFO_DISCLOSURE });
    }
  }

  // --- DNS ------------------------------------------------------------------
  if (results.dns.status === "checked") {
    if (!results.dns.spf.present) {
      findings.push({ checkId: "dns.spf-missing", severity: "high", title: "No SPF record", detail: "Email from this domain can be spoofed. Add an SPF TXT record.", remediation: FIX.SPF_MISSING });
    } else if (results.dns.spf.issues.length > 0) {
      findings.push({ checkId: "dns.spf-issues", severity: "medium", title: "SPF misconfiguration", detail: results.dns.spf.issues.join("; "), remediation: FIX.SPF_ISSUES });
    }
    // DKIM absence is info-level, not high like SPF/DMARC: those live at fixed
    // record names so a missing one is proof, whereas the DKIM selector is
    // unguessable and a custom one may well be signing correctly. Title and
    // detail both say "not detected" rather than "missing" for that reason.
    if (results.dns.dkim.found && results.dns.dkim.issues.length > 0) {
      findings.push({ checkId: "dns.dkim-issues", severity: "medium", title: "DKIM record misconfiguration", detail: results.dns.dkim.issues.join("; "), remediation: FIX.DKIM_ISSUES });
    } else if (!results.dns.dkim.found && results.dns.dkim.selectorsTried > 0) {
      findings.push({ checkId: "dns.dkim-not-detected", severity: "info", title: "DKIM not detected at common selectors", detail: `No DKIM key found at any of the ${results.dns.dkim.selectorsTried} default selectors used by major providers. This does not prove DKIM is absent — a custom selector cannot be discovered from DNS. Verify via the Authentication-Results header on a message you send.`, remediation: FIX.DKIM_NOT_DETECTED });
    }
    if (!results.dns.dmarc.present) {
      findings.push({ checkId: "dns.dmarc-missing", severity: "high", title: "No DMARC record", detail: "Without DMARC, email spoofing is undetected. Add a _dmarc TXT record.", remediation: FIX.DMARC_MISSING });
    } else if (results.dns.dmarc.policy === "none") {
      findings.push({ checkId: "dns.dmarc-none", severity: "medium", title: "DMARC policy is 'none' — no enforcement", detail: "Spoofed emails are not rejected. Upgrade to p=quarantine or p=reject.", remediation: FIX.DMARC_NONE });
    }
    if (!results.dns.caa.present) {
      findings.push({ checkId: "dns.caa-missing", severity: "low", title: "No CAA records", detail: "Any CA can issue certificates for this domain. Add CAA records to restrict to your provider.", remediation: FIX.CAA_MISSING });
    }
    if (!results.dns.dnssec.likelySigned) {
      findings.push({ checkId: "dns.dnssec-missing", severity: "info", title: "DNSSEC not detected", detail: results.dns.dnssec.note, remediation: FIX.DNSSEC_MISSING });
    }
    // MTA-STS/TLS-RPT only get evaluated when the domain has MX records (see
    // checkMtaSts's header comment) — dnsRecordPresent/present both default
    // false when that gate wasn't met, so these blocks are naturally silent
    // for a domain with no mail transport to protect.
    if (results.dns.mxCount > 0 && !results.dns.mtaSts.dnsRecordPresent) {
      findings.push({ checkId: "dns.mta-sts-missing", severity: "info", title: "MTA-STS not configured", detail: "No _mta-sts TXT record found — inbound mail delivery has no protection against downgrade or interception attacks on the SMTP connection itself.", remediation: FIX.MTA_STS_MISSING });
    } else if (results.dns.mtaSts.issues.length > 0) {
      findings.push({ checkId: "dns.mta-sts-issues", severity: "low", title: "MTA-STS misconfiguration", detail: results.dns.mtaSts.issues.join("; "), remediation: FIX.MTA_STS_ISSUES });
    }
    if (results.dns.mxCount > 0 && !results.dns.tlsRpt.present) {
      findings.push({ checkId: "dns.tls-rpt-missing", severity: "info", title: "TLS-RPT not configured", detail: "No _smtp._tls TXT record found — no visibility into failed opportunistic-TLS connections for inbound mail.", remediation: FIX.TLS_RPT_MISSING });
    } else if (results.dns.tlsRpt.issues.length > 0) {
      findings.push({ checkId: "dns.tls-rpt-issues", severity: "low", title: "TLS-RPT misconfiguration", detail: results.dns.tlsRpt.issues.join("; "), remediation: FIX.TLS_RPT_ISSUES });
    }
  }

  // --- Exposure -------------------------------------------------------------
  if (results.exposure.status === "checked") {
    for (const file of results.exposure.exposed) {
      findings.push({ checkId: `exposure.exposed-file:${file.path}`, severity: file.severity, title: `${file.name} accessible at ${file.path}`, detail: file.hint, remediation: FIX.EXPOSED_FILE });
    }
    if (!results.exposure.securityTxt) {
      findings.push({ checkId: "exposure.no-security-txt", severity: "info", title: "No security.txt found", detail: "Add /.well-known/security.txt with a contact address so researchers can report vulnerabilities.", remediation: FIX.SECURITY_TXT_MISSING });
    }
  }

  // --- Directory listing ------------------------------------------------------
  if (results.directoryListing.status === "checked") {
    for (const dir of results.directoryListing.listings) {
      findings.push({
        checkId: `directory-listing.open-directory:${dir.path}`,
        severity: "medium",
        title: `Directory listing enabled at ${dir.path}`,
        detail:
          dir.fileCount !== null
            ? `Autoindex is on — approximately ${dir.fileCount} entr${dir.fileCount === 1 ? "y" : "ies"} browsable without authentication.`
            : "Autoindex is on — the directory's contents are browsable without authentication.",
        remediation: FIX.DIRECTORY_LISTING,
      });
    }
  }

  // --- Cloud misconfiguration -------------------------------------------------
  if (results.cloudMisconfig.status === "checked") {
    for (const bucket of results.cloudMisconfig.publicBuckets) {
      const providerLabel =
        bucket.provider === "s3" ? "S3 bucket" : bucket.provider === "azure-blob" ? "Azure Blob container" : "GCS bucket";
      findings.push({
        checkId: `cloud-misconfig.public-bucket:${bucket.provider}:${bucket.identifier}`,
        severity: "high",
        title: `Publicly listable ${providerLabel}: ${bucket.identifier}`,
        detail:
          bucket.objectCount !== null
            ? `Anyone can list its contents — approximately ${bucket.objectCount} object(s) enumerable at ${bucket.url}.`
            : `Anyone can list its contents at ${bucket.url}.`,
        remediation: FIX.CLOUD_STORAGE_PUBLIC,
      });
    }
  }

  // --- Fingerprint ----------------------------------------------------------
  if (results.fingerprint.status === "checked") {
    for (const risky of results.fingerprint.riskySoftware) {
      // Keyed by name only, not name+version: an upgrade should read as
      // "fixed", not as an unrelated old finding plus a brand-new one.
      findings.push({ checkId: `fingerprint.risky-library:${risky.name}`, severity: "high", title: `Outdated library: ${risky.name} ${risky.version}`, detail: risky.reason, remediation: FIX.OUTDATED_LIBRARY });
    }
    const techList = results.fingerprint.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""}`).join(", ");
    if (techList) {
      findings.push({ checkId: "fingerprint.tech-detected", severity: "info", title: `Detected technologies: ${techList}`, detail: "Technology stack fingerprinted from headers and page source.", remediation: FIX.TECH_DETECTED });
    }
  }

  // --- Playwright -----------------------------------------------------------
  if (results.playwright.status === "checked") {
    if (!results.playwright.loadedOk) {
      findings.push({ checkId: "playwright.unhealthy-status", severity: "medium", title: "Page returned unhealthy HTTP status", detail: `Headless load returned status ${results.playwright.httpStatus}.`, remediation: FIX.UNHEALTHY_STATUS });
    }
    if (results.playwright.mixedContentUrls.length > 0) {
      findings.push({ checkId: "playwright.mixed-content", severity: "high", title: "Mixed content detected", detail: `HTTP resources loaded on HTTPS page: ${results.playwright.mixedContentUrls.slice(0, 3).join(", ")}`, remediation: FIX.MIXED_CONTENT });
    }
    if (results.playwright.consoleErrors.length > 0) {
      findings.push({ checkId: "playwright.console-errors", severity: "low", title: `${results.playwright.consoleErrors.length} browser console error(s)`, detail: "Review browser console output for broken scripts or failed requests.", remediation: FIX.CONSOLE_ERRORS });
    }
  }

  // --- Ports ----------------------------------------------------------------
  if (results.ports.status === "checked" && results.ports.riskyPorts.length > 0) {
    for (const p of results.ports.riskyPorts) {
      findings.push({ checkId: `ports.risky-port:${p.port}`, severity: p.risk as Finding["severity"], title: `Port ${p.port} (${p.service}) open`, detail: p.reason, remediation: FIX.OPEN_PORT });
    }
  }

  // --- Recon ----------------------------------------------------------------
  if (results.recon.status === "checked") {
    const { shodan, subdomains } = results.recon;
    if (shodan && shodan.cves.length > 0) {
      findings.push({
        checkId: "recon.shodan-cves",
        severity: "high",
        title: `${shodan.cves.length} CVE(s) associated with this IP (Shodan)`,
        detail: `Shodan InternetDB reports: ${shodan.cves.slice(0, 5).join(", ")}${shodan.cves.length > 5 ? ` (+${shodan.cves.length - 5} more)` : ""}`,
        remediation: FIX.SHODAN_CVES,
      });
    }
    if (subdomains.length > 0) {
      findings.push({
        checkId: "recon.subdomains-found",
        severity: "info",
        title: `${subdomains.length} subdomain(s) found via Certificate Transparency`,
        detail: `crt.sh enumerated: ${subdomains.slice(0, 5).map((s) => s.name).join(", ")}${subdomains.length > 5 ? ` (+${subdomains.length - 5} more)` : ""}`,
        remediation: FIX.SUBDOMAINS_FOUND,
      });
    }
  }

  // --- Web App (robots / methods / disclosure / WP / CORS / JS libs) --------
  if (results.webapp.status === "checked") {
    const { robots, httpMethods, errorDisclosure, wordpress, joomla, drupal, corsReflected, jsLibraries } =
      results.webapp;

    // robots.txt interesting paths
    if (robots?.accessible && robots.interestingPaths.length > 0) {
      findings.push({
        checkId: "webapp.robots-sensitive-paths",
        severity: "info",
        title: `robots.txt disallows ${robots.interestingPaths.length} sensitive path(s)`,
        detail: `Interesting disallowed paths: ${robots.interestingPaths.slice(0, 5).join(", ")}. These paths may be worth investigating manually.`,
        remediation: FIX.ROBOTS_PATHS,
      });
    }

    // Dangerous HTTP methods
    if (httpMethods.dangerousMethods.length > 0) {
      findings.push({
        checkId: "webapp.dangerous-methods",
        severity: "medium",
        title: `Dangerous HTTP methods enabled: ${httpMethods.dangerousMethods.join(", ")}`,
        detail: `Server advertises ${httpMethods.allowHeader}. Methods like PUT/DELETE can enable unauthorised file modifications if not restricted.`,
        remediation: FIX.DANGEROUS_METHODS,
      });
    }

    // Error page disclosure
    if (errorDisclosure.disclosesFramework) {
      findings.push({
        checkId: "webapp.error-disclosure",
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
          checkId: "webapp.wp-xmlrpc",
          severity: "medium",
          title: "WordPress XML-RPC endpoint accessible (/xmlrpc.php)",
          detail: "XML-RPC enables brute-force attacks via multicall. Disable it unless required by a plugin.",
          remediation: FIX.WP_XMLRPC,
        });
      }
      if (wordpress.userEnumerationPossible) {
        findings.push({
          checkId: "webapp.wp-user-enum",
          severity: "medium",
          title: "WordPress user enumeration via REST API (/wp-json/wp/v2/users)",
          detail: `${wordpress.enumeratedUsers.length} user(s) exposed: ${wordpress.enumeratedUsers.join(", ")}. Disable the users endpoint or restrict with authentication.`,
          remediation: FIX.WP_USER_ENUM,
        });
      }
      if (wordpress.debugLogAccessible) {
        findings.push({
          checkId: "webapp.wp-debug-log",
          severity: "high",
          title: "WordPress debug log publicly accessible (/wp-content/debug.log)",
          detail: "Debug logs may contain credentials, file paths, and stack traces. Remove or restrict access immediately.",
          remediation: FIX.WP_DEBUG_LOG,
        });
      }
      if (wordpress.readmeAccessible) {
        findings.push({
          checkId: "webapp.wp-readme",
          severity: "low",
          title: "WordPress readme.html accessible (version disclosure)",
          detail: "readme.html reveals the WordPress version to attackers. Delete or block this file.",
          remediation: FIX.WP_README,
        });
      }
      if (wordpress.wpCronAccessible) {
        findings.push({
          checkId: "webapp.wp-cron",
          severity: "info",
          title: "WordPress wp-cron.php is accessible",
          detail: "wp-cron.php can be used for DoS via repeated HTTP calls. Consider disabling it and using a real cron job.",
          remediation: FIX.WP_CRON,
        });
      }
      if (wordpress.plugins.length > 0) {
        for (const plugin of wordpress.plugins) {
          findings.push({
            checkId: `webapp.wp-plugin-detected:${plugin.slug}`,
            severity: "info",
            title: `WordPress plugin detected: ${plugin.name} ${plugin.version}`,
            detail: `Version read from the plugin's public readme.txt (Stable tag). No automated CVE lookup is available for WordPress plugins — OSV.dev has no WordPress ecosystem coverage — so check this version manually against the plugin's changelog or WPScan/NVD for known vulnerabilities.`,
            remediation: FIX.WP_PLUGIN_DETECTED,
          });
        }
      }
    }

    // Joomla findings
    if (joomla) {
      if (joomla.version) {
        findings.push({
          checkId: "webapp.joomla-version-disclosed",
          severity: "low",
          title: `Joomla version disclosed: ${joomla.version}`,
          detail:
            "The exact Joomla core version is readable from the administrator manifest, which lets an attacker pick a matching exploit.",
          remediation: FIX.JOOMLA_VERSION_DISCLOSED,
        });
      }
      if (joomla.installFilesPresent) {
        findings.push({
          checkId: "webapp.joomla-install-files",
          severity: "low",
          title: "Joomla installer leftover files present (htaccess.txt / web.config.txt)",
          detail:
            "These ship with Joomla core and should be renamed or removed after install — their presence usually means the install was never hardened.",
          remediation: FIX.JOOMLA_INSTALL_FILES,
        });
      }
    }

    // Drupal findings
    if (drupal) {
      if (drupal.version) {
        findings.push({
          checkId: "webapp.drupal-version-disclosed",
          severity: "low",
          title: `Drupal version disclosed: ${drupal.version}`,
          detail: "CHANGELOG.txt reveals the exact core version, which lets an attacker pick a matching exploit.",
          remediation: FIX.DRUPAL_VERSION_DISCLOSED,
        });
      }
      if (drupal.updatePhpAccessible) {
        findings.push({
          checkId: "webapp.drupal-update-php",
          severity: "medium",
          title: "Drupal update.php is publicly accessible",
          detail:
            "update.php should be restricted to trusted operators — it has historically been a vector for both information disclosure and denial-of-service.",
          remediation: FIX.DRUPAL_UPDATE_PHP,
        });
      }
      if (drupal.jsonApiExposed) {
        findings.push({
          checkId: "webapp.drupal-jsonapi-exposed",
          severity: "info",
          title: "Drupal JSON:API is publicly enabled",
          detail:
            "The default JSON:API endpoint responds without authentication. Confirm this is intentional and that no sensitive content types are exposed through it.",
          remediation: FIX.DRUPAL_JSONAPI_EXPOSED,
        });
      }
      if (drupal.uid1ProfileAccessible) {
        findings.push({
          checkId: "webapp.drupal-uid1-enumerable",
          severity: "low",
          title: "Drupal user profile /user/1 is publicly viewable",
          detail:
            "uid 1 is Drupal's built-in superuser account. A public profile page at this URL helps an attacker confirm the admin account exists ahead of a credential attack.",
          remediation: FIX.DRUPAL_UID1_ENUMERABLE,
        });
      }
    }

    // CORS reflected-origin
    if (corsReflected.reflectsOrigin) {
      if (corsReflected.credentialsAllowed) {
        findings.push({
          checkId: "webapp.cors-reflected-creds",
          severity: "critical",
          title: "CORS reflects arbitrary Origin with credentials allowed",
          detail: `The server reflects Origin: ${corsReflected.testedOrigin} and sets Access-Control-Allow-Credentials: true. This allows cross-origin requests to read authenticated responses — a critical misconfiguration.`,
          remediation: FIX.CORS_REFLECTED,
        });
      } else {
        findings.push({
          checkId: "webapp.cors-reflected",
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
        // Keyed by name only — see the identical rationale on
        // fingerprint.risky-library above.
        findings.push({
          checkId: `webapp.vulnerable-js-lib:${lib.name}`,
          severity: "medium",
          title: `Vulnerable JS library: ${lib.name} ${lib.version}`,
          detail: lib.reason,
          remediation: FIX.OUTDATED_LIBRARY,
          cveIds: lib.cveIds,
        });
      }
    }
  }

  // --- Google Safe Browsing --------------------------------------------------
  if (results.safeBrowsing.status === "checked" && results.safeBrowsing.flagged) {
    const threatLabel = results.safeBrowsing.threatTypes
      .map((t) =>
        t === "SOCIAL_ENGINEERING" ? "phishing/social engineering" : t === "UNWANTED_SOFTWARE" ? "unwanted software" : "malware"
      )
      .join(", ");
    findings.push({
      checkId: "safe-browsing.flagged",
      severity: "critical",
      title: `Site flagged by Google Safe Browsing: ${threatLabel}`,
      detail: `Google's Safe Browsing threat lists currently flag this URL for ${threatLabel}. Chrome, Firefox, and Safari may already be showing visitors a full-page warning or blocking access entirely.`,
      remediation: FIX.SAFE_BROWSING_FLAGGED,
    });
  }

  // --- Wayback Machine historical URL discovery -------------------------------
  if (results.waybackDiscovery.status === "checked") {
    for (const found of results.waybackDiscovery.discovered) {
      findings.push({
        checkId: found.checkId,
        severity: found.severity,
        title: `${found.name}: ${found.path}`,
        detail: found.hint,
        remediation: FIX.WAYBACK_LIVE_PATH,
      });
    }
  }

  // --- HaveIBeenPwned domain breach check --------------------------------------
  if (results.hibp.status === "checked") {
    for (const breach of results.hibp.breaches) {
      findings.push({
        checkId: `hibp.domain-breach:${breach.name}`,
        severity: hibpBreachSeverity(breach),
        title: `${breach.title}${breach.breachDate ? ` (${breach.breachDate})` : ""} — ${breach.affectedAliasCount} address(es) on this domain exposed`,
        detail: breach.description || `Data classes exposed: ${breach.dataClasses.join(", ") || "unknown"}.`,
        remediation: FIX.hibpBreachRemediation(breach.dataClasses),
      });
    }
  }

  // --- WPScan Vulnerability Database (WordPress plugin CVE matches) ---------
  if (results.wpVulnDb.status === "checked") {
    for (const plugin of results.wpVulnDb.plugins) {
      for (const vuln of plugin.vulnerabilities) {
        findings.push({
          checkId: `wpvdb.plugin-vulnerability:${plugin.slug}:${vuln.id}`,
          severity: wpVulnSeverity(vuln.vulnType),
          title: `${plugin.name} ${plugin.version} — ${vuln.title}`,
          detail: vuln.fixedIn
            ? `WPScan's vulnerability database lists this as fixed in version ${vuln.fixedIn} — the detected version ${plugin.version} predates that fix.${vuln.vulnType ? ` Vulnerability type: ${vuln.vulnType}.` : ""}`
            : `WPScan's vulnerability database lists this as still unpatched upstream as of its last update — no fixed version exists yet.${vuln.vulnType ? ` Vulnerability type: ${vuln.vulnType}.` : ""}`,
          remediation: FIX.wpPluginVulnerabilityRemediation(plugin.name, vuln.fixedIn, vuln.referenceUrls[0]),
          cveIds: vuln.cveIds,
        });
      }
    }
  }

  if (findings.length === 0) {
    findings.push({ checkId: "meta.no-issues", severity: "info", title: "No issues found by automated checks", detail: "Passive and active checks completed — no findings. Manual review recommended for business logic flaws.", remediation: FIX.NO_ISSUES });
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
