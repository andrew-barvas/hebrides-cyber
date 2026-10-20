// Main scanner orchestration. Imports all check modules and runs them in
// parallel where possible. Exports the same public API surface as the old
// single-file scanners.ts so run-scan/index.ts needs no import changes.
import { checkTls, type TlsResult } from "./tls";
import { checkHeaders, type HeadersResult } from "./headers";
import { checkDns, type DnsResult } from "./dns";
import { checkExposure, type ExposureResult } from "./exposure";
import { checkDirectoryListing, type DirectoryListingResult } from "./directoryListing";
import { checkCloudMisconfig, type CloudMisconfigResult } from "./cloudMisconfig";
import { checkFingerprint, getCmsType, type FingerprintResult } from "./fingerprint";
import { checkOpenPorts, type PortsResult } from "./ports";
import { checkPlaywrightPageLoad, type PlaywrightResult } from "./playwright";
import { checkRecon, type ReconResult } from "./recon";
import { checkWebApp, type WebAppResult } from "./webapp";
import { checkSafeBrowsing, type SafeBrowsingResult } from "./safeBrowsing";
import { checkWaybackDiscovery, type WaybackDiscoveryResult } from "./waybackDiscovery";
import { checkHibp, hibpBreachSeverity, type HibpResult } from "./hibp";
import { checkWpVulnDb, wpVulnSeverity, type WpVulnDbResult } from "./wpvdb";
import { checkSoftwareCveDb, type SoftwareCveDbResult } from "./softwareCveDb";
import { checkBusinessLogic, type BusinessLogicResult } from "./businessLogic";
import { checkApiSpecPassive, type ApiSpecResult } from "./apiSpec";
import { checkTakeover, type TakeoverResult } from "./takeover";
import { checkDomainRegistration, type DomainRegistrationResult } from "./domainRegistration";
import { checkEndOfLife, eolSeverity, type EndOfLifeResult } from "./endOfLife";
import { checkSubdomainCerts, type SubdomainCertsResult } from "./subdomainCerts";
import { checkCrawl, type CrawlResult } from "./crawler";
import { checkBackendExposure, type BackendExposureResult } from "./backendExposure";
import { checkJsSecrets, buildJsSecretsFindings, type JsSecretsResult } from "./jsSecrets";
import { checkGraphql, buildGraphqlFindings, type GraphqlResult } from "./graphql";
import { buildCrawlFindings, buildMalwareFindings } from "./crawlFindings";
import { checkScriptInventory, foundByPhrase, integrityPhrase, type ScriptInventoryResult } from "./scriptInventory";
import { runCookieConsent, type CookieConsentResult } from "./cookieConsent";
import { getComplianceRefs, type ComplianceRef } from "./compliance";
import { getFixDifficulty, estimateFixMinutes, type FixDifficulty } from "./fixDifficulty";
export { enrichFindingsWithCvss } from "./cvssEnrich";
export { enrichFindingsWithThreatIntel } from "./threatIntel";
import { scoreFromPenalties } from "./riskScore";
import * as FIX from "./remediationText";

export type {
  TlsResult, HeadersResult, DnsResult, ExposureResult, FingerprintResult,
  PortsResult, PlaywrightResult, ReconResult, WebAppResult, DirectoryListingResult,
  CloudMisconfigResult, SafeBrowsingResult, WaybackDiscoveryResult, HibpResult, WpVulnDbResult,
  BusinessLogicResult, ApiSpecResult, SoftwareCveDbResult, TakeoverResult, DomainRegistrationResult,
  EndOfLifeResult, SubdomainCertsResult, ScriptInventoryResult, CrawlResult, BackendExposureResult,
  CookieConsentResult,
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
  softwareCveDb: SoftwareCveDbResult;
  businessLogic: BusinessLogicResult;
  apiSpec: ApiSpecResult;
  // Optional because scans stored before these checks existed lack them.
  takeover?: TakeoverResult;
  domainRegistration?: DomainRegistrationResult;
  endOfLife?: EndOfLifeResult;
  subdomainCerts?: SubdomainCertsResult;
  scriptInventory?: ScriptInventoryResult;
  cookieConsent?: CookieConsentResult;
  crawl?: CrawlResult;
  backendExposure?: BackendExposureResult;
  jsSecrets?: JsSecretsResult;
  graphql?: GraphqlResult;
  // Optional: ZAP stays available if ZAP_API_URL is set
  zap: ZapResult;
};

/** Another tool's report of the same underlying issue, folded into the canonical finding
 *  by src/lib/findingConsolidation.ts. */
export type Corroboration = {
  /** Display name of the reporting tool ("nuclei", "ZAP", "testssl", or a built-in module). */
  tool: string;
  /** The duplicate's original checkId — kept so diffs and lifecycle can still recognise it. */
  checkId: string;
  title: string;
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
  /**
   * Compliance/framework references (Cyber Essentials, OWASP Top 10, CIS
   * Controls v8) this finding maps to — see src/lib/scanners/compliance.ts.
   * Applied as a final pass in summariseResults(), not set at push time by
   * any individual check, so it's never present on findings from a scan
   * stored before this field existed. Absent/empty means either "not yet
   * categorised" or genuinely not applicable to any framework — the module
   * header explains why those are deliberately not distinguished.
   */
  complianceRefs?: ComplianceRef[];
  /**
   * How much effort fixing this finding takes — a different axis from
   * severity (how much risk it poses). See src/lib/scanners/fixDifficulty.ts.
   * Applied as a final pass alongside complianceRefs, same optionality
   * reasoning: absent means either "not yet rated" or genuinely no fixed
   * estimate makes sense for this check.
   */
  fixDifficulty?: FixDifficulty;
  /** Rough remediation time estimate in minutes, derived from fixDifficulty. */
  estimatedFixMinutes?: number;
  /**
   * Other tools that reported this same issue, merged into this finding by
   * findingConsolidation.ts before scoring (so the issue costs score once).
   * Absent means nothing corroborated it — not that nothing else looked.
   */
  corroboratedBy?: Corroboration[];
  /** CVSS v3.1 base score (0.0–10.0), when the finding maps to a known CVE. */
  cvssScore?: number;
  /** CVSS v3.1 vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". */
  cvssVector?: string;
  /**
   * Threat intelligence for CVE-backed findings (threatIntel.ts), applied as
   * a final pass like CVSS. CVSS says how bad a flaw *could* be; these say
   * whether anyone is actually using it. Absent = not looked up (no CVE, or
   * the feed was unreachable) — never read absence as "not exploited".
   */
  threatIntel?: {
    /** One of cveIds is in CISA's Known Exploited Vulnerabilities catalog. */
    knownExploited: boolean;
    /** The KEV-listed CVE ids, when knownExploited. */
    kevCveIds?: string[];
    /** CISA marks at least one as used in ransomware campaigns. */
    ransomware?: boolean;
    /** Highest FIRST EPSS probability (0–1) of exploitation in the next 30 days, across cveIds. */
    epss?: number;
    /** That CVE's EPSS percentile (0–1) among all scored CVEs. */
    epssPercentile?: number;
  };
  /** Arbitrary metadata for enrichment passes (proof-of-exploit, scanner-specific context). */
  metadata?: Record<string, unknown>;
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
 *
 * The optional supabaseAdmin/ownerId pair enables checks that need the
 * database (API spec lookup). When omitted (e.g. scan-local.ts), those
 * checks fall back to auto-discovery or return not_configured.
 */
export async function runAllChecks(
  targetUrl: string,
  supabaseAdmin?: import("@supabase/supabase-js").SupabaseClient,
  ownerId?: string
): Promise<ScanResults> {
  const settled1 = await Promise.allSettled([
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
    checkBusinessLogic(targetUrl),
    checkDomainRegistration(targetUrl),
    checkBackendExposure(targetUrl),
    checkGraphql(targetUrl),
    checkJsSecrets(targetUrl),
  ]);

  function unwrap<T extends { status: string }>(r: PromiseSettledResult<T>, fallback: T): T {
    return r.status === "fulfilled" ? r.value : fallback;
  }

  const tls = unwrap(settled1[0], { status: "error", isHttps: false, protocol: null, weakProtocol: false, selfSigned: false, certificateExpiresAt: null, daysUntilExpiry: null, issuer: null, hsts: { present: false, adequate: false, maxAge: null }, note: String((settled1[0] as PromiseRejectedResult).reason) } as TlsResult);
  const headers = unwrap(settled1[1], { status: "error" } as HeadersResult);
  const dns = unwrap(settled1[2], { status: "error" } as DnsResult);
  const exposure = unwrap(settled1[3], { status: "error" } as ExposureResult);
  const directoryListing = unwrap(settled1[4], { status: "error", listings: [], note: "check crashed" } as DirectoryListingResult);
  const cloudMisconfig = unwrap(settled1[5], { status: "error", publicBuckets: [], note: "check crashed" } as CloudMisconfigResult);
  const fingerprint = unwrap(settled1[6], { status: "error" } as FingerprintResult);
  const ports = unwrap(settled1[7], { status: "error" } as PortsResult);
  const recon = unwrap(settled1[8], { status: "error" } as ReconResult);
  const safeBrowsing = unwrap(settled1[9], { status: "error" } as SafeBrowsingResult);
  const waybackDiscovery = unwrap(settled1[10], { status: "error" } as WaybackDiscoveryResult);
  const hibp = unwrap(settled1[11], { status: "error" } as HibpResult);
  const businessLogic = unwrap(settled1[12], { status: "error", note: "check crashed" } as BusinessLogicResult);
  const domainRegistration = unwrap(settled1[13], { status: "error", note: "check crashed" } as DomainRegistrationResult);
  const backendExposure = unwrap(settled1[14], { status: "error", note: "check crashed" } as BackendExposureResult);
  const graphql = unwrap(settled1[15], { status: "error", note: "check crashed" } as GraphqlResult);
  const jsSecrets = unwrap(settled1[16], { status: "error", note: "check crashed" } as JsSecretsResult);

  // CMS deep scans only run for the CMS fingerprint.ts actually detected.
  const detectedTechs = fingerprint.status === "checked" ? fingerprint.technologies : [];
  const cmsType = getCmsType(detectedTechs);
  const cms = {
    isWordPress: cmsType === "wordpress",
    isJoomla: cmsType === "joomla",
    isDrupal: cmsType === "drupal",
    isMagento: cmsType === "magento",
    isShopify: cmsType === "shopify",
  };

  // Site crawl (E-70): page-level checks on every reachable page. Seeded with
  // the Wayback URLs that still resolve; runs alongside the batch below.
  const crawlPending = checkCrawl(targetUrl, {
    seedPaths: waybackDiscovery.status === "checked" ? waybackDiscovery.discovered.map((d) => d.path) : [],
  }).catch((err: Error): CrawlResult => ({ status: "error", note: `Crawl failed: ${err.message}` }));

  const settled2 = await Promise.allSettled([
    checkPlaywrightPageLoad(targetUrl),
    checkWebApp(targetUrl, cms),
    checkZap(targetUrl),
    // API spec passive checks need the database to look up stored specs.
    // When supabaseAdmin/ownerId are not provided (scan-local.ts), pass
    // null so the check skips the DB lookup and falls back to auto-discovery.
    checkApiSpecPassive(targetUrl, supabaseAdmin ?? null, ownerId ?? null),
  ]);
  const playwright = unwrap(settled2[0], { status: "error" } as PlaywrightResult);
  const webapp = unwrap(settled2[1], { status: "error" } as WebAppResult);
  const zap = unwrap(settled2[2], { status: "error", note: "ZAP check crashed" } as unknown as ZapResult);
  const apiSpec = unwrap(settled2[3], { status: "not_configured", findings: [], endpointsTested: 0, specSource: "none" } as ApiSpecResult);

  // Needs fingerprint and webapp versions; runs alongside the enrichment below.
  const endOfLifePending = checkEndOfLife(fingerprint, webapp).catch(
    (err: Error): EndOfLifeResult => ({ status: "error", note: err.message })
  );

  // Needs the headless browser's runtime script capture; falls back to the
  // raw HTML alone ("partial") when Playwright failed.
  const crawl = await crawlPending;
  const scriptInventoryPending = checkScriptInventory(targetUrl, playwright, crawl).catch(
    (err: Error): ScriptInventoryResult => ({ status: "error", note: err.message })
  );
  // Cookie-consent / tracker-before-consent (PECR/GDPR): consumes the same
  // Playwright pass (cookies + script hosts) plus one HTML fetch for CMP
  // markers. Runs after playwright resolves, like scriptInventory.
  const cookieConsentPending = runCookieConsent(targetUrl, playwright).catch(
    (err: Error): CookieConsentResult => ({ status: "error", note: err.message })
  );

  // Depends on webapp's WordPress plugin detection, so it can't join the
  // Promise.all batches above — those run before webapp exists.
  const wpVulnDb = await checkWpVulnDb(
    webapp.status === "checked" && webapp.wordpress ? webapp.wordpress.plugins : [],
    webapp.status === "checked" && webapp.wordpress ? (webapp.wordpress.themes ?? []) : []
  );

  // Depends on fingerprint's riskySoftware detection (WordPress core, PHP,
  // Apache), so it can't join the Promise.allSettled batch above either —
  // same "enrichment runs after its input resolves" pattern as wpVulnDb.
  const softwareCveDb = await checkSoftwareCveDb(
    fingerprint.status === "checked" ? fingerprint.riskySoftware : []
  );

  // Both need recon's Certificate Transparency subdomains as their candidate
  // list, and are independent of each other.
  //
  // If the CT lookup failed, the list is unknown rather than empty: both
  // report an error instead of "checked", or a crt.sh outage (common) would
  // mark every open subdomain finding fixed and close its tickets.
  const ctSubdomains = recon.status === "checked" ? recon.subdomains : [];
  const ctUnavailable = recon.status !== "checked" || recon.ctLookupFailed === true;
  const ctNote = "Certificate Transparency lookup (crt.sh) failed, so this domain's subdomains couldn't be listed this scan.";
  const [takeover, subdomainCerts] = ctUnavailable
    ? [{ status: "error", note: ctNote } as TakeoverResult, { status: "error", note: ctNote } as SubdomainCertsResult]
    : await Promise.all([
        checkTakeover(targetUrl, ctSubdomains.map((s) => s.name)).catch(
          (err: Error): TakeoverResult => ({ status: "error", note: err.message })
        ),
        checkSubdomainCerts(
          targetUrl,
          ctSubdomains,
          tls.status === "checked" && "certFingerprint" in tls ? tls.certFingerprint : null
        ).catch((err: Error): SubdomainCertsResult => ({ status: "error", note: err.message })),
      ]);

  const endOfLife = await endOfLifePending;
  const scriptInventory = await scriptInventoryPending;
  const cookieConsent = await cookieConsentPending;

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
    softwareCveDb,
    businessLogic,
    apiSpec,
    takeover,
    domainRegistration,
    endOfLife,
    subdomainCerts,
    scriptInventory,
    cookieConsent,
    crawl,
    backendExposure,
    jsSecrets,
    graphql,
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
    // Browsers refuse the certificate outright for these (until 2026-10 the
    // scan couldn't read such a certificate at all — see tls.ts).
    const trust = results.tls.trustProblem ?? null;
    const days = results.tls.daysUntilExpiry;
    if (trust === "expired" || (days !== null && days < 0)) {
      findings.push({ checkId: "tls.cert-expired", severity: "critical", title: "TLS certificate has expired", detail: `The certificate expired ${results.tls.certificateExpiresAt}. Every visitor gets a full-page browser warning instead of your site, and most will leave.`, remediation: FIX.CERT_EXPIRED });
    } else if ((days ?? 999) < 21) {
      findings.push({ checkId: "tls.cert-expiring", severity: "high", title: "TLS certificate expiring soon", detail: `Certificate expires ${results.tls.certificateExpiresAt} — renew before it lapses.`, remediation: FIX.CERT_EXPIRING });
    }
    if (results.tls.selfSigned) {
      findings.push({ checkId: "tls.self-signed", severity: "high", title: "Self-signed TLS certificate", detail: "Browsers will show a scary warning. Obtain a certificate from a trusted CA (e.g. Let's Encrypt).", remediation: FIX.SELF_SIGNED });
    }
    if (trust === "hostname-mismatch") {
      const names = results.tls.subjectAltNames.slice(0, 5).join(", ") || results.tls.subject;
      findings.push({ checkId: "tls.cert-name-mismatch", severity: "critical", title: "TLS certificate doesn't cover this hostname", detail: `The certificate is issued for ${names}, not for the address scanned. Browsers block the page with a full-page warning.`, remediation: FIX.CERT_NAME_MISMATCH });
    }
    if (trust === "incomplete-chain") {
      findings.push({ checkId: "tls.cert-chain-incomplete", severity: "medium", title: "TLS certificate chain is incomplete", detail: "The server sends its certificate without the intermediate certificate that links it to a trusted root. Chrome and Edge fetch the missing piece themselves, so the site looks fine there — but Firefox, curl, many mobile apps and API clients reject the connection.", remediation: FIX.CERT_CHAIN_INCOMPLETE });
    }
    if (trust === "untrusted") {
      findings.push({ checkId: "tls.cert-untrusted", severity: "high", title: "TLS certificate isn't trusted", detail: `Browsers don't trust this certificate (${results.tls.trustErrorCode ?? "verification failed"}), usually because it was issued by a private or unknown certificate authority, or has been revoked. Visitors get a full-page warning.`, remediation: FIX.CERT_UNTRUSTED });
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
    const smugglingIssues = results.headers.smugglingSurface.issues;
    if (smugglingIssues.length > 0) {
      findings.push({ checkId: "headers.smuggling-surface", severity: "medium", title: "Possible HTTP request smuggling surface", detail: smugglingIssues.join("; "), remediation: FIX.SMUGGLING_SURFACE });
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
    } else {
      // Enforcing policy (quarantine/reject) but weakened or unmonitored.
      // Separate from dmarc-none above: these only apply when the policy IS
      // enforcing, so they never double up with it.
      if (results.dns.dmarc.partialEnforcement) {
        findings.push({
          checkId: "dns.dmarc-partial-enforcement",
          severity: "low",
          title: `DMARC enforcement weakened by pct=${results.dns.dmarc.pct}`,
          detail: `The policy is p=${results.dns.dmarc.policy}, but pct=${results.dns.dmarc.pct} applies it to only ${results.dns.dmarc.pct}% of failing messages — the rest are delivered as if there were no policy. Once you've confirmed legitimate mail passes, raise pct to 100.`,
          remediation: FIX.DMARC_PARTIAL_ENFORCEMENT,
        });
      }
      if (results.dns.dmarc.noReporting) {
        findings.push({
          checkId: "dns.dmarc-no-reporting",
          severity: "info",
          title: "DMARC has no aggregate-report (rua) address",
          detail: `The policy enforces (p=${results.dns.dmarc.policy}) but has no rua= tag, so you receive no aggregate reports and have no visibility into who is sending as your domain or whether legitimate mail is being caught. Add rua=mailto:dmarc@your-domain to start receiving them.`,
          remediation: FIX.DMARC_NO_REPORTING,
        });
      }
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
      findings.push({ checkId: `exposure.exposed-file:${file.path}`, severity: file.severity, title: `${file.name} accessible at ${file.path}`, detail: file.hint, remediation: FIX.EXPOSED_FILE, metadata: { path: file.path } });
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
    // End-of-life detection answers the same question from live, dated data
    // (this table is a hand-kept major-version cut-off). Where it reached a
    // verdict for a technology, its finding stands in for this one.
    const eolEvaluated = new Set(results.endOfLife?.status === "checked" ? results.endOfLife.evaluated : []);
    for (const risky of results.fingerprint.riskySoftware) {
      if (eolEvaluated.has(risky.name)) continue;
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
    // Confirmed by construction (see confirmDomXss's header comment): the
    // marker only ever reaches the DOM via client-side script, never the
    // server, so there is no separate "possible" state to proofOfExploit.ts
    // confirm later — the metadata is attached directly, here.
    if (results.playwright.domXss?.status === "confirmed") {
      findings.push({
        checkId: "playwright.dom-xss",
        severity: "critical",
        title: "DOM-based XSS: the page writes the URL into itself unsafely",
        detail: results.playwright.domXss.evidence,
        remediation: FIX.DOM_XSS,
        metadata: {
          proofOfExploit: {
            confirmed: true,
            evidence: results.playwright.domXss.evidence,
            request: `GET ${results.playwright.domXss.probeUrl}`,
            response: "Marker element present in the live DOM after a client-side script ran",
            validatedAt: new Date().toISOString(),
          },
        },
      });
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
    const { robots, httpMethods, errorDisclosure, wordpress, joomla, drupal, magento, shopify, corsReflected, jsLibraries, unprotectedResources } =
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
      // One finding for plugins seen but not versioned: we can't check them
      // against a vulnerability database, and say so rather than staying silent.
      const unversioned = wordpress.pluginsWithoutVersion ?? [];
      if (unversioned.length > 0) {
        findings.push({
          checkId: "webapp.wp-plugins-unversioned",
          severity: "info",
          title: `${unversioned.length} WordPress plugin${unversioned.length === 1 ? "" : "s"} in use, version not readable`,
          detail: `The page loads files from these plugins, but their version could not be read (readme.txt is blocked or missing), so they could not be checked for known vulnerabilities: ${unversioned.slice(0, 15).join(", ")}${unversioned.length > 15 ? ` (+${unversioned.length - 15} more)` : ""}. Check each is up to date in your WordPress dashboard.`,
          remediation: FIX.WP_PLUGIN_DETECTED,
        });
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

    // Magento findings
    if (magento) {
      if (magento.envPhpExposed) {
        findings.push({
          checkId: "webapp.magento-env-php-exposed",
          severity: "critical",
          title: "Magento configuration file (app/etc/env.php) is publicly readable",
          detail:
            "This file contains the database connection string and the crypt key used to encrypt every other secret the store has stored — reading it gives an attacker near-total access.",
          remediation: FIX.MAGENTO_ENV_PHP_EXPOSED,
        });
      }
      if (magento.downloaderAccessible) {
        findings.push({
          checkId: "webapp.magento-downloader-accessible",
          severity: "medium",
          title: "Magento Connect Manager (/downloader/) is publicly accessible",
          detail:
            "This deprecated component has historically been used to compromise Magento stores and should be disabled or removed in production.",
          remediation: FIX.MAGENTO_DOWNLOADER_ACCESSIBLE,
        });
      }
      if (magento.defaultAdminPathAccessible) {
        findings.push({
          checkId: "webapp.magento-default-admin-path",
          severity: "info",
          title: "Magento admin panel is reachable at its default path (/admin)",
          detail:
            "Not a vulnerability by itself, but every Magento hardening guide recommends moving the admin panel to a custom path so it isn't the first thing an automated attacker tries.",
          remediation: FIX.MAGENTO_DEFAULT_ADMIN_PATH,
        });
      }
    }

    // Shopify findings
    if (shopify && shopify.exposedAdminTokens.length > 0) {
      findings.push({
        checkId: "webapp.shopify-admin-token-exposed",
        severity: "critical",
        title: "A Shopify admin-level API token is exposed in the page source",
        detail: `Found ${shopify.exposedAdminTokens.length} token-shaped string(s) matching Shopify's Admin API/custom-app/private-app formats (redacted: ${shopify.exposedAdminTokens.join(", ")}). Unlike the public Storefront API token, these grant store-management access and must never appear in anything a browser loads.`,
        remediation: FIX.SHOPIFY_ADMIN_TOKEN_EXPOSED,
      });
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
          // The published severity when retire.js supplied one; the legacy
          // pattern path has none and stays medium.
          severity: lib.severity ?? "medium",
          title: `Vulnerable JS library: ${lib.name} ${lib.version}`,
          detail: lib.reason,
          remediation: FIX.OUTDATED_LIBRARY,
          cveIds: lib.cveIds,
        });
      }
    }

    // Subresource Integrity — cross-origin scripts/stylesheets loaded
    // without an integrity hash. Scripts are riskier than stylesheets (full
    // code execution vs. CSS-level tampering), so severity differs.
    for (const resource of unprotectedResources) {
      findings.push({
        checkId: `webapp.missing-sri:${resource.kind}:${resource.url}`,
        severity: resource.kind === "script" ? "medium" : "low",
        title: `Cross-origin ${resource.kind} loaded without Subresource Integrity`,
        detail: `${resource.url} is loaded with no integrity attribute — if that origin is compromised, hijacked, or MITM'd, it can serve modified content with no way for the browser to detect it.`,
        remediation: FIX.sriRemediation(resource.kind, resource.url),
      });
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

  // --- Business Logic -------------------------------------------------------
  if (results.businessLogic.status === "checked") {
    const { csrf, externalForms, autocompleteIssues, sequentialUrls, predictableIds, openRedirects, rateLimiting } =
      results.businessLogic;

    if (csrf.formsFound > 0 && csrf.formsWithoutToken > 0) {
      findings.push({
        checkId: "business-logic.csrf-missing",
        severity: "high",
        title: `${csrf.formsWithoutToken} form(s) missing CSRF token protection`,
        detail: `${csrf.formsWithoutToken} of ${csrf.formsFound} state-changing form(s) have no CSRF token (hidden input or meta tag). This allows cross-site request forgery attacks.`,
        remediation: FIX.BUSINESS_LOGIC_CSRF_MISSING,
      });
    }

    for (const form of externalForms) {
      findings.push({
        checkId: `business-logic.external-form-action:${form.targetDomain}`,
        severity: "medium",
        title: `Form posts data to external domain: ${form.targetDomain}`,
        detail: `A form action points to ${form.formAction} — data submitted through this form leaves the site. Verify this is intentional.`,
        remediation: FIX.BUSINESS_LOGIC_EXTERNAL_FORM_ACTION,
      });
    }

    for (const issue of autocompleteIssues) {
      findings.push({
        checkId: `business-logic.autocomplete-sensitive:${issue.fieldName}`,
        severity: "low",
        title: `Sensitive ${issue.fieldType} field "${issue.fieldName}" allows autocomplete`,
        detail: issue.autocompleteValue
          ? `Field has autocomplete="${issue.autocompleteValue}" instead of "off" or "new-password". Browser autofill may store sensitive data locally.`
          : `Field has no autocomplete attribute. Browser autofill may store sensitive data locally.`,
        remediation: FIX.BUSINESS_LOGIC_AUTOCOMPLETE,
      });
    }

    if (sequentialUrls.length > 0) {
      findings.push({
        checkId: "business-logic.sequential-url",
        severity: "info",
        title: `Sequential workflow URL pattern detected (${sequentialUrls.length} link(s))`,
        detail: `Links with sequential step patterns found: ${sequentialUrls.slice(0, 3).map((s) => s.pattern).join(", ")}${sequentialUrls.length > 3 ? ` (+${sequentialUrls.length - 3} more)` : ""}. These may allow step-skipping if server-side workflow state is not enforced.`,
        remediation: FIX.BUSINESS_LOGIC_SEQUENTIAL_URL,
      });
    }

    if (predictableIds.length > 0) {
      findings.push({
        checkId: "business-logic.predictable-ids",
        severity: "medium",
        title: `Predictable numeric resource IDs in ${predictableIds.length} link(s)`,
        detail: `Links with small sequential numeric IDs found: ${predictableIds.slice(0, 3).map((p) => p.url).join(", ")}${predictableIds.length > 3 ? ` (+${predictableIds.length - 3} more)` : ""}. These resources may be enumerable if authorisation checks are missing.`,
        remediation: FIX.BUSINESS_LOGIC_PREDICTABLE_IDS,
      });
    }

    for (const redirect of openRedirects) {
      findings.push({
        checkId: `business-logic.open-redirect:${redirect.parameter}`,
        severity: "medium",
        title: `Open redirect via "${redirect.parameter}" parameter`,
        detail: `The server redirected to ${redirect.redirectedTo} when the "${redirect.parameter}" query parameter was set to an external URL. This can be used in phishing attacks.`,
        remediation: FIX.BUSINESS_LOGIC_OPEN_REDIRECT,
        // What proofOfExploit.ts re-requests to confirm the redirect.
        metadata: { url: redirect.endpoint, parameter: redirect.parameter },
      });
    }

    if (rateLimiting.checked && !rateLimiting.rateLimited && rateLimiting.endpoint) {
      // A CAPTCHA on the login page is a credential-stuffing defence, so the
      // absence of rate limiting is less exposed — downgrade to low and say so,
      // rather than claiming brute force is unthrottled when a CAPTCHA stands in
      // the way.
      const captchaNote = rateLimiting.captcha
        ? " A CAPTCHA was detected on the login page, which mitigates automated credential attacks, but request throttling is still recommended as defence in depth."
        : " No CAPTCHA was detected on the login page either, so there is no automated-attack defence in front of this endpoint.";
      findings.push({
        checkId: "business-logic.no-rate-limit",
        severity: rateLimiting.captcha ? "low" : "medium",
        title: `No rate limiting detected on login endpoint (${rateLimiting.endpoint})`,
        detail: `${rateLimiting.requestsSent} rapid POST requests to ${rateLimiting.endpoint} received no rate-limiting response (no 429 status or Retry-After header). Brute-force attacks are not throttled.${captchaNote}`,
        remediation: FIX.BUSINESS_LOGIC_NO_RATE_LIMIT,
      });
    }
  }

  // --- API Spec (OpenAPI/Swagger-driven endpoint testing) -------------------
  // Findings are already fully formed (with checkId and remediation) by the
  // scanner module itself — no per-finding derivation needed here, just
  // append them.
  if (results.apiSpec.status === "completed") {
    findings.push(...results.apiSpec.findings);
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
    // Themes: same evidence (WPScan record vs the version in the theme's
    // own style.css header), separate checkId so a theme and a plugin with
    // the same slug can never collide.
    for (const theme of results.wpVulnDb.themes ?? []) {
      for (const vuln of theme.vulnerabilities) {
        findings.push({
          checkId: `wpvdb.theme-vulnerability:${theme.slug}:${vuln.id}`,
          severity: wpVulnSeverity(vuln.vulnType),
          title: `Theme ${theme.name} ${theme.version} — ${vuln.title}`,
          detail: vuln.fixedIn
            ? `WPScan's vulnerability database lists this as fixed in version ${vuln.fixedIn} — the detected theme version ${theme.version} (from its style.css) predates that fix.${vuln.vulnType ? ` Vulnerability type: ${vuln.vulnType}.` : ""}`
            : `WPScan's vulnerability database lists this as still unpatched upstream as of its last update — no fixed version exists yet.${vuln.vulnType ? ` Vulnerability type: ${vuln.vulnType}.` : ""}`,
          remediation: FIX.wpPluginVulnerabilityRemediation(theme.name, vuln.fixedIn, vuln.referenceUrls[0], "theme"),
          cveIds: vuln.cveIds,
        });
      }
    }
  }

  // --- Software CVE DB (WordPress core / PHP / Apache CVE matches) ----------
  // Findings are already fully formed (with checkId and cveIds) by the
  // module itself — unlike wpVulnDb above, no per-vulnerability derivation
  // is needed here, just attach remediation text and append.
  if (results.softwareCveDb.status === "checked") {
    for (const finding of results.softwareCveDb.findings) {
      const remediation = finding.checkId?.startsWith("softwareCveDb.wordpressCore")
        ? FIX.SOFTWARE_CVE_WORDPRESS_CORE
        : finding.checkId?.includes("nvdCpe:php-php")
          ? FIX.SOFTWARE_CVE_PHP
          : FIX.SOFTWARE_CVE_APACHE;
      findings.push({ ...finding, remediation });
    }
  }

  // --- Dangling DNS / subdomain takeover ------------------------------------
  // --- Certificates on other hostnames --------------------------------------
  // One finding per certificate (a wildcard on ten hosts is one renewal),
  // keyed by its name, which survives renewal. Lower than the main site's
  // tls.cert-*: CT logs include hosts nobody uses any more.
  if (results.subdomainCerts?.status === "checked") {
    for (const issue of results.subdomainCerts.issues) {
      const shown = issue.hosts.slice(0, 10).join(", ") + (issue.hosts.length > 10 ? `, and ${issue.hosts.length - 10} more` : "");
      const plural = issue.hosts.length === 1 ? "" : "s";
      if (issue.state === "expired") {
        const ago = -issue.daysUntilExpiry;
        findings.push({
          checkId: `subdomain-certs.expired:${issue.certName}`,
          severity: "medium",
          title: `Expired certificate on subdomain${plural}: ${issue.hosts[0]}${issue.hosts.length > 1 ? ` (+${issue.hosts.length - 1})` : ""}`,
          detail: `The certificate for ${issue.certName} (issued by ${issue.issuer}) expired ${issue.validTo}, ${ago} day${ago === 1 ? "" : "s"} ago. It is still served on ${shown}, so anyone visiting gets a full-page browser warning. If a hostname is no longer used, delete its DNS record rather than renewing — a forgotten host is an easy way in.`,
          remediation: FIX.SUBDOMAIN_CERT_EXPIRED,
        });
      } else {
        findings.push({
          checkId: `subdomain-certs.expiring:${issue.certName}`,
          severity: issue.daysUntilExpiry <= 7 ? "medium" : "low",
          title: `Certificate expiring in ${issue.daysUntilExpiry} day${issue.daysUntilExpiry === 1 ? "" : "s"} on subdomain${plural}: ${issue.hosts[0]}${issue.hosts.length > 1 ? ` (+${issue.hosts.length - 1})` : ""}`,
          detail: `The certificate for ${issue.certName} (issued by ${issue.issuer}) expires ${issue.validTo}. It is served on ${shown}. If it isn't renewed in time, those addresses show a browser warning instead of your content.`,
          remediation: FIX.SUBDOMAIN_CERT_EXPIRING,
        });
      }
    }
  }

  // --- End-of-life software -------------------------------------------------
  // Keyed by product, not version: an upgrade to a supported release should
  // read as "fixed", not as a new finding. Approaching and unsupported are
  // separate ids so crossing the date reads as a change.
  if (results.endOfLife?.status === "checked") {
    for (const item of results.endOfLife.items) {
      const vendorNote = item.packagedBy
        ? ` The version was reported alongside "${item.packagedBy}", so this is probably a distribution package: distributions keep backporting security fixes into the versions they ship after upstream stops. Check that your ${item.packagedBy} release still receives updates for it.`
        : "";
      if (item.state === "unsupported") {
        const when = item.eolDate ? `on ${item.eolDate}${item.daysOverdue !== null ? ` (${item.daysOverdue} day${item.daysOverdue === 1 ? "" : "s"} ago)` : ""}` : "";
        findings.push({
          checkId: `eol.unsupported:${item.product}`,
          severity: eolSeverity(item.kind, item.daysOverdue, item.packagedBy),
          title: `End-of-life software: ${item.label} ${item.version}`,
          detail: `${item.label} ${item.cycle} reached end of life${when ? ` ${when}` : ""}, according to endoflife.date. Its maintainers no longer publish security fixes for it, so vulnerabilities found from now on stay unfixed.${vendorNote}`,
          remediation: FIX.endOfLifeRemediation(item.label, item.cycle, item.eolDate, item.product, item.packagedBy),
        });
      } else {
        findings.push({
          checkId: `eol.approaching:${item.product}`,
          severity: "info",
          title: `${item.label} ${item.cycle} reaches end of life on ${item.eolDate}`,
          detail: `${item.label} ${item.version} is on the ${item.cycle} release line, which stops receiving security fixes in ${item.daysLeft} day${item.daysLeft === 1 ? "" : "s"}, according to endoflife.date. Plan the upgrade now rather than after the date.`,
          remediation: FIX.endOfLifeRemediation(item.label, item.cycle, item.eolDate, item.product, null),
        });
      }
    }
  }

  if (results.takeover?.status === "checked") {
    for (const record of results.takeover.dangling) {
      findings.push({
        checkId: `takeover.dangling-cname:${record.host}`,
        severity: record.confidence === "high" ? "high" : "medium",
        title: `Dangling DNS record: ${record.host} points to an unclaimed ${record.provider} resource`,
        detail: `${record.host} is a CNAME to ${record.cname}, and ${record.evidence}.${record.confidence === "high" ? " Anyone can create a resource with that name and serve content on your subdomain." : " Whether someone else can claim it depends on the provider's current verification — the record is dangling either way."}`,
        remediation: FIX.danglingCnameRemediation(record.host, record.cname, record.provider),
      });
    }
  }

  // --- Domain registration (RDAP) -------------------------------------------
  if (results.domainRegistration?.status === "checked") {
    const reg = results.domainRegistration;
    const by = reg.registrar ? ` Registrar: ${reg.registrar}.` : "";
    if (reg.daysUntilExpiry !== null && reg.daysUntilExpiry < 0) {
      findings.push({
        checkId: "domain.expired",
        severity: "high",
        title: `Domain registration for ${reg.domain} has expired`,
        detail: `The registry lists ${reg.domain} as expiring on ${reg.expiresAt}. Renew it before the registrar's grace period ends.${by}`,
        remediation: FIX.DOMAIN_EXPIRING,
      });
    } else if (reg.daysUntilExpiry !== null && reg.daysUntilExpiry <= 30) {
      findings.push({
        checkId: "domain.expiring",
        severity: reg.daysUntilExpiry <= 14 ? "high" : "medium",
        title: `Domain ${reg.domain} expires in ${reg.daysUntilExpiry} day${reg.daysUntilExpiry === 1 ? "" : "s"}`,
        detail: `The registry lists the registration as expiring on ${reg.expiresAt}. If auto-renew is on and the card on file is valid, this will renew itself — otherwise the website and email stop working.${by}`,
        remediation: FIX.DOMAIN_EXPIRING,
      });
    }
    if (reg.transferLocked === false) {
      findings.push({
        checkId: "domain.transfer-lock-missing",
        severity: "low",
        title: `No registrar transfer lock on ${reg.domain}`,
        detail: `The registry record has no "transfer prohibited" status (statuses: ${reg.statuses.join(", ") || "none"}).${by}`,
        remediation: FIX.DOMAIN_TRANSFER_LOCK,
      });
    }
  }

  // --- Third-party script inventory (PCI DSS 6.4.3 / 11.6.1) ----------------
  // One finding per third-party origin, open for as long as the page loads
  // from it: it closes when the customer authorises the origin (accepts the
  // finding with a justification) or the page stops loading it. Low on a
  // page with payment signals, where 6.4.3 applies directly. A "partial"
  // inventory (no headless browser) still evidences every origin it lists.
  const inventory = results.scriptInventory;
  if (inventory?.status === "checked" || inventory?.status === "partial") {
    const { detected, signals } = inventory.paymentPage;
    const context = detected
      ? `This page looks like a payment page (${signals.join("; ")}), so PCI DSS v4.0.1 applies to every script on it: requirement 6.4.3 needs each one inventoried, authorised and backed by a written business or technical justification, and 11.6.1 needs unauthorised changes to them detected.`
      : "This page shows no payment signals (card fields, a checkout form or a payment provider's script), so for PCI DSS this is good practice here rather than a requirement. If your checkout loads the same scripts (through a site-wide tag manager, for example), requirements 6.4.3 (inventory, authorisation and justification for every payment-page script) and 11.6.1 (detecting unauthorised changes) apply there.";
    for (const entry of inventory.origins) {
      const onPayment = detected || !!entry.paymentPages?.length;
      const entryContext = detected || !entry.paymentPages?.length
        ? context
        : `One of the pages that loads it looks like a payment page (${entry.paymentPages!.join(", ")}), so PCI DSS v4.0.1 applies to every script on it: requirement 6.4.3 needs each one inventoried, authorised and backed by a written business or technical justification, and 11.6.1 needs unauthorised changes to them detected.`;
      const shown = entry.origin.replace(/^https:\/\//, "");
      const more = entry.scriptCount > entry.sampleUrls.length ? ` (and ${entry.scriptCount - entry.sampleUrls.length} more)` : "";
      findings.push({
        checkId: `script-inventory.unreviewed:${entry.origin}`,
        // An inventory entry, not a vulnerability: "info" (no score cost) on
        // ordinary pages, "low" where payment signals make PCI 6.4.3 apply.
        // Owner decision 2026-10-05 — a typical site loads ~10 sources, and
        // charging each would cut scores ~20 points for normal analytics.
        severity: onPayment ? "low" : "info",
        title: `Unreviewed third-party script source: ${shown}`,
        detail: `This page runs JavaScript from ${entry.origin}, ${foundByPhrase(entry.foundBy)}. Scripts: ${entry.sampleUrls.join(", ")}${more}. ${integrityPhrase(entry.integrity)} ${entryContext} It stays listed as unreviewed until you authorise it: use "Mark as accepted / authorised" on this finding and record why the script is needed. Every scan compares this list with the previous one, so a script source that appears or disappears shows as New or Fixed.`,
        remediation: FIX.scriptInventoryRemediation(entry.origin, onPayment),
      });
    }
  }

  // --- Cookie consent / tracker-before-consent (PECR/GDPR) --------------------
  // Known analytics/marketing trackers (by cookie name or request host) fired
  // on the no-interaction load with no consent-management platform on the
  // page. A page with a CMP is silent (we can't prove pre-consent firing
  // without driving the banner); not_applicable/partial/error produce nothing.
  if (results.cookieConsent?.status === "checked") {
    for (const tracker of results.cookieConsent.trackers) {
      const key = tracker.kind === "cookie" ? tracker.name : tracker.host;
      findings.push({
        checkId: `cookie-consent.tracker-before-consent:${key}`,
        severity: "medium",
        title: `Tracker set before consent: ${tracker.detail}`,
        detail: `${tracker.detail} was ${tracker.kind === "cookie" ? "set" : "requested"} on the initial page load, before any consent was given, and no cookie-consent banner (CMP) was detected on the page. Under UK PECR and GDPR, analytics and marketing cookies/trackers need the visitor's consent *before* they fire — a non-essential cookie set on arrival with no banner at all is the most common compliance gap for small-business sites.`,
        remediation: FIX.COOKIE_CONSENT_TRACKER,
      });
    }
    if (results.cookieConsent.trackers.length > 0) {
      // Only emitted alongside real trackers: "no CMP" is only a problem when
      // there's something that needs consent in the first place.
      findings.push({
        checkId: "cookie-consent.no-cmp-detected",
        severity: "info",
        title: "No cookie-consent banner detected despite trackers present",
        detail: `This page loads analytics or marketing trackers but no consent-management platform (OneTrust, Cookiebot, Osano, CookieYes, and similar) was detected in its scripts or markup. A compliant site presents a banner that blocks non-essential cookies until the visitor opts in.`,
        remediation: FIX.COOKIE_CONSENT_NO_CMP,
      });
    }
  }

  // --- Live-site JS secrets / endpoints ---------------------------------------
  // High-confidence API keys/tokens and internal endpoints shipped to the
  // browser. Supabase/Firebase/JWT/framework-key material is owned by other
  // checks and skipped inside jsSecrets.ts, so nothing is double-reported.
  findings.push(...buildJsSecretsFindings(results.jsSecrets));

  findings.push(...buildGraphqlFindings(results.graphql));

  // --- Supabase / Firebase backend exposure -------------------------------------
  // Only reported with evidence: a service_role key in client code, a table
  // the anon key can read rows from (count above zero), a bucket that lists a
  // file, or a Firebase store that returned a key, object or document.
  // "not_applicable" (neither on the page) and "error" produce nothing.
  if (results.backendExposure?.status === "checked") {
    for (const project of results.backendExposure.projects) {
      if (project.serviceKey) {
        findings.push({
          checkId: `backend-exposure.service-key:${project.ref}`,
          severity: "critical",
          title: "Supabase service_role key exposed in client-side code",
          detail: `A key with the service_role role for project ${project.ref} (${project.serviceKey.fingerprint}) is delivered to every visitor in ${project.serviceKey.foundIn}. That key bypasses row level security, so anyone who copies it has full read and write access to the whole database.`,
          remediation: FIX.BACKEND_SERVICE_KEY,
        });
      }
      for (const t of project.openTables) {
        findings.push({
          checkId: `backend-exposure.open-table:${project.ref}:${t.table}`,
          severity: "high",
          title: `Supabase table "${t.table}" is readable without signing in`,
          detail: `The public anon key for project ${project.ref} can read the "${t.table}" table: the API reports ${t.rowCount} row${t.rowCount === 1 ? "" : "s"} visible with no login. We asked only for the row count and read no data. Row level security is off for this table, or a policy allows everyone.`,
          remediation: FIX.backendOpenTableRemediation(t.table),
        });
      }
      for (const b of project.openBuckets ?? []) {
        findings.push({
          checkId: `backend-exposure.storage-bucket:${project.ref}:${b.bucket}`,
          severity: "medium",
          title: `Supabase storage bucket "${b.bucket}" can be listed without signing in`,
          detail: `The public anon key for project ${project.ref} can list the files in the "${b.bucket}" bucket. We asked for one file name and downloaded nothing. A storage policy lets anonymous visitors select from this bucket.`,
          remediation: FIX.backendStorageBucketRemediation(b.bucket),
        });
      }
    }
    for (const f of results.backendExposure.firebase?.open ?? []) {
      if (f.kind === "rtdb") {
        findings.push({
          checkId: `backend-exposure.firebase-rtdb:${new URL(f.url).hostname}`,
          severity: "high",
          title: "Firebase Realtime Database is readable without signing in",
          detail: `The database at ${f.url}, named in this site's Firebase config, answers an unauthenticated read of its root: ${f.keyCount} top-level key${f.keyCount === 1 ? "" : "s"}. We asked only for key names (a shallow read) and read no values. The security rules allow reads from the root, so anyone can download the whole database.`,
          remediation: FIX.FIREBASE_RTDB_OPEN,
        });
      } else if (f.kind === "storage") {
        findings.push({
          checkId: `backend-exposure.firebase-storage:${f.bucket}`,
          severity: "medium",
          title: "Firebase Storage bucket can be listed without signing in",
          detail: `The bucket ${f.bucket}, named in this site's Firebase config, lists its files to anyone. We asked for one file name and downloaded nothing.`,
          remediation: FIX.FIREBASE_STORAGE_OPEN,
        });
      } else {
        findings.push({
          checkId: `backend-exposure.firestore:${f.project}:${f.collection}`,
          severity: "high",
          title: `Firestore collection "${f.collection}" is readable without signing in`,
          detail: `The "${f.collection}" collection in Firebase project ${f.project}, which this site's code reads, returns documents to an unauthenticated request. We asked for one document name only and read no fields.`,
          remediation: FIX.firestoreOpenRemediation(f.collection),
        });
      }
    }
  }

  // --- Site crawl (E-70) ------------------------------------------------------
  // Page-level issues on pages beyond the one scanned. "partial" still
  // evidences what it saw; findingLifecycle.ts won't resolve on it.
  findings.push(...buildCrawlFindings(results.crawl));
  // Injected content / malware traces from the same crawl (malware.* namespace).
  findings.push(...buildMalwareFindings(results.crawl));

  if (findings.length === 0) {
    findings.push({ checkId: "meta.no-issues", severity: "info", title: "No issues found by automated checks", detail: "Passive and active checks completed — no findings. Manual review recommended for business logic flaws.", remediation: FIX.NO_ISSUES });
  }

  // Compliance mapping and fix-difficulty rating are both final passes over
  // the whole set, not something any individual push site needs to know
  // about — see compliance.ts's and fixDifficulty.ts's headers.
  for (const finding of findings) {
    const refs = getComplianceRefs(finding.checkId);
    if (refs.length > 0) finding.complianceRefs = refs;

    const difficulty = getFixDifficulty(finding.checkId);
    if (difficulty) {
      finding.fixDifficulty = difficulty;
      finding.estimatedFixMinutes = estimateFixMinutes(difficulty);
    }
  }

  const topTitles = findings.slice(0, 3).map((f) => f.title).join("; ");
  const summary = `Security scan of ${results.target_url}: ${topTitles}.`;
  return { summary, findings };
}

// Severity penalty, weighted by CVSS / CISA KEV / EPSS where a finding carries
// them — see riskScore.ts. Findings with no such intel cost their flat penalty.
export function scoreFromFindings(findings: Finding[]): number {
  return scoreFromPenalties(findings);
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
