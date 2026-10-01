// Estimates how much effort fixing a finding takes — a different axis from
// severity (how much risk it poses). Additive enrichment only, same shape
// and philosophy as ./compliance.ts: applied as a final pass over an
// already-built Finding[], keyed by checkId, deliberately non-exhaustive.
// An unmapped checkId gets no fixDifficulty/estimatedFixMinutes at all,
// never a forced guess — the same "never report what you can't evidence"
// discipline the rest of this scanner suite follows, applied to remediation
// effort rather than to the finding itself.
//
// Matched on the checkId's BASE — the part before the first ":" — same
// convention as compliance.ts.

export type FixDifficulty = "trivial" | "easy" | "moderate" | "hard";

const FIX_DIFFICULTY_MAP: Record<string, FixDifficulty> = {
  // --- TLS: config-only changes on an existing cert/server ---
  "tls.hsts-missing": "trivial",
  "tls.hsts-short": "trivial",
  "tls.cert-expiring": "trivial",
  "tls.self-signed": "moderate", // needs a real CA-issued certificate, not just a config flag
  "tls.cert-expired": "easy",
  "tls.cert-name-mismatch": "easy",
  "tls.cert-chain-incomplete": "trivial", // point the server at the full-chain file
  "tls.cert-untrusted": "moderate",
  "subdomain-certs.expired": "easy", // renew, or delete an unused DNS record
  "subdomain-certs.expiring": "trivial",
  "tls.weak-protocol": "moderate",
  "tls.no-https": "moderate",

  // --- Headers: mostly config, CSP needs real authoring ---
  "headers.missing-critical": "easy",
  "headers.missing-recommended": "easy",
  "headers.cors-wildcard": "easy",
  "headers.info-disclosure": "trivial",
  "headers.csp-weak": "moderate",
  "headers.csp-absent": "moderate", // needs enumerating every real script/style/connect source

  // --- DNS / email: DNS record changes ---
  "dns.spf-missing": "easy",
  "dns.spf-issues": "easy",
  "dns.dmarc-missing": "easy",
  "dns.dmarc-none": "easy",
  "dns.dkim-issues": "moderate", // needs coordination with the sending mail platform
  "dns.caa-missing": "trivial",
  "dns.mta-sts-missing": "moderate",
  "dns.mta-sts-issues": "moderate",
  "dns.tls-rpt-missing": "trivial",
  "dns.tls-rpt-issues": "trivial",
  "dns.dnssec-missing": "hard", // registrar/DNS-provider-dependent, real operational risk if misconfigured

  // --- Exposure / directory / cloud ---
  "exposure.exposed-file": "easy",
  "directory-listing.open-directory": "easy",
  "cloud-misconfig.public-bucket": "moderate",
  "wayback-discovery.live-path": "easy",

  // --- Fingerprint / outdated software ---
  "fingerprint.risky-library": "moderate",

  // --- Playwright ---
  "playwright.mixed-content": "easy",

  // --- Ports ---
  "ports.risky-port": "easy", // firewall rule change, assuming the service doesn't need to be public

  // --- Recon ---
  "recon.shodan-cves": "hard", // real patching, not a config toggle

  // --- Web app / CMS ---
  "webapp.dangerous-methods": "easy",
  "webapp.error-disclosure": "easy",
  "webapp.wp-xmlrpc": "trivial",
  "webapp.wp-user-enum": "moderate",
  "webapp.wp-debug-log": "trivial",
  "webapp.wp-readme": "trivial",
  "webapp.wp-cron": "moderate",
  "webapp.joomla-version-disclosed": "trivial",
  "webapp.joomla-install-files": "trivial",
  "webapp.drupal-version-disclosed": "trivial",
  "webapp.drupal-update-php": "trivial",
  "webapp.drupal-jsonapi-exposed": "moderate",
  "webapp.drupal-uid1-enumerable": "moderate",
  "webapp.cors-reflected-creds": "moderate",
  "webapp.cors-reflected": "easy",
  "webapp.vulnerable-js-lib": "moderate", // version bump, but can carry breaking changes
  "webapp.missing-sri": "easy",

  // --- Third-party threat intel ---
  "safe-browsing.flagged": "hard", // real malware/compromise cleanup, not a config change

  // --- WPScan Vulnerability Database ---
  "wpvdb.plugin-vulnerability": "easy", // usually a plugin update

  // --- Software CVE DB (E-24) ---
  "softwareCveDb.wordpressCore": "easy", // core update, usually low-risk/backward-compatible
  "softwareCveDb.nvdCpe": "moderate", // PHP/Apache version bumps can break compatibility

  // --- Extended tool suite (scheduled scans only) ---
  "sqlmap.sqli": "hard",
  "xsser.xss": "hard",
  "commix.command-injection": "hard",
  "nmap.dangerous-port": "easy",
  "secretScan.exposed-secret": "moderate", // rotate the credential + purge from git history
  "dependency-manifest.npm": "easy",
  "dependency-manifest.pip": "easy",
  "dependency-manifest.composer": "easy",
  "dependency-manifest.additional-vulnerable": "easy",
  "docker-base-image.unpinned-tag": "trivial",
  "docker-base-image.outdated-base": "moderate",
  "eol.unsupported": "moderate", // a major-version upgrade, usually
  "eol.approaching": "moderate",
  "trivy-image.vulnerable-package": "moderate",
  "trivy-config.misconfiguration": "moderate",

  // --- Authenticated scanning (Sprint 3) ---
  "auth-check.missing-headers": "easy",
  "auth-check.csp-absent": "moderate",
  "auth-check.session-cookie-insecure": "easy",
  "auth-check.cors-wildcard": "easy",

  // --- WAF detection ---
  "whatwaf.no-waf": "hard",
  "whatwaf.waf-bypass": "hard",

  // --- WPScan CLI ---
  "wpscan.theme-vulnerability": "easy",
  "wpscan.config-backup": "easy",
  "wpscan.db-export": "trivial",
  "wpscan.timthumb": "easy",

  // --- CMSmap ---
  "cmsmap.vulnerability": "moderate",
  "cmsmap.misconfiguration": "moderate",

  // --- OSINT / metadata leaks ---
  "metadataLeak.email": "easy",
  "metadataLeak.internal-ip": "easy",
  "metadataLeak.path": "easy",
  "metadataLeak.author": "trivial",
  "metadataLeak.software": "trivial",

  // --- ZAP AJAX Spider ---
  "zapAjaxSpider.hidden-endpoint": "moderate",

  // --- API scanning (Kiterunner / Arjun) ---
  "kiterunner.hidden-api-endpoint": "moderate",
  "arjun.hidden-parameter": "moderate",

  // --- Session / business logic ---
  "sessionCheck.no-rate-limit": "moderate",
  "sessionCheck.session-fixation": "hard",
  "sessionCheck.idor-indicator": "hard",

  // --- Strix AI pentest (Sprint 18) ---
  "strix.finding": "hard",

  // --- Cairn autonomous exploitation (AGPL-3.0, subprocess-isolated) ---
  "cairn.finding": "hard",

  // --- API spec scanning (E-33) ---
  "api-spec.auth-bypass": "moderate",   // requires wiring auth middleware, not just a config toggle
  "api-spec.method-confusion": "easy",  // restrict allowed HTTP methods on each route
  "api-spec.schema-violation": "easy",  // add server-side request validation
  "api-spec.excessive-data": "easy",    // use a serialisation layer / DTO to control response fields
  "api-spec.undocumented-fields": "easy",
  "api-spec.sqli": "hard",             // parameterised queries + full audit of query construction
  "api-spec.xss": "hard",              // output encoding + CSP, can touch many templates
  "api-spec.sqli-path": "hard",

  // --- Cloud posture (E-32): toggling a cloud console setting or running
  // one CLI command in every case, so easy across the board — "moderate"
  // reserved for the confirmed-public-policy findings, which also warrant
  // reviewing what was exposed and rotating anything sensitive, not just
  // flipping the setting back.
  "cloudPosture.awsPublicS3": "easy",
  "cloudPosture.awsPublicS3Policy": "moderate", // also warrants reviewing what was exposed
  "cloudPosture.awsAccountPublicAccess": "easy",
  "cloudPosture.azurePublicBlob": "easy",
  "cloudPosture.azureHttpTraffic": "easy",
  "cloudPosture.azureWeakTls": "easy",
  "cloudPosture.gcpPublicAccessPrevention": "easy",
  "cloudPosture.gcpUniformAccess": "moderate", // may require re-issuing signed URLs for anything relying on legacy ACLs
  "cloudPosture.gcpPublicBucket": "moderate", // also warrants reviewing what was exposed

  // --- Business logic (passive) ---
  "business-logic.csrf-missing": "moderate", // needs per-form token integration
  "business-logic.external-form-action": "easy", // verify and fix the action attribute
  "business-logic.autocomplete-sensitive": "trivial", // add autocomplete attribute
  "business-logic.sequential-url": "hard", // requires server-side workflow refactoring
  "business-logic.predictable-ids": "hard", // requires ID scheme change + auth checks
  "business-logic.open-redirect": "moderate", // validate redirect targets server-side
  "business-logic.no-rate-limit": "moderate", // add rate-limiting middleware
};

const FIX_MINUTES_BY_DIFFICULTY: Record<FixDifficulty, number> = {
  trivial: 15,
  easy: 60,
  moderate: 240,
  hard: 960,
};

/** The part of a checkId before its first ":" — see module header. */
function baseCheckId(checkId: string): string {
  const idx = checkId.indexOf(":");
  return idx === -1 ? checkId : checkId.slice(0, idx);
}

/** Returns undefined (not a guess) when the checkId is unmapped — see module header. */
export function getFixDifficulty(checkId: string | undefined): FixDifficulty | undefined {
  if (!checkId) return undefined;
  return FIX_DIFFICULTY_MAP[baseCheckId(checkId)];
}

/**
 * Rough estimate in minutes, derived from difficulty via a single fixed
 * lookup rather than a second hand-curated per-checkId map — cheaper to
 * keep consistent, and honest given these are rough estimates regardless.
 */
export function estimateFixMinutes(difficulty: FixDifficulty): number {
  return FIX_MINUTES_BY_DIFFICULTY[difficulty];
}
