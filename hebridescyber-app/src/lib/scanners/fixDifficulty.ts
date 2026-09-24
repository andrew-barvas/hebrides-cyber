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
