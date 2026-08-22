// Maps findings to real compliance/framework references — Cyber Essentials
// (UK NCSC scheme, strong fit given this product's Hebrides/UK positioning),
// OWASP Top 10:2021, and CIS Controls v8. Additive enrichment only: applied
// as a final pass over an already-built Finding[] in summariseResults(),
// keyed by checkId, so no individual finding-push call site needs to know
// this module exists.
//
// DELIBERATELY NOT EXHAUSTIVE. A checkId with no entry here gets no
// complianceRefs — that means "not yet categorised," not "irrelevant," and
// is the honest choice over force-fitting every check into a framework it
// doesn't genuinely belong to (the same "never report what you can't
// evidence" discipline the rest of this scanner suite follows). Purely
// informational findings (tech-detected, subdomains-found, security.txt
// presence, console errors) are deliberately left unmapped — they aren't
// control failures a framework would cite.
//
// Matched on the checkId's BASE — the part before the first ":" — so a
// per-instance checkId like "webapp.vulnerable-js-lib:jquery" or
// "dependency-manifest.npm:lodash" still matches the rule keyed on
// "webapp.vulnerable-js-lib" / "dependency-manifest.npm". A checkId with no
// ":" is its own base.

export type ComplianceFramework = "cyber-essentials" | "owasp-top-10" | "cis-controls-v8";

export type ComplianceRef = {
  framework: ComplianceFramework;
  /** The specific control/category name within that framework. */
  control: string;
};

const CE_SECURE_CONFIG: ComplianceRef = { framework: "cyber-essentials", control: "Secure configuration" };
const CE_FIREWALLS: ComplianceRef = { framework: "cyber-essentials", control: "Firewalls and internet gateways" };
const CE_PATCHING: ComplianceRef = { framework: "cyber-essentials", control: "Security update management" };
const CE_ACCESS: ComplianceRef = { framework: "cyber-essentials", control: "User access control" };
const CE_MALWARE: ComplianceRef = { framework: "cyber-essentials", control: "Malware protection" };

const OWASP_A01: ComplianceRef = { framework: "owasp-top-10", control: "A01:2021 – Broken Access Control" };
const OWASP_A02: ComplianceRef = { framework: "owasp-top-10", control: "A02:2021 – Cryptographic Failures" };
const OWASP_A03: ComplianceRef = { framework: "owasp-top-10", control: "A03:2021 – Injection" };
const OWASP_A05: ComplianceRef = { framework: "owasp-top-10", control: "A05:2021 – Security Misconfiguration" };
const OWASP_A06: ComplianceRef = { framework: "owasp-top-10", control: "A06:2021 – Vulnerable and Outdated Components" };
const OWASP_A08: ComplianceRef = { framework: "owasp-top-10", control: "A08:2021 – Software and Data Integrity Failures" };

const CIS_3: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 3 – Data Protection" };
const CIS_4: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 4 – Secure Configuration of Enterprise Assets and Software" };
const CIS_7: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 7 – Continuous Vulnerability Management" };
const CIS_9: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 9 – Email and Web Browser Protections" };
const CIS_12: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 12 – Network Infrastructure Management" };
const CIS_16: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 16 – Application Software Security" };

const COMPLIANCE_MAP: Record<string, ComplianceRef[]> = {
  // --- TLS ---
  "tls.no-https": [CE_SECURE_CONFIG, OWASP_A02, CIS_3],
  "tls.weak-protocol": [CE_SECURE_CONFIG, OWASP_A02, CIS_3],
  "tls.cert-expiring": [CE_SECURE_CONFIG, OWASP_A02],
  "tls.self-signed": [CE_SECURE_CONFIG, OWASP_A02],
  "tls.hsts-missing": [OWASP_A02, CIS_3],
  "tls.hsts-short": [OWASP_A02, CIS_3],

  // --- Headers ---
  "headers.missing-critical": [CE_SECURE_CONFIG, OWASP_A05, CIS_4],
  "headers.missing-recommended": [CE_SECURE_CONFIG, OWASP_A05, CIS_4],
  "headers.csp-absent": [OWASP_A05, CIS_4],
  "headers.csp-weak": [OWASP_A05, CIS_4],
  "headers.cors-wildcard": [OWASP_A05, OWASP_A01, CIS_4],
  "headers.info-disclosure": [CE_SECURE_CONFIG, OWASP_A05],

  // --- DNS / email ---
  "dns.spf-missing": [CIS_9],
  "dns.spf-issues": [CIS_9],
  "dns.dkim-issues": [CIS_9],
  "dns.dmarc-missing": [CIS_9],
  "dns.dmarc-none": [CIS_9],
  "dns.caa-missing": [OWASP_A05, CIS_4],
  "dns.dnssec-missing": [CIS_4],
  "dns.mta-sts-missing": [CIS_9],
  "dns.mta-sts-issues": [CIS_9],
  "dns.tls-rpt-missing": [CIS_9],
  "dns.tls-rpt-issues": [CIS_9],

  // --- Exposure / directory / cloud ---
  "exposure.exposed-file": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4],
  "directory-listing.open-directory": [CE_SECURE_CONFIG, OWASP_A05, CIS_4],
  "cloud-misconfig.public-bucket": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, CIS_3, CIS_4],
  "wayback-discovery.live-path": [CE_SECURE_CONFIG, OWASP_A05],

  // --- Fingerprint / outdated software ---
  "fingerprint.risky-library": [CE_PATCHING, OWASP_A06, CIS_7],

  // --- Playwright ---
  "playwright.mixed-content": [OWASP_A02, CIS_3],

  // --- Ports ---
  "ports.risky-port": [CE_FIREWALLS, OWASP_A05, CIS_12, CIS_4],

  // --- Recon ---
  "recon.shodan-cves": [CE_PATCHING, OWASP_A06, CIS_7],

  // --- Web app ---
  "webapp.dangerous-methods": [OWASP_A05, CIS_4],
  "webapp.error-disclosure": [CE_SECURE_CONFIG, OWASP_A05],
  "webapp.wp-xmlrpc": [CE_SECURE_CONFIG, OWASP_A05, CIS_4],
  "webapp.wp-user-enum": [CE_ACCESS, OWASP_A05, OWASP_A01, CIS_4],
  "webapp.wp-debug-log": [CE_SECURE_CONFIG, OWASP_A05, CIS_3],
  "webapp.wp-readme": [CE_PATCHING, OWASP_A05],
  "webapp.wp-cron": [CE_SECURE_CONFIG, OWASP_A05],
  "webapp.joomla-version-disclosed": [CE_PATCHING, OWASP_A05],
  "webapp.joomla-install-files": [CE_SECURE_CONFIG, OWASP_A05],
  "webapp.drupal-version-disclosed": [CE_PATCHING, OWASP_A05],
  "webapp.drupal-update-php": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01],
  "webapp.drupal-jsonapi-exposed": [OWASP_A05, OWASP_A01],
  "webapp.drupal-uid1-enumerable": [CE_ACCESS, OWASP_A05, OWASP_A01],
  "webapp.cors-reflected-creds": [CE_ACCESS, OWASP_A01, OWASP_A05, CIS_4],
  "webapp.cors-reflected": [OWASP_A01, OWASP_A05, CIS_4],
  "webapp.vulnerable-js-lib": [CE_PATCHING, OWASP_A06, CIS_7],
  "webapp.missing-sri": [OWASP_A08, CIS_16],

  // --- Third-party threat intel ---
  "safe-browsing.flagged": [CE_MALWARE, CIS_9, CIS_7],

  // --- WPScan Vulnerability Database ---
  "wpvdb.plugin-vulnerability": [CE_PATCHING, OWASP_A06, CIS_7],

  // --- Extended tool suite (scheduled scans only) ---
  "sqlmap.sqli": [OWASP_A03, CE_SECURE_CONFIG, CIS_16],
  "nmap.dangerous-port": [CE_FIREWALLS, OWASP_A05, CIS_12],
  "secretScan.exposed-secret": [OWASP_A02, CE_SECURE_CONFIG, CIS_3, CIS_16],
  "dependency-manifest.npm": [CE_PATCHING, OWASP_A06, CIS_7],
  "dependency-manifest.pip": [CE_PATCHING, OWASP_A06, CIS_7],
  "dependency-manifest.composer": [CE_PATCHING, OWASP_A06, CIS_7],
  "dependency-manifest.additional-vulnerable": [CE_PATCHING, OWASP_A06, CIS_7],
  "docker-base-image.unpinned-tag": [CE_SECURE_CONFIG, OWASP_A05],
  "docker-base-image.outdated-base": [CE_PATCHING, OWASP_A06, CIS_7],
};

/** The part of a checkId before its first ":" — see module header. */
function baseCheckId(checkId: string): string {
  const idx = checkId.indexOf(":");
  return idx === -1 ? checkId : checkId.slice(0, idx);
}

/** Returns [] (not undefined) when nothing maps — callers can treat an empty array and a missing checkId identically. */
export function getComplianceRefs(checkId: string | undefined): ComplianceRef[] {
  if (!checkId) return [];
  return COMPLIANCE_MAP[baseCheckId(checkId)] ?? [];
}

export const COMPLIANCE_FRAMEWORK_LABELS: Record<ComplianceFramework, string> = {
  "cyber-essentials": "Cyber Essentials",
  "owasp-top-10": "OWASP Top 10",
  "cis-controls-v8": "CIS Controls v8",
};
