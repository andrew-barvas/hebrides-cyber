// Maps findings to real compliance/framework references — Cyber Essentials
// (UK NCSC scheme, strong fit given this product's Hebrides/UK positioning),
// OWASP Top 10:2021, CIS Controls v8, ISO/IEC 27001 (Annex A, 2013 domain
// numbering — more widely recognised in SME conversations than the 2022
// theme restructuring), PCI DSS v4.0, the EU NIS2 Directive, and the EU
// Digital Operational Resilience Act (DORA). Additive enrichment only:
// applied as a final pass over an already-built Finding[] in
// summariseResults(), keyed by checkId, so no individual finding-push call
// site needs to know this module exists.
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

export type ComplianceFramework =
  | "cyber-essentials"
  | "owasp-top-10"
  | "cis-controls-v8"
  | "iso-27001"
  | "pci-dss"
  | "nis2"
  | "dora";

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
const OWASP_A07: ComplianceRef = { framework: "owasp-top-10", control: "A07:2021 – Identification and Authentication Failures" };
const OWASP_A08: ComplianceRef = { framework: "owasp-top-10", control: "A08:2021 – Software and Data Integrity Failures" };

const CIS_3: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 3 – Data Protection" };
const CIS_4: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 4 – Secure Configuration of Enterprise Assets and Software" };
const CIS_7: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 7 – Continuous Vulnerability Management" };
const CIS_9: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 9 – Email and Web Browser Protections" };
const CIS_12: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 12 – Network Infrastructure Management" };
const CIS_16: ComplianceRef = { framework: "cis-controls-v8", control: "CIS Control 16 – Application Software Security" };

const ISO_A8: ComplianceRef = { framework: "iso-27001", control: "A.8 – Asset Management" };
const ISO_A9: ComplianceRef = { framework: "iso-27001", control: "A.9 – Access Control" };
const ISO_A12: ComplianceRef = { framework: "iso-27001", control: "A.12 – Operations Security" };
const ISO_A13: ComplianceRef = { framework: "iso-27001", control: "A.13 – Communications Security" };

const PCI_REQ4: ComplianceRef = { framework: "pci-dss", control: "Requirement 4 – Protect Cardholder Data with Strong Cryptography During Transmission" };
const PCI_REQ6: ComplianceRef = { framework: "pci-dss", control: "Requirement 6 – Develop and Maintain Secure Systems and Software" };
const PCI_REQ8: ComplianceRef = { framework: "pci-dss", control: "Requirement 8 – Identify Users and Authenticate Access to System Components" };

const NIS2_ART21: ComplianceRef = { framework: "nis2", control: "Article 21 – Cybersecurity Risk-Management Measures" };

const DORA_ART9: ComplianceRef = { framework: "dora", control: "Article 9 – ICT Risk Protection and Prevention" };

const COMPLIANCE_MAP: Record<string, ComplianceRef[]> = {
  // --- TLS ---
  "tls.no-https": [CE_SECURE_CONFIG, OWASP_A02, CIS_3, PCI_REQ4, ISO_A13, NIS2_ART21, DORA_ART9],
  "tls.weak-protocol": [CE_SECURE_CONFIG, OWASP_A02, CIS_3, PCI_REQ4, ISO_A13, NIS2_ART21],
  "tls.cert-expiring": [CE_SECURE_CONFIG, OWASP_A02, PCI_REQ4, ISO_A13],
  "tls.self-signed": [CE_SECURE_CONFIG, OWASP_A02, PCI_REQ4, ISO_A13],
  "tls.hsts-missing": [OWASP_A02, CIS_3, PCI_REQ4, ISO_A13],
  "tls.hsts-short": [OWASP_A02, CIS_3, PCI_REQ4, ISO_A13],

  // --- Headers ---
  "headers.missing-critical": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12, NIS2_ART21],
  "headers.missing-recommended": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "headers.csp-absent": [OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "headers.csp-weak": [OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "headers.cors-wildcard": [OWASP_A05, OWASP_A01, CIS_4, PCI_REQ6, ISO_A9],
  "headers.info-disclosure": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12],

  // --- DNS / email ---
  "dns.spf-missing": [CIS_9, ISO_A13],
  "dns.spf-issues": [CIS_9, ISO_A13],
  "dns.dkim-issues": [CIS_9, ISO_A13],
  "dns.dmarc-missing": [CIS_9, ISO_A13],
  "dns.dmarc-none": [CIS_9, ISO_A13],
  "dns.caa-missing": [OWASP_A05, CIS_4, ISO_A13],
  "dns.dnssec-missing": [CIS_4, ISO_A12, NIS2_ART21],
  "dns.mta-sts-missing": [CIS_9, ISO_A13],
  "dns.mta-sts-issues": [CIS_9, ISO_A13],
  "dns.tls-rpt-missing": [CIS_9, ISO_A13],
  "dns.tls-rpt-issues": [CIS_9, ISO_A13],

  // --- Exposure / directory / cloud ---
  "exposure.exposed-file": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "directory-listing.open-directory": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "cloud-misconfig.public-bucket": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "wayback-discovery.live-path": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12],

  // --- Fingerprint / outdated software ---
  "fingerprint.risky-library": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A8, ISO_A12, NIS2_ART21],

  // --- Playwright ---
  "playwright.mixed-content": [OWASP_A02, CIS_3, PCI_REQ4, ISO_A13],

  // --- Ports ---
  "ports.risky-port": [CE_FIREWALLS, OWASP_A05, CIS_12, CIS_4, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],

  // --- Recon ---
  "recon.shodan-cves": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],

  // --- Web app ---
  "webapp.dangerous-methods": [OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "webapp.error-disclosure": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12],
  "webapp.wp-xmlrpc": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "webapp.wp-user-enum": [CE_ACCESS, OWASP_A05, OWASP_A01, CIS_4, PCI_REQ8, ISO_A9],
  "webapp.wp-debug-log": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, ISO_A12],
  "webapp.wp-readme": [CE_PATCHING, OWASP_A05, PCI_REQ6, ISO_A12],
  "webapp.wp-cron": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12],
  "webapp.joomla-version-disclosed": [CE_PATCHING, OWASP_A05, PCI_REQ6, ISO_A12],
  "webapp.joomla-install-files": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12],
  "webapp.drupal-version-disclosed": [CE_PATCHING, OWASP_A05, PCI_REQ6, ISO_A12],
  "webapp.drupal-update-php": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, ISO_A9, ISO_A12],
  "webapp.drupal-jsonapi-exposed": [OWASP_A05, OWASP_A01, ISO_A9],
  "webapp.drupal-uid1-enumerable": [CE_ACCESS, OWASP_A05, OWASP_A01, PCI_REQ8, ISO_A9],
  "webapp.cors-reflected-creds": [CE_ACCESS, OWASP_A01, OWASP_A05, CIS_4, PCI_REQ8, ISO_A9],
  "webapp.cors-reflected": [OWASP_A01, OWASP_A05, CIS_4, ISO_A9],
  "webapp.vulnerable-js-lib": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "webapp.missing-sri": [OWASP_A08, CIS_16, PCI_REQ6, ISO_A12],

  // --- Third-party threat intel ---
  "safe-browsing.flagged": [CE_MALWARE, CIS_9, CIS_7, NIS2_ART21, DORA_ART9],

  // --- WPScan Vulnerability Database ---
  "wpvdb.plugin-vulnerability": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],

  // --- Software CVE DB (E-24) — WordPress core / PHP / Apache CVE matches,
  // same "outdated software" category as fingerprint.risky-library above.
  "softwareCveDb.wordpressCore": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A8, ISO_A12, NIS2_ART21],
  "softwareCveDb.nvdCpe": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A8, ISO_A12, NIS2_ART21],

  // --- Extended tool suite (scheduled scans only) ---
  "sqlmap.sqli": [OWASP_A03, CE_SECURE_CONFIG, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],
  "xsser.xss": [OWASP_A03, CE_SECURE_CONFIG, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],
  "commix.command-injection": [OWASP_A03, CE_SECURE_CONFIG, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],
  "nmap.dangerous-port": [CE_FIREWALLS, OWASP_A05, CIS_12, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],
  "secretScan.exposed-secret": [OWASP_A02, CE_SECURE_CONFIG, CIS_3, CIS_16, PCI_REQ8, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "dependency-manifest.npm": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "dependency-manifest.pip": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "dependency-manifest.composer": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "dependency-manifest.additional-vulnerable": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "docker-base-image.unpinned-tag": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12],
  "docker-base-image.outdated-base": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  // Same family as dependency-manifest.*/docker-base-image.outdated-base —
  // a real, installed-package CVE inside the base image.
  "trivy-image.vulnerable-package": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  // Same family as docker-base-image.unpinned-tag — a build/infra
  // configuration weakness, not a vulnerable component.
  "trivy-config.misconfiguration": [CE_SECURE_CONFIG, OWASP_A05, ISO_A12, NIS2_ART21],

  // --- Authenticated scanning (Sprint 3) ---
  "auth-check.missing-headers": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "auth-check.csp-absent": [OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "auth-check.session-cookie-insecure": [CE_ACCESS, OWASP_A05, OWASP_A01, CIS_4, PCI_REQ8, ISO_A9],
  "auth-check.cors-wildcard": [CE_ACCESS, OWASP_A01, OWASP_A05, CIS_4, PCI_REQ8, ISO_A9],

  // --- WAF detection ---
  "whatwaf.no-waf": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, NIS2_ART21],
  "whatwaf.waf-bypass": [CE_SECURE_CONFIG, OWASP_A05, CIS_4],

  // --- WPScan CLI ---
  "wpscan.theme-vulnerability": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "wpscan.config-backup": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "wpscan.db-export": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "wpscan.timthumb": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],

  // --- CMSmap ---
  "cmsmap.vulnerability": [CE_PATCHING, OWASP_A06, CIS_7, PCI_REQ6, ISO_A12, NIS2_ART21],
  "cmsmap.misconfiguration": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],

  // --- OSINT / metadata ---
  "metadataLeak.email": [OWASP_A05, CIS_3, ISO_A9],
  "metadataLeak.internal-ip": [OWASP_A05, CIS_3, ISO_A9, NIS2_ART21],
  "metadataLeak.path": [OWASP_A05, CIS_3, ISO_A9],
  "metadataLeak.author": [OWASP_A05, CIS_3],

  // --- ZAP AJAX Spider ---
  "zapAjaxSpider.hidden-endpoint": [OWASP_A05, CIS_3],

  // --- API scanning (Kiterunner / Arjun) ---
  "kiterunner.hidden-api-endpoint": [OWASP_A05, CIS_3],
  "arjun.hidden-parameter": [OWASP_A05, CIS_3],

  // --- Session / business logic ---
  "sessionCheck.no-rate-limit": [OWASP_A07, CIS_16],
  "sessionCheck.session-fixation": [OWASP_A07, CIS_16],
  "sessionCheck.idor-indicator": [OWASP_A01, CIS_3],

  // --- Cloud posture (E-32) ---
  "cloudPosture.awsPublicS3": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "cloudPosture.awsPublicS3Policy": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "cloudPosture.awsAccountPublicAccess": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4, ISO_A12, NIS2_ART21],
  "cloudPosture.azurePublicBlob": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "cloudPosture.azureHttpTraffic": [CE_SECURE_CONFIG, OWASP_A02, CIS_3, PCI_REQ4, ISO_A13, NIS2_ART21],
  "cloudPosture.azureWeakTls": [CE_SECURE_CONFIG, OWASP_A02, CIS_3, PCI_REQ4, ISO_A13],
  "cloudPosture.gcpPublicBucket": [CE_SECURE_CONFIG, OWASP_A05, OWASP_A01, CIS_3, CIS_4, PCI_REQ6, ISO_A9, ISO_A12, NIS2_ART21, DORA_ART9],
  "cloudPosture.gcpPublicAccessPrevention": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4, ISO_A12, NIS2_ART21],
  "cloudPosture.gcpUniformAccess": [CE_SECURE_CONFIG, OWASP_A05, CIS_3, CIS_4, ISO_A12, NIS2_ART21],

  // --- Strix AI pentest (Sprint 18) ---
  "strix.finding": [CE_SECURE_CONFIG, OWASP_A03, OWASP_A05, CIS_7, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],

  // --- Cairn autonomous exploitation (AGPL-3.0, subprocess-isolated) ---
  "cairn.finding": [CE_SECURE_CONFIG, OWASP_A03, OWASP_A05, OWASP_A01, CIS_7, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],

  // --- API spec scanning (E-33) ---
  "api-spec.auth-bypass": [CE_ACCESS, OWASP_A01, OWASP_A07, CIS_16, PCI_REQ8, ISO_A9, NIS2_ART21, DORA_ART9],
  "api-spec.method-confusion": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, CIS_16, PCI_REQ6, ISO_A12],
  "api-spec.schema-violation": [CE_SECURE_CONFIG, OWASP_A05, CIS_16, PCI_REQ6, ISO_A12],
  "api-spec.excessive-data": [CE_SECURE_CONFIG, OWASP_A01, CIS_3, CIS_16, PCI_REQ6, ISO_A9, NIS2_ART21],
  "api-spec.undocumented-fields": [CE_SECURE_CONFIG, OWASP_A01, CIS_3, CIS_16, PCI_REQ6, ISO_A9],
  "api-spec.sqli": [OWASP_A03, CE_SECURE_CONFIG, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],
  "api-spec.xss": [OWASP_A03, CE_SECURE_CONFIG, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],
  "api-spec.sqli-path": [OWASP_A03, CE_SECURE_CONFIG, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21, DORA_ART9],

  // --- Business logic (passive) ---
  "business-logic.csrf-missing": [CE_SECURE_CONFIG, OWASP_A01, CIS_16, PCI_REQ6, ISO_A12],
  "business-logic.external-form-action": [OWASP_A05, CIS_16, ISO_A12],
  "business-logic.autocomplete-sensitive": [CE_SECURE_CONFIG, OWASP_A05, CIS_4, PCI_REQ6, ISO_A12],
  "business-logic.sequential-url": [OWASP_A01, CIS_16, ISO_A12],
  "business-logic.predictable-ids": [OWASP_A01, CIS_3, CIS_16, PCI_REQ6, ISO_A9],
  "business-logic.open-redirect": [CE_SECURE_CONFIG, OWASP_A01, CIS_16, PCI_REQ6, ISO_A12, NIS2_ART21],
  "business-logic.no-rate-limit": [CE_ACCESS, OWASP_A07, CIS_16, PCI_REQ8, ISO_A9],
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
  "iso-27001": "ISO 27001",
  "pci-dss": "PCI DSS",
  "nis2": "NIS2",
  "dora": "DORA",
};

/**
 * The full set of controls this app's mapping ever cites per framework —
 * derived from COMPLIANCE_MAP itself (never a hand-maintained second list
 * that could drift out of sync with it). Used as a fixed denominator for
 * "coverage" calculations (e.g. E-28's compliance-trend chart): "how many
 * of the controls we actually check for are currently clean" needs a
 * stable universe of controls to divide by, not just whichever ones
 * happen to appear in one scan's findings.
 */
export const ALL_CONTROLS_BY_FRAMEWORK: Record<ComplianceFramework, ReadonlySet<string>> = (() => {
  // Seeded from COMPLIANCE_FRAMEWORK_LABELS' own keys rather than a second
  // hand-typed framework list, so this can never drift out of sync with the
  // ComplianceFramework union the way a hand-listed Record would.
  const frameworks = Object.keys(COMPLIANCE_FRAMEWORK_LABELS) as ComplianceFramework[];
  const byFramework = Object.fromEntries(frameworks.map((f) => [f, new Set<string>()])) as Record<
    ComplianceFramework,
    Set<string>
  >;
  for (const refs of Object.values(COMPLIANCE_MAP)) {
    for (const ref of refs) byFramework[ref.framework].add(ref.control);
  }
  return byFramework;
})();
