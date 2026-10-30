// Maps findings to the MITRE ATT&CK technique an adversary could use against
// the exposure (attack.mitre.org, Enterprise matrix) and to CWE weakness ids
// (cwe.mitre.org). Defensive context for a report reader: "why this matters",
// in a vocabulary their IT supplier or insurer already uses. It says nothing
// about how to carry the technique out, and must not: IDs, names and links
// only. Applied as a final pass alongside compliance.ts and fixDifficulty.ts
// (summariseResults() and executeScan()), keyed on the same checkId base.
//
// Mapped per finding TYPE, never per tool, and DELIBERATELY NOT EXHAUSTIVE: a
// checkId with no entry gets no refs, meaning "not yet categorised" or
// "genuinely doesn't fit", never a forced mapping (compliance.ts's rule).
// Purely informational checks (headers, CSP, WAF presence) are left out:
// they are hardening gaps, not an exposure a named technique acts on.
//
// ATT&CK IDs and names change between releases. Re-check this table against
// the current Enterprise version each quarter (DEFENSIVE-ASSESSMENT-PLAN.md).
// Checked against ATT&CK v17. Use of ATT&CK is under MITRE's terms of use,
// which require the attribution the report prints (ATTACK_ATTRIBUTION).

export type AttackRef = {
  /** Technique or sub-technique id, e.g. "T1190" or "T1552.001". */
  id: string;
  name: string;
  url: string;
};

export const ATTACK_ATTRIBUTION = "MITRE ATT&CK® is a registered trademark of The MITRE Corporation; technique references are from attack.mitre.org.";

const TECHNIQUES: Record<string, string> = {
  T1110: "Brute Force",
  T1133: "External Remote Services",
  T1189: "Drive-by Compromise",
  T1190: "Exploit Public-Facing Application",
  T1195: "Supply Chain Compromise",
  "T1195.001": "Compromise Software Dependencies and Development Tools",
  T1496: "Resource Hijacking",
  "T1491.002": "External Defacement",
  T1530: "Data from Cloud Storage",
  T1539: "Steal Web Session Cookie",
  "T1552.001": "Unsecured Credentials: Credentials In Files",
  T1557: "Adversary-in-the-Middle",
  T1566: "Phishing",
  "T1566.002": "Phishing: Spearphishing Link",
  "T1583.001": "Acquire Infrastructure: Domains",
  "T1584.001": "Compromise Infrastructure: Domains",
  "T1588.004": "Obtain Capabilities: Digital Certificates",
  T1589: "Gather Victim Identity Information",
  "T1589.002": "Gather Victim Identity Information: Email Addresses",
  T1590: "Gather Victim Network Information",
  T1592: "Gather Victim Host Information",
  "T1592.002": "Gather Victim Host Information: Software",
  T1606: "Forge Web Credentials",
  "T1608.006": "Stage Capabilities: SEO Poisoning",
};

/** attack.mitre.org path: sub-technique T1552.001 lives at /techniques/T1552/001/. */
export function attackUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

type Entry = { attack?: string[]; cwe?: string[] };

const TLS_WEAK: Entry = { attack: ["T1557"], cwe: ["CWE-327"] };
const PLAINTEXT: Entry = { attack: ["T1557"], cwe: ["CWE-319"] };
const CERT_INVALID: Entry = { attack: ["T1557"], cwe: ["CWE-295"] };
const EXPOSED_SERVICE: Entry = { attack: ["T1133", "T1190"] };
const SERVER_CVE: Entry = { attack: ["T1190"], cwe: ["CWE-1395"] };
const DEPENDENCY_CVE: Entry = { attack: ["T1195.001"], cwe: ["CWE-1395"] };
const CLIENT_LIB_CVE: Entry = { attack: ["T1189"], cwe: ["CWE-1395"] };
const SECRET_IN_FILE: Entry = { attack: ["T1552.001"], cwe: ["CWE-798"] };
const CONFIG_FILE: Entry = { attack: ["T1552.001"], cwe: ["CWE-538"] };
const PUBLIC_STORAGE: Entry = { attack: ["T1530"], cwe: ["CWE-284"] };
const VERSION_DISCLOSED: Entry = { attack: ["T1592.002"], cwe: ["CWE-200"] };
const ERROR_DISCLOSED: Entry = { attack: ["T1592"], cwe: ["CWE-209"] };
const NO_RATE_LIMIT: Entry = { attack: ["T1110"], cwe: ["CWE-307"] };
const USER_ENUM: Entry = { attack: ["T1589", "T1110"], cwe: ["CWE-204"] };
const SPOOFABLE_EMAIL: Entry = { attack: ["T1566"] };
const SQLI: Entry = { attack: ["T1190"], cwe: ["CWE-89"] };
const COMMAND_INJECTION: Entry = { attack: ["T1190"], cwe: ["CWE-78"] };
const XSS: Entry = { attack: ["T1189"], cwe: ["CWE-79"] };
const OPEN_REDIRECT: Entry = { attack: ["T1566.002"], cwe: ["CWE-601"] };
const COOKIE_FLAGS: Entry = { attack: ["T1539"], cwe: ["CWE-614"] };
const NO_SRI: Entry = { attack: ["T1195"], cwe: ["CWE-353"] };

// Every key is a real checkId base that compliance.ts also maps (the test
// holds this table to that), so a typo can't silently map nothing.
const ATTACK_MAP: Record<string, Entry> = {
  // Transport and certificates
  "tls.no-https": PLAINTEXT,
  "tls.weak-protocol": TLS_WEAK,
  "tls.cert-expired": { attack: ["T1557"], cwe: ["CWE-298"] },
  "tls.self-signed": CERT_INVALID,
  "tls.cert-untrusted": CERT_INVALID,
  "tls.cert-name-mismatch": { attack: ["T1557"], cwe: ["CWE-297"] },
  "tls.hsts-missing": PLAINTEXT,
  "crawl.mixed-content": PLAINTEXT,
  "crawl.insecure-form": PLAINTEXT,
  "playwright.mixed-content": PLAINTEXT,
  "dns.mta-sts-missing": { attack: ["T1557"] },
  "dns.caa-missing": { attack: ["T1588.004"] },

  // Email spoofing
  "dns.spf-missing": SPOOFABLE_EMAIL,
  "dns.dmarc-missing": SPOOFABLE_EMAIL,
  "dns.dmarc-none": SPOOFABLE_EMAIL,

  // Domains
  "takeover.dangling-cname": { attack: ["T1584.001"] },
  "domain.expired": { attack: ["T1583.001"] },
  "domain.expiring": { attack: ["T1583.001"] },

  // Exposed network services
  "network-exposure.open-port": EXPOSED_SERVICE,
  "nmap.dangerous-port": EXPOSED_SERVICE,
  "ports.risky-port": EXPOSED_SERVICE,

  // Known-vulnerable or unsupported software
  "recon.shodan-cves": SERVER_CVE,
  "softwareCveDb.wordpressCore": SERVER_CVE,
  "softwareCveDb.nvdCpe": SERVER_CVE,
  "wpvdb.plugin-vulnerability": SERVER_CVE,
  "wpvdb.theme-vulnerability": SERVER_CVE,
  "wpscan.theme-vulnerability": SERVER_CVE,
  "cmsmap.vulnerability": SERVER_CVE,
  "trivy-image.vulnerable-package": SERVER_CVE,
  "eol.unsupported": { attack: ["T1190"], cwe: ["CWE-1104"] },
  "webapp.vulnerable-js-lib": CLIENT_LIB_CVE,
  "fingerprint.risky-library": CLIENT_LIB_CVE,
  "dependency-manifest.npm": DEPENDENCY_CVE,
  "dependency-manifest.pip": DEPENDENCY_CVE,
  "dependency-manifest.composer": DEPENDENCY_CVE,
  "dependency-manifest.go": DEPENDENCY_CVE,
  "dependency-manifest.maven": DEPENDENCY_CVE,
  "dependency-manifest.ruby": DEPENDENCY_CVE,
  "dependency-manifest.cargo": DEPENDENCY_CVE,
  "dependency-manifest.nuget": DEPENDENCY_CVE,
  "dependency-manifest.typosquat-risk": { attack: ["T1195.001"] },
  "crawl.missing-sri": NO_SRI,
  "webapp.missing-sri": NO_SRI,

  // Credentials and sensitive files left reachable
  "exposure.exposed-file": CONFIG_FILE,
  "wpscan.config-backup": CONFIG_FILE,
  "webapp.magento-env-php-exposed": CONFIG_FILE,
  "webapp.wp-debug-log": { attack: ["T1552.001"], cwe: ["CWE-532"] },
  "js-secrets.exposed-key": SECRET_IN_FILE,
  "secretScan.exposed-secret": SECRET_IN_FILE,
  "backend-exposure.service-key": SECRET_IN_FILE,
  "webapp.shopify-admin-token-exposed": SECRET_IN_FILE,

  // Public cloud data
  "backend-exposure.open-table": PUBLIC_STORAGE,
  "backend-exposure.storage-bucket": PUBLIC_STORAGE,
  "backend-exposure.firebase-rtdb": PUBLIC_STORAGE,
  "backend-exposure.firebase-storage": PUBLIC_STORAGE,
  "backend-exposure.firestore": PUBLIC_STORAGE,
  "cloud-misconfig.public-bucket": PUBLIC_STORAGE,
  "cloudPosture.awsPublicS3": PUBLIC_STORAGE,
  "cloudPosture.awsPublicS3Policy": PUBLIC_STORAGE,
  "cloudPosture.azurePublicBlob": PUBLIC_STORAGE,
  "cloudPosture.gcpPublicBucket": PUBLIC_STORAGE,

  // Information an attacker uses to plan
  "headers.info-disclosure": VERSION_DISCLOSED,
  "webapp.joomla-version-disclosed": VERSION_DISCLOSED,
  "webapp.drupal-version-disclosed": VERSION_DISCLOSED,
  "webapp.wp-readme": VERSION_DISCLOSED,
  "crawl.error-disclosure": ERROR_DISCLOSED,
  "webapp.error-disclosure": ERROR_DISCLOSED,
  "metadataLeak.email": { attack: ["T1589.002"], cwe: ["CWE-200"] },
  "metadataLeak.internal-ip": { attack: ["T1590"], cwe: ["CWE-200"] },
  "metadataLeak.path": { attack: ["T1592"], cwe: ["CWE-200"] },

  // Sign-in and sessions
  "webapp.wp-user-enum": USER_ENUM,
  "webapp.drupal-uid1-enumerable": USER_ENUM,
  "webapp.wp-xmlrpc": { attack: ["T1110"] },
  "sessionCheck.no-rate-limit": NO_RATE_LIMIT,
  "business-logic.no-rate-limit": NO_RATE_LIMIT,
  "cloudPosture.awsIamPasswordPolicy": { attack: ["T1110"], cwe: ["CWE-521"] },
  "crawl.cookie-flags": COOKIE_FLAGS,
  "auth-check.session-cookie-insecure": COOKIE_FLAGS,
  "jwt-analysis.none-algorithm": { attack: ["T1606"], cwe: ["CWE-347"] },
  "jwt-analysis.weak-secret": { attack: ["T1606"], cwe: ["CWE-1391"] },
  "badsecrets.known-secret": { attack: ["T1606"], cwe: ["CWE-321"] },

  // Injection (found by the active profiles; the exposure profile sends none)
  "sqlmap.sqli": SQLI,
  "api-spec.sqli": SQLI,
  "api-spec.sqli-path": SQLI,
  "commix.command-injection": COMMAND_INJECTION,
  "dalfox.reflected-xss": XSS,
  "api-spec.xss": XSS,
  "playwright.dom-xss": XSS,
  "business-logic.open-redirect": OPEN_REDIRECT,

  // Signs of compromise
  "malware.hidden-iframe": { attack: ["T1189"] },
  "malware.obfuscated-script": { attack: ["T1189"] },
  "malware.cryptominer": { attack: ["T1496"] },
  "malware.defacement": { attack: ["T1491.002"] },
  "malware.seo-spam": { attack: ["T1608.006"] },
};

/** Same base rule as compliance.ts: the part before the first ":", with signed-in and katana crawl copies folded into crawl.*. */
function baseCheckId(checkId: string): string {
  const idx = checkId.indexOf(":");
  const base = idx === -1 ? checkId : checkId.slice(0, idx);
  return base.replace(/^(?:crawl\.auth|katana)\./, "crawl.");
}

/** Returns [] when nothing maps, like getComplianceRefs. */
export function getAttackRefs(checkId: string | undefined): AttackRef[] {
  if (!checkId) return [];
  return (ATTACK_MAP[baseCheckId(checkId)]?.attack ?? []).map((id) => ({ id, name: TECHNIQUES[id], url: attackUrl(id) }));
}

/** CWE ids ("CWE-89") for this finding type; [] when nothing maps. */
export function getCweIds(checkId: string | undefined): string[] {
  if (!checkId) return [];
  return ATTACK_MAP[baseCheckId(checkId)]?.cwe ?? [];
}

/** Every mapped checkId base — for the test that holds the table to real checks. */
export const ATTACK_MAPPED_CHECK_IDS: readonly string[] = Object.keys(ATTACK_MAP);

/** Every technique id the table cites — for the test that each one has a name. */
export const ATTACK_TECHNIQUE_IDS: readonly string[] = [...new Set(Object.values(ATTACK_MAP).flatMap((e) => e.attack ?? []))];

/** Adds attackRefs/cwe to findings that map. Mutates in place, like the compliance pass it runs beside. */
export function applyAttackRefs(findings: { checkId?: string; attackRefs?: AttackRef[]; cwe?: string[] }[]): void {
  for (const finding of findings) {
    const refs = getAttackRefs(finding.checkId);
    if (refs.length > 0) finding.attackRefs = refs;
    const cwe = getCweIds(finding.checkId);
    if (cwe.length > 0) finding.cwe = cwe;
  }
}
