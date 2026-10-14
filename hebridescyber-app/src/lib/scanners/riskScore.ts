// Per-finding score penalty, and the 0–100 score built from it.
//
// Severity is still the base: it is the finding's own evidence and this module
// never changes it. What the enrichment passes (cvssEnrich.ts, threatIntel.ts)
// add is how much that finding should *cost*:
//   - CVSS: a CVE-backed finding our check rated lower than its CVSS band
//     costs at least that band's penalty.
//   - CISA KEV / ransomware use: someone is exploiting it now — costs more.
//   - FIRST EPSS: a measured probability of exploitation in the next 30 days.
//
// A finding with no CVSS and no threat intel (most of them: headers, TLS, DNS,
// exposure…) costs exactly its flat severity penalty, so those scores are
// unchanged. Absent intel means "unknown", never "safe" — it neither raises nor
// lowers anything. Only a measured EPSS can lower a penalty, and only for a
// finding that is not in KEV.

import type { Finding } from "./index";

export const SEVERITY_PENALTY: Record<Finding["severity"], number> = {
  critical: 30,
  high: 15,
  medium: 7,
  low: 2,
  info: 0,
};

/** No single finding may cost more than this, so one KEV-listed ransomware CVE can't blank the whole score by itself. */
export const MAX_PENALTY_PER_FINDING = 45;

const KEV_MULTIPLIER = 1.5;
const KEV_RANSOMWARE_MULTIPLIER = 2;
const EPSS_HIGH = 0.5;
const EPSS_ELEVATED = 0.1;
const EPSS_NEGLIGIBLE = 0.01;
const EPSS_HIGH_MULTIPLIER = 1.4;
const EPSS_ELEVATED_MULTIPLIER = 1.2;
const EPSS_NEGLIGIBLE_MULTIPLIER = 0.75;

function cvssFloor(cvss: number): number {
  if (cvss >= 9) return SEVERITY_PENALTY.critical;
  if (cvss >= 7) return SEVERITY_PENALTY.high;
  if (cvss >= 4) return SEVERITY_PENALTY.medium;
  return 0;
}

export function findingPenalty(finding: Finding): number {
  const base = SEVERITY_PENALTY[finding.severity];
  if (base === 0) return 0;

  let penalty = base;
  if (typeof finding.cvssScore === "number" && Number.isFinite(finding.cvssScore)) {
    penalty = Math.max(penalty, cvssFloor(finding.cvssScore));
  }

  const intel = finding.threatIntel;
  if (intel?.knownExploited) {
    penalty *= intel.ransomware ? KEV_RANSOMWARE_MULTIPLIER : KEV_MULTIPLIER;
  } else if (typeof intel?.epss === "number" && Number.isFinite(intel.epss)) {
    if (intel.epss >= EPSS_HIGH) penalty *= EPSS_HIGH_MULTIPLIER;
    else if (intel.epss >= EPSS_ELEVATED) penalty *= EPSS_ELEVATED_MULTIPLIER;
    else if (intel.epss < EPSS_NEGLIGIBLE) penalty *= EPSS_NEGLIGIBLE_MULTIPLIER;
  }

  return Math.min(MAX_PENALTY_PER_FINDING, penalty);
}

export function scoreFromPenalties(findings: Finding[]): number {
  const total = findings.reduce((sum, f) => sum + findingPenalty(f), 0);
  return Math.max(0, Math.round(100 - total));
}
