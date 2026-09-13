// Critical Path Analysis — docs/24-FEATURE-EXPANSION-SPEC.md #9. Pure
// derived logic: no new scanner, no schema change, no scoring change (see
// this module's own note on that below). Matches *combinations* of
// checkId bases already present in one scan's findings against a small,
// hand-curated rule table, surfacing genuine "these two findings together
// are worse than either alone" narratives rather than a generic list.
//
// Deliberately informational-only for v1 — NOT fed into scoreFromFindings.
// The underlying findings are already scored individually; compounding a
// chain into an extra penalty would need real calibration against actual
// scan data first, not a number picked out of thin air. Noted as a
// possible v2 idea, not built speculatively now.
import type { Finding } from "./scanners";

export type CriticalPath = {
  title: string;
  narrative: string;
  /** The actual checkIds (with any :key suffix) that triggered this chain — for cross-referencing/highlighting in the UI. */
  findingCheckIds: string[];
  severity: Finding["severity"];
};

type ChainRule = {
  title: string;
  narrative: string;
  /**
   * Every entry must have at least one matching finding for the rule to
   * fire. An entry ending in ".*" matches any checkId from that module
   * (e.g. "secretScan.*" matches any secretScan.<check-name>[:key]
   * checkId, regardless of which specific check within that module fired);
   * anything else matches a specific checkId base exactly.
   */
  requires: string[];
  severity: Finding["severity"];
};

function baseOf(checkId: string): string {
  const idx = checkId.indexOf(":");
  return idx === -1 ? checkId : checkId.slice(0, idx);
}

function moduleOf(checkId: string): string {
  return checkId.split(".")[0];
}

function matchesRequirement(requirement: string, findings: Finding[]): Finding[] {
  if (requirement.endsWith(".*")) {
    const mod = requirement.slice(0, -2);
    return findings.filter((f) => f.checkId && moduleOf(f.checkId) === mod);
  }
  return findings.filter((f) => f.checkId && baseOf(f.checkId) === requirement);
}

const CHAIN_RULES: ChainRule[] = [
  {
    title: "Exposed .git directory could leak credentials found by secret scanning",
    narrative:
      "An exposed .git directory lets an attacker download the full repository history, including any commit that ever contained a secret — even one later removed but never purged from history. Combined with a confirmed exposed secret, this makes that leaked credential meaningfully more exploitable than either finding alone suggests.",
    requires: ["exposure.exposed-file", "secretScan.*"],
    severity: "critical",
  },
  {
    title: "A vulnerable CMS plugin combined with missing security headers increases exploit reliability",
    narrative:
      "Missing security headers (e.g. Content-Security-Policy, X-Frame-Options) remove defence-in-depth that would otherwise partially mitigate a plugin vulnerability's real-world impact — for example, limiting what an injected script can do, or preventing clickjacking. Together, a confirmed plugin vulnerability is more reliably exploitable than the two findings would suggest in isolation.",
    requires: ["wpscan.vulnerable-plugin", "headers.missing-critical"],
    severity: "high",
  },
  {
    title: "A publicly reachable database port combined with a confirmed SQL injection point compounds impact",
    narrative:
      "SQL injection alone extracts data through the vulnerable application as an intermediary. A directly reachable database port removes even that step — an attacker who obtains credentials (from this or another finding) can connect straight to the database, bypassing the application entirely.",
    requires: ["sqlmap.sqli", "nmap.dangerous-port"],
    severity: "critical",
  },
  {
    title: "A known-vulnerable dependency combined with a confirmed injection point raises the chance of full compromise",
    narrative:
      "A known-vulnerable dependency and a confirmed injection vulnerability on the same target increase the chance that a single compromise chains further — the injection point may be usable to reach and trigger the vulnerable dependency's own exploit path from inside the application.",
    requires: ["sqlmap.sqli", "dependency-manifest.*"],
    severity: "high",
  },
  {
    title: "Weak TLS combined with an insecure session cookie increases the risk of session hijacking",
    narrative:
      "A weak or self-signed TLS configuration makes it easier for an attacker positioned on the network path to intercept traffic. An insecure session cookie (missing Secure/HttpOnly flags) is exactly the kind of credential that interception would expose, letting the attacker hijack an authenticated session.",
    requires: ["tls.weak-protocol", "auth-check.session-cookie-insecure"],
    severity: "high",
  },
  {
    title: "An open directory listing combined with an exposed sensitive file broadens what an attacker can find",
    narrative:
      "An open directory listing lets an attacker browse for files beyond whatever specific sensitive path was already confirmed exposed — turning one known exposure into a broader reconnaissance foothold across the same directory tree.",
    requires: ["directory-listing.open-directory", "exposure.exposed-file"],
    severity: "high",
  },
];

export function computeCriticalPaths(findings: Finding[]): CriticalPath[] {
  const paths: CriticalPath[] = [];
  for (const rule of CHAIN_RULES) {
    const matchedGroups = rule.requires.map((req) => matchesRequirement(req, findings));
    if (matchedGroups.some((group) => group.length === 0)) continue;

    const findingCheckIds = [...new Set(matchedGroups.flat().map((f) => f.checkId).filter((id): id is string => Boolean(id)))];
    paths.push({ title: rule.title, narrative: rule.narrative, findingCheckIds, severity: rule.severity });
  }
  return paths;
}
