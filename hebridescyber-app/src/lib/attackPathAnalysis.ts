// Critical Path Analysis — docs/24-FEATURE-EXPANSION-SPEC.md #9, extended to
// attack-path *graphing* (v2). Pure derived logic: no new scanner, no schema
// change, no scoring change (see this module's own note below). Matches
// *combinations* of checkId bases already present in one scan's findings
// against a small, hand-curated rule table, surfacing genuine "these findings
// together are worse than any alone" narratives rather than a generic list.
//
// v2 adds, without changing the v1 contract:
//   - ordered entry → pivot → impact `steps` on every CriticalPath, so the
//     report can draw the chain rather than only describe it. The v1 fields
//     (title/narrative/findingCheckIds/severity) are untouched, so the public
//     API (`ScanReport.critical_paths`), the webhook, and the existing report
//     UI keep working exactly as before.
//   - `computeChokepoints()`: which single finding, if fixed, collapses the
//     most chains — the "break these first" remediation-prioritisation the
//     flat v1 list couldn't express.
//
// Deliberately still informational-only — NOT fed into scoreFromFindings. The
// underlying findings are already scored individually; compounding a chain
// into an extra penalty would need real calibration against actual scan data
// first, not a number picked out of thin air. Noted as a possible v2 idea in
// the spec, still not built speculatively here.
//
// Evidence discipline (same as findingConsolidation.ts's EQUIVALENCES): a
// chain only ever fires when every requirement-bearing step has at least one
// matching finding *in this scan*. Rules are curated against real checkId
// bases — never title similarity, never a path invented from findings that
// don't actually chain. Every base referenced below is emitted by a live
// check (verified against the scanners before adding it).
import type { Finding } from "./scanners";

export type AttackStepRole = "entry" | "pivot" | "impact";

/**
 * One stage of an attack path. `entry`/`pivot` stages are backed by real
 * findings (`checkIds` lists which ones matched this stage in this scan); an
 * `impact` stage is the consequence they lead to and has no finding of its
 * own, so its `checkIds` is empty.
 */
export type AttackStep = {
  role: AttackStepRole;
  label: string;
  checkIds: string[];
};

export type CriticalPath = {
  title: string;
  narrative: string;
  /** The actual checkIds (with any :key suffix) that triggered this chain — for cross-referencing/highlighting in the UI. */
  findingCheckIds: string[];
  severity: Finding["severity"];
  /**
   * Ordered stages of the chain, entry → pivot(s) → impact (v2). Always
   * present. The union of every stage's `checkIds` equals `findingCheckIds`.
   */
  steps: AttackStep[];
};

/**
 * A finding that sits on one or more attack paths, with how many it appears
 * in. Fixing a high `pathCount` finding breaks every chain it's part of at
 * once, so this is the "remediate these first to collapse the most paths"
 * ranking the flat chain list couldn't give.
 */
export type Chokepoint = {
  checkId: string;
  /** Number of distinct attack paths this finding participates in. */
  pathCount: number;
  /** Titles of those paths, for the UI. */
  pathTitles: string[];
  /** Highest severity among the paths this finding appears on. */
  severity: Finding["severity"];
};

type ChainStepRule = {
  role: AttackStepRole;
  /** Short human label for this stage, shown as a node in the diagram. */
  label: string;
  /**
   * Which finding(s) satisfy this stage. A value ending in ".*" matches any
   * checkId from that module (e.g. "secretScan.*" matches any
   * secretScan.<check-name>[:key]); anything else matches a specific checkId
   * base exactly. Omitted for an `impact` stage — a consequence, not a
   * finding, so nothing is matched and the rule's firing never depends on it.
   */
  requires?: string;
};

type ChainRule = {
  title: string;
  narrative: string;
  severity: Finding["severity"];
  /**
   * Ordered stages. The rule fires only when every stage that has a
   * `requires` has at least one matching finding.
   */
  steps: ChainStepRule[];
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
    severity: "critical",
    steps: [
      { role: "entry", label: "Exposed .git directory", requires: "exposure.exposed-file" },
      { role: "pivot", label: "Leaked secret in history", requires: "secretScan.*" },
      { role: "impact", label: "Credential compromise" },
    ],
  },
  {
    title: "A vulnerable CMS plugin combined with missing security headers increases exploit reliability",
    narrative:
      "Missing security headers (e.g. Content-Security-Policy, X-Frame-Options) remove defence-in-depth that would otherwise partially mitigate a plugin vulnerability's real-world impact — for example, limiting what an injected script can do, or preventing clickjacking. Together, a confirmed plugin vulnerability is more reliably exploitable than the two findings would suggest in isolation.",
    severity: "high",
    steps: [
      { role: "entry", label: "Vulnerable CMS plugin", requires: "wpscan.vulnerable-plugin" },
      { role: "pivot", label: "Missing security headers", requires: "headers.missing-critical" },
      { role: "impact", label: "More reliable exploitation" },
    ],
  },
  {
    title: "A publicly reachable database port combined with a confirmed SQL injection point compounds impact",
    narrative:
      "SQL injection alone extracts data through the vulnerable application as an intermediary. A directly reachable database port removes even that step — an attacker who obtains credentials (from this or another finding) can connect straight to the database, bypassing the application entirely.",
    severity: "critical",
    steps: [
      { role: "entry", label: "SQL injection point", requires: "sqlmap.sqli" },
      { role: "pivot", label: "Exposed database port", requires: "nmap.dangerous-port" },
      { role: "impact", label: "Direct database access" },
    ],
  },
  {
    title: "A known-vulnerable dependency combined with a confirmed injection point raises the chance of full compromise",
    narrative:
      "A known-vulnerable dependency and a confirmed injection vulnerability on the same target increase the chance that a single compromise chains further — the injection point may be usable to reach and trigger the vulnerable dependency's own exploit path from inside the application.",
    severity: "high",
    steps: [
      { role: "entry", label: "Injection point", requires: "sqlmap.sqli" },
      { role: "pivot", label: "Known-vulnerable dependency", requires: "dependency-manifest.*" },
      { role: "impact", label: "Chained compromise" },
    ],
  },
  {
    title: "Weak TLS combined with an insecure session cookie increases the risk of session hijacking",
    narrative:
      "A weak or self-signed TLS configuration makes it easier for an attacker positioned on the network path to intercept traffic. An insecure session cookie (missing Secure/HttpOnly flags) is exactly the kind of credential that interception would expose, letting the attacker hijack an authenticated session.",
    severity: "high",
    steps: [
      { role: "entry", label: "Weak TLS", requires: "tls.weak-protocol" },
      { role: "pivot", label: "Insecure session cookie", requires: "auth-check.session-cookie-insecure" },
      { role: "impact", label: "Session hijacking" },
    ],
  },
  {
    title: "An open directory listing combined with an exposed sensitive file broadens what an attacker can find",
    narrative:
      "An open directory listing lets an attacker browse for files beyond whatever specific sensitive path was already confirmed exposed — turning one known exposure into a broader reconnaissance foothold across the same directory tree.",
    severity: "high",
    steps: [
      { role: "entry", label: "Open directory listing", requires: "directory-listing.open-directory" },
      { role: "pivot", label: "Exposed sensitive file", requires: "exposure.exposed-file" },
      { role: "impact", label: "Broader reconnaissance" },
    ],
  },
  // ---- v2 additions: multi-stage chains across newer checks ----
  {
    title: "A takeable subdomain combined with a loosely-scoped cookie can lead to session or account takeover",
    narrative:
      "A dangling subdomain an attacker can claim lets them serve content from a hostname the main application trusts. A session cookie that isn't locked down — missing Secure, or scoped to the parent domain so it travels to every subdomain — is then exactly what that attacker-controlled subdomain can read or set, turning a subdomain takeover into theft of an authenticated session.",
    severity: "critical",
    steps: [
      { role: "entry", label: "Subdomain takeover", requires: "takeover.dangling-cname" },
      { role: "pivot", label: "Loosely-scoped cookie", requires: "headers.cookie-flags" },
      { role: "impact", label: "Session / account takeover" },
    ],
  },
  {
    title: "A leaked service_role key combined with a publicly readable table is a confirmed data-exfiltration path",
    narrative:
      "A Supabase service_role key shipped to the browser bypasses row-level security on every table. A table that already answers to the anonymous key confirms the data store is reachable from the open internet. Together they are not two separate issues but one demonstrated path: anyone who views the page can read — or with the service_role key, modify — real records.",
    severity: "critical",
    steps: [
      { role: "entry", label: "Leaked service_role key", requires: "backend-exposure.service-key" },
      { role: "pivot", label: "Publicly readable table", requires: "backend-exposure.open-table" },
      { role: "impact", label: "Full database read/write" },
    ],
  },
  {
    title: "Exposed GraphQL introspection combined with a confirmed injection point enables targeted data extraction",
    narrative:
      "Open GraphQL introspection hands an attacker the full type and field catalogue of the API. A confirmed injection point elsewhere on the target then stops being guesswork — the attacker already knows exactly which tables, fields and resolvers to aim the injection at, making targeted extraction far more reliable.",
    severity: "high",
    steps: [
      { role: "entry", label: "GraphQL schema disclosed", requires: "graphql.introspection" },
      { role: "pivot", label: "Confirmed injection point", requires: "sqlmap.sqli" },
      { role: "impact", label: "Targeted data extraction" },
    ],
  },
  {
    title: "A secret or private endpoint in client-side JavaScript combined with an exposed sensitive file widens credential exposure",
    narrative:
      "A key or internal endpoint shipped in client-side JavaScript is readable by anyone who views the page source. An additional exposed sensitive file raises the chance that the matching secret, config, or second half of a credential pair is also sitting in the open — turning a single client-side leak into a usable set of credentials.",
    severity: "high",
    steps: [
      { role: "entry", label: "Secret/endpoint in client JS", requires: "js-secrets.*" },
      { role: "pivot", label: "Exposed sensitive file", requires: "exposure.exposed-file" },
      { role: "impact", label: "Usable credential set" },
    ],
  },
  // ---- v2.1 additions: chains across the recent scanner-depth checks ----
  {
    title: "An exposed source map combined with a client-side secret makes that secret trivial to locate and use",
    narrative:
      "A publicly readable `.map` source map reconstructs the original, un-minified source — variable names, comments and structure the minified bundle hid. When the same site also ships a high-confidence secret in its client JavaScript, the source map turns 'a key is in here somewhere' into a labelled map of exactly where it is and how it's used, collapsing the effort to weaponise it.",
    severity: "high",
    steps: [
      { role: "entry", label: "Exposed source map", requires: "js-secrets.exposed-sourcemap" },
      { role: "pivot", label: "Secret in client JS", requires: "js-secrets.exposed-key" },
      { role: "impact", label: "Readily usable credential" },
    ],
  },
  {
    title: "Mixed content on an HTTPS page combined with an insecure session cookie exposes that cookie to interception",
    narrative:
      "A subresource loaded over plain HTTP on an otherwise-HTTPS page is a request an on-path attacker can read or tamper with. A session cookie missing the Secure flag is sent on exactly that kind of plaintext request, so the mixed-content load becomes a concrete interception point for the authenticated session rather than a theoretical weakness.",
    severity: "high",
    steps: [
      { role: "entry", label: "Mixed (HTTP) content on an HTTPS page", requires: "playwright.mixed-content" },
      { role: "pivot", label: "Insecure session cookie", requires: "headers.cookie-flags" },
      { role: "impact", label: "Session cookie interception" },
    ],
  },
];

export function computeCriticalPaths(findings: Finding[]): CriticalPath[] {
  const paths: CriticalPath[] = [];
  for (const rule of CHAIN_RULES) {
    const matchedPerStep = rule.steps.map((step) => (step.requires ? matchesRequirement(step.requires, findings) : []));

    // A rule fires only if every requirement-bearing stage matched something.
    const unmet = rule.steps.some((step, i) => step.requires && matchedPerStep[i].length === 0);
    if (unmet) continue;

    const steps: AttackStep[] = rule.steps.map((step, i) => ({
      role: step.role,
      label: step.label,
      checkIds: [...new Set(matchedPerStep[i].map((f) => f.checkId).filter((id): id is string => Boolean(id)))],
    }));

    const findingCheckIds = [...new Set(steps.flatMap((s) => s.checkIds))];
    paths.push({ title: rule.title, narrative: rule.narrative, findingCheckIds, severity: rule.severity, steps });
  }
  return paths;
}

const SEVERITY_RANK: Record<Finding["severity"], number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Ranks the findings that sit on the computed paths by how many paths each one
 * breaks if fixed (desc), then by the highest severity of those paths. Pure
 * over the output of computeCriticalPaths(), so the report can render a "fix
 * these first" list without re-deriving anything. A finding that appears in
 * only one path is still returned — it is the one and only lever for that
 * chain — the UI decides how many to emphasise.
 */
export function computeChokepoints(paths: CriticalPath[]): Chokepoint[] {
  const byCheckId = new Map<string, { titles: Set<string>; severity: Finding["severity"] }>();
  for (const path of paths) {
    for (const checkId of path.findingCheckIds) {
      const entry = byCheckId.get(checkId) ?? { titles: new Set<string>(), severity: "info" as Finding["severity"] };
      entry.titles.add(path.title);
      if (SEVERITY_RANK[path.severity] > SEVERITY_RANK[entry.severity]) entry.severity = path.severity;
      byCheckId.set(checkId, entry);
    }
  }

  return [...byCheckId.entries()]
    .map(([checkId, v]) => ({ checkId, pathCount: v.titles.size, pathTitles: [...v.titles], severity: v.severity }))
    .sort((a, b) => b.pathCount - a.pathCount || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.checkId.localeCompare(b.checkId));
}
