// Cross-tool duplicate findings. Our own checks, nuclei, ZAP, testssl and the
// rest can report the same underlying issue on the same target; left alone
// the report lists it two or three times and the score charges it twice.
// This pure pass, run by executeScan() after every finding is gathered and
// before scoring, folds the extended-tool duplicates into ONE canonical
// finding and records who else reported it in `corroboratedBy`.
//
// What makes a match. Never titles. Each finding is mapped to a set of
// canonical *issue keys* from a curated, evidence-based table:
//   - our own checks by exact checkId,
//   - nuclei by template id, ZAP by alert name (the only identifier its
//     checkId carries), testssl by its check id,
//   - CVE ids, but only against target-side canonicals (JS library and
//     WordPress-plugin findings), and only when every CVE the duplicate
//     reports is one the canonical already lists.
// A finding is folded into a canonical only when ALL of its issue keys are
// covered by the canonical's, so an aggregate (headers.missing-critical lists
// three headers) can absorb a single-header duplicate but never the reverse.
// A finding with no keys, or no confident match, is left untouched.
//
// Rules this module guarantees:
//   - The canonical's checkId never changes, so findingsDiff / ticket dedupe /
//     lifecycle / triage keep working. Our own base checks always win over
//     extended tools (own < testssl < ZAP < nuclei < everything else).
//   - Only extended-tool findings are ever dropped. Our own checks are never
//     merged into one another: they are aggregates with their own triage,
//     SLA rows and tickets, which a merge would orphan.
//   - The canonical's severity is the maximum of the group.
//   - Several equally good canonicals (or none) means no merge.
//   - A duplicate the customer has triaged (`options.isTriaged`) is kept as it
//     is, so their decision about that exact finding keeps applying.
//
// What happens to the dropped duplicates' stored state is spelled out where
// it is handled: findingsDiff.ts (a duplicate is not "fixed", the canonical is
// not "new"), findingLifecycle.ts (rows are resolved, the SLA clock moves to
// the canonical) and CLAUDE.md "Cross-tool duplicate findings".
//
// CONFIDENCE NOTE: the nuclei template ids and ZAP alert names below come
// from those projects' public template/alert catalogues, not from a live run
// in this repo. A wrong or renamed entry simply never matches (the finding
// stays separate), which is the safe failure.
import type { Corroboration, Finding } from "./scanners";

type Severity = Finding["severity"];

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

type Equivalence = {
  /** The canonical issue key — a short stable slug. */
  issue: string;
  /** Our own checkIds, exact. */
  own?: string[];
  /** nuclei template ids (`nuclei.finding:<id>`). */
  nuclei?: string[];
  /** ZAP alert names (`zap.alert:<name>`), exact. */
  zap?: string[];
  /** testssl.sh check ids (`deep-tls.finding:<id>`). */
  testssl?: string[];
};

export const EQUIVALENCES: Equivalence[] = [
  { issue: "hsts-missing", own: ["tls.hsts-missing"], zap: ["Strict-Transport-Security Header Not Set"] },
  { issue: "csp-missing", own: ["headers.csp-absent"], zap: ["Content Security Policy (CSP) Header Not Set"] },
  { issue: "xcto-missing", zap: ["X-Content-Type-Options Header Missing"] },
  { issue: "cors-wildcard", own: ["headers.cors-wildcard"], zap: ["Cross-Domain Misconfiguration"] },
  // tls.ts only sees what node negotiates; testssl sees what is *offered*.
  // SSLv2/SSLv3 are deliberately not here: tls.weak-protocol's text is about
  // TLS 1.0/1.1, and those are different (worse) findings.
  { issue: "legacy-tls", own: ["tls.weak-protocol"], nuclei: ["deprecated-tls"], testssl: ["TLS1", "TLS1_1"] },
  { issue: "cert-expired", own: ["tls.cert-expired"], nuclei: ["expired-ssl"] },
  { issue: "cert-self-signed", own: ["tls.self-signed"], nuclei: ["self-signed-ssl"] },
  { issue: "cert-name-mismatch", own: ["tls.cert-name-mismatch"], nuclei: ["mismatched-ssl-certificate"] },
  { issue: "cert-untrusted", own: ["tls.cert-untrusted"], nuclei: ["untrusted-root-certificate"] },
  // Path-specific only: a template that probes many paths (phpinfo-files)
  // cannot be tied to one exposure.exposed-file:<path> finding.
  { issue: "exposed:/.env", own: ["exposure.exposed-file:/.env"], nuclei: ["dotenv-file"] },
  { issue: "exposed:/.git/config", own: ["exposure.exposed-file:/.git/config"], nuclei: ["git-config"] },
  { issue: "exposed:/server-status", own: ["exposure.exposed-file:/server-status"], nuclei: ["server-status-localhost"] },
];

/** The header names headers.missing-critical lists in its detail → issue key. */
const HEADER_ISSUES: Record<string, string> = {
  "strict-transport-security": "hsts-missing",
  "content-security-policy": "csp-missing",
  "x-content-type-options": "xcto-missing",
};

/** Target-side own findings whose CVE list can absorb another tool's CVE finding. */
const CVE_CANONICAL_BASES = new Set(["webapp.vulnerable-js-lib", "wpvdb.plugin-vulnerability"]);
/** Extended tools whose findings carry real CVE ids worth matching on. */
const CVE_REPORTING_TOOLS = new Set(["nuclei", "cairn", "strix"]);

const OWN_ISSUES = new Map<string, string[]>();
const NUCLEI_ISSUES = new Map<string, string[]>();
const ZAP_ISSUES = new Map<string, string[]>();
const TESTSSL_ISSUES = new Map<string, string[]>();

function register(map: Map<string, string[]>, id: string, issue: string): void {
  const list = map.get(id);
  if (list) list.push(issue);
  else map.set(id, [issue]);
}
for (const e of EQUIVALENCES) {
  for (const id of e.own ?? []) register(OWN_ISSUES, id, e.issue);
  for (const id of e.nuclei ?? []) register(NUCLEI_ISSUES, id.toLowerCase(), e.issue);
  for (const id of e.zap ?? []) register(ZAP_ISSUES, id, e.issue);
  for (const id of e.testssl ?? []) register(TESTSSL_ISSUES, id, e.issue);
}

/** Which tool produced a checkId, from its namespace. Everything else is one of our own checks. */
const EXTENDED_NAMESPACES: Record<string, { tool: string; rank: number }> = {
  "deep-tls": { tool: "testssl", rank: 10 },
  zap: { tool: "ZAP", rank: 20 },
  nuclei: { tool: "nuclei", rank: 30 },
  sqlmap: { tool: "sqlmap", rank: 40 },
  xsser: { tool: "XSSer", rank: 40 },
  commix: { tool: "commix", rank: 40 },
  cairn: { tool: "Cairn", rank: 40 },
  strix: { tool: "Strix", rank: 40 },
};

function namespaceOf(checkId: string): string {
  return checkId.split(/[.:]/)[0];
}

type Identity = { tool: string; rank: number; extended: boolean; keys: Set<string> };

function identify(f: Finding): Identity | null {
  const id = f.checkId;
  if (!id) return null;
  const ns = namespaceOf(id);
  const ext = EXTENDED_NAMESPACES[ns];
  const keys = new Set<string>();

  const add = (list: string[] | undefined) => list?.forEach((k) => keys.add(k));
  if (ns === "nuclei") add(NUCLEI_ISSUES.get(id.slice("nuclei.finding:".length).toLowerCase()));
  else if (ns === "zap") add(ZAP_ISSUES.get(id.slice("zap.alert:".length)));
  else if (ns === "deep-tls") add(TESTSSL_ISSUES.get(id.slice("deep-tls.finding:".length)));
  else {
    add(OWN_ISSUES.get(id));
    if (id === "headers.missing-critical") {
      for (const name of f.detail.split(",")) {
        const issue = HEADER_ISSUES[name.trim().toLowerCase()];
        if (issue) keys.add(issue);
      }
    }
  }

  const base = id.split(":")[0];
  const cveEligible = ext ? CVE_REPORTING_TOOLS.has(ns) : CVE_CANONICAL_BASES.has(base);
  if (cveEligible && f.cveIds && f.cveIds.length > 0) {
    for (const cve of f.cveIds) keys.add(`cve:${cve.toUpperCase()}`);
  }

  return { tool: ext?.tool ?? ns, rank: ext?.rank ?? 0, extended: Boolean(ext), keys };
}

function isSubset(small: Set<string>, big: Set<string>): boolean {
  for (const k of small) if (!big.has(k)) return false;
  return true;
}

export type ConsolidationOptions = {
  /** True when the customer has an active triage decision on this checkId.
   *  Such a finding is never folded away. */
  isTriaged?: (checkId: string) => boolean;
};

export type ConsolidationResult = {
  findings: Finding[];
  /** Findings dropped into a canonical. */
  mergedCount: number;
};

function sameCorroboration(a: Corroboration, b: Corroboration): boolean {
  return a.tool === b.tool && a.checkId === b.checkId;
}

export function consolidateFindings(input: Finding[], options: ConsolidationOptions = {}): ConsolidationResult {
  const identities = input.map(identify);

  // Roots are settled in ascending rank, so a finding is only ever compared
  // with canonicals that have themselves survived.
  const order = input
    .map((_, i) => i)
    .filter((i) => identities[i] !== null)
    .sort((a, b) => identities[a]!.rank - identities[b]!.rank || a - b);

  const dropped = new Set<number>();
  const absorbed = new Map<number, number[]>();

  for (const i of order) {
    const me = identities[i]!;
    const checkId = input[i].checkId!;
    // Own checks are never dropped; nothing without keys can match; a
    // customer's decision about this exact finding must keep applying.
    if (!me.extended || me.keys.size === 0) continue;
    if (options.isTriaged?.(checkId)) continue;

    const candidates: number[] = [];
    for (const j of order) {
      if (j === i || dropped.has(j)) continue;
      const other = identities[j]!;
      if (other.rank >= me.rank || other.tool === me.tool) continue;
      if (isSubset(me.keys, other.keys)) candidates.push(j);
    }
    if (candidates.length === 0) continue;

    // Best evidence tier first, then the most specific canonical (fewest
    // keys: a single-issue finding beats an aggregate). A tie is ambiguous.
    const score = (j: number) => [identities[j]!.rank, identities[j]!.keys.size];
    candidates.sort((a, b) => score(a)[0] - score(b)[0] || score(a)[1] - score(b)[1] || a - b);
    const [best, runnerUp] = candidates;
    if (runnerUp !== undefined) {
      const [r1, k1] = score(best);
      const [r2, k2] = score(runnerUp);
      if (r1 === r2 && k1 === k2) continue;
    }

    dropped.add(i);
    absorbed.set(best, [...(absorbed.get(best) ?? []), i]);
  }

  const out: Finding[] = [];
  input.forEach((f, i) => {
    if (dropped.has(i)) return;
    const mine = absorbed.get(i);
    if (!mine) {
      out.push(f);
      return;
    }
    const corroboratedBy: Corroboration[] = [...(f.corroboratedBy ?? [])];
    let severity = f.severity;
    const cves = [...(f.cveIds ?? [])];
    const hasCve = (id: string) => cves.some((c) => c.toUpperCase() === id.toUpperCase());
    for (const j of mine) {
      const dup = input[j];
      const entry: Corroboration = { tool: identities[j]!.tool, checkId: dup.checkId!, title: dup.title };
      if (!corroboratedBy.some((c) => sameCorroboration(c, entry))) corroboratedBy.push(entry);
      if (SEVERITY_RANK[dup.severity] < SEVERITY_RANK[severity]) severity = dup.severity;
      for (const c of dup.cveIds ?? []) if (!hasCve(c)) cves.push(c);
    }
    const merged: Finding = { ...f, severity, corroboratedBy };
    if (cves.length > 0) merged.cveIds = cves;
    out.push(merged);
  });

  return { findings: out, mergedCount: dropped.size };
}

/** Every checkId a finding stands for: its own plus the duplicates folded into it. */
export function findingCheckIds(f: { checkId?: string; corroboratedBy?: Array<{ checkId: string }> }): string[] {
  const ids: string[] = [];
  if (f.checkId) ids.push(f.checkId);
  for (const c of f.corroboratedBy ?? []) ids.push(c.checkId);
  return ids;
}

/** "nuclei, ZAP" — the distinct reporting tools, in first-seen order. */
export function corroboratingTools(corroboratedBy: Array<{ tool: string }> | undefined): string[] {
  return [...new Set((corroboratedBy ?? []).map((c) => c.tool))];
}
