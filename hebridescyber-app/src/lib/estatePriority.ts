// "Fix this first" (P1-2): one ranked list of open findings across every site
// an account monitors, with a plain-English reason for each position.
//
// Rule-based on purpose, so every position can be explained and argued with:
//
//   score = findingPenalty(finding)          riskScore.ts: severity, CVSS floor,
//                                           KEV / ransomware, EPSS — unchanged
//         × site criticality               high ×1.5, low ×0.6     (067)
//         × environment                    staging/development/test ×0.8 (067)
//         × internet-facing service        ×1.3  (an open port / service CVE)
//         × host confirmed live            ×1.1  (answered HTTP, or httpx saw it)
//         × WAF in front                   ×0.85 (web-attack findings only, never KEV)
//         × exploitability rating          ×0.7 to ×1.3, from the 0–100 score
//
// Each multiplier that applies becomes one factor in the explanation ("High
// severity, KEV listed, on a high-criticality site"). A signal we don't have
// is "unknown" and never moves a finding, in either direction: a host we
// couldn't confirm live is not treated as down, a site with no WhatWaf verdict
// is not treated as unprotected, and a site with no criticality set is normal.
//
// Inputs are FindingsView rows (findingsView.ts), which already apply
// finding_lifecycle (only open findings) and active triage. Triaged rows —
// accepted risk, false positive, snoozed — and info findings (penalty 0:
// nothing to fix) never appear in the list.
//
// Everything except the two loaders at the bottom is pure.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { bandText } from "./exploitability/labels";
import { hostOf } from "./findingLifecycle";
import { compareFindings, loadFindingsView, type FindingRow, type HostDetail } from "./findingsView";
import { findingPenalty } from "./scanners/riskScore";
import { CRITICALITIES, ENVIRONMENTS, type Criticality, type Environment } from "./targetCriticality";

export { CRITICALITIES, ENVIRONMENTS, type Criticality, type Environment };

export type TargetContext = { criticality: Criticality; environment: Environment | null };

export const DEFAULT_TARGET_CONTEXT: TargetContext = { criticality: "normal", environment: null };

/** What the latest scans say about a host. Absent evidence is false/null, never the opposite claim. */
export type HostSignals = {
  /** The host answered HTTP in its latest scan, or httpx found it live from another scan. */
  live: boolean;
  /** The WAF WhatWaf identified in front of the host's latest scan, or null when none was reported. */
  waf: string | null;
};

export const CRITICALITY_MULTIPLIER: Record<Criticality, number> = { low: 0.6, normal: 1, high: 1.5 };
export const NON_PRODUCTION_MULTIPLIER = 0.8;
export const INTERNET_FACING_MULTIPLIER = 1.3;
export const LIVE_HOST_MULTIPLIER = 1.1;
export const WAF_MULTIPLIER = 0.85;

/**
 * 0.7 at score 0, 1 at score 50, 1.3 at score 100, on the scale of the other
 * multipliers. It only ranks a finding down on real evidence: a low-confidence
 * rating or a KEV listing can raise a finding but never lowers it. No rating is
 * "unknown" and doesn't move it.
 */
export function exploitabilityMultiplier(row: Pick<FindingRow, "exploitabilityAssessment" | "knownExploited">): number {
  const a = row.exploitabilityAssessment;
  if (!a) return 1;
  const m = Math.round((0.7 + (0.6 * a.score) / 100) * 100) / 100;
  return m < 1 && (a.confidence === "low" || row.knownExploited) ? 1 : m;
}

/** Findings about a network service reachable from the internet. */
const EXPOSED_SERVICE_CHECKS = new Set([
  "network-exposure.open-port",
  "network-exposure.service-cve",
  "ports.risky-port",
  "nmap.dangerous-port",
  "recon.shodan-cves",
]);

/** Web-attack classes a WAF actually stands in front of. Header, TLS, DNS,
 *  exposure and dependency findings aren't blunted by one, so aren't discounted. */
const WAF_MITIGATED_CATEGORIES = new Set(["zap", "nuclei", "sqlmap", "commix", "dalfox", "webapp", "api-spec", "graphql"]);

/** Checks whose presence in a host's latest scan means it answered over HTTP. */
const HTTP_EVIDENCE_CATEGORIES = new Set(["headers", "fingerprint", "playwright"]);

const SEVERITY_LABEL: Record<FindingRow["severity"], string> = {
  critical: "Critical severity",
  high: "High severity",
  medium: "Medium severity",
  low: "Low severity",
  info: "Informational",
};

export type FactorKey =
  | "severity"
  | "cvss"
  | "kev"
  | "epss"
  | "internet_facing"
  | "criticality"
  | "environment"
  | "live"
  | "waf"
  | "exploitability";

export type PriorityFactor = {
  key: FactorKey;
  /** Plain English, reads as one clause of the reason. */
  label: string;
  /** What this factor did to the score; 1 for factors folded into the base penalty. */
  multiplier: number;
};

export type Priority = {
  /** 1 = fix first. */
  rank: number;
  score: number;
  /** riskScore.ts's per-finding penalty, before estate weighting. */
  base: number;
  factors: PriorityFactor[];
  /** The factors joined into one sentence. */
  reason: string;
};

export type PrioritisedFinding = FindingRow & { priority: Priority };

const round1 = (n: number) => Math.round(n * 10) / 10;

function portOf(checkId: string): string | null {
  const key = checkId.split(":")[1];
  return key && /^\d+$/.test(key) ? key : null;
}

/** Pure: the base penalty and factors for one finding, before ranking. */
export function scoreFinding(
  row: FindingRow,
  target: TargetContext,
  signals: HostSignals | undefined
): { score: number; base: number; factors: PriorityFactor[] } {
  const base = findingPenalty({
    severity: row.severity,
    title: row.title,
    detail: "",
    cvssScore: row.cvssScore ?? undefined,
    threatIntel: { knownExploited: row.knownExploited, ransomware: row.ransomware, epss: row.epss ?? undefined },
  });

  const factors: PriorityFactor[] = [{ key: "severity", label: SEVERITY_LABEL[row.severity], multiplier: 1 }];
  if (row.cvssScore !== null && row.cvssScore >= 7 && (row.severity === "medium" || row.severity === "low")) {
    factors.push({ key: "cvss", label: `CVSS ${row.cvssScore.toFixed(1)}`, multiplier: 1 });
  }
  if (row.knownExploited) {
    factors.push({ key: "kev", label: row.ransomware ? "KEV listed and used in ransomware" : "KEV listed", multiplier: 1 });
  } else if (row.epss !== null && row.epss >= 0.1) {
    factors.push({ key: "epss", label: `${Math.round(row.epss * 100)}% chance of exploitation (EPSS)`, multiplier: 1 });
  }

  if (EXPOSED_SERVICE_CHECKS.has(row.checkBase)) {
    const port = portOf(row.checkId);
    factors.push({
      key: "internet_facing",
      label: port ? `on an internet-facing service (port ${port})` : "on an internet-facing service",
      multiplier: INTERNET_FACING_MULTIPLIER,
    });
  }
  if (target.criticality !== "normal") {
    factors.push({ key: "criticality", label: `on a ${target.criticality}-criticality site`, multiplier: CRITICALITY_MULTIPLIER[target.criticality] });
  }
  if (target.environment && target.environment !== "production") {
    factors.push({ key: "environment", label: `on a ${target.environment} site`, multiplier: NON_PRODUCTION_MULTIPLIER });
  }
  if (signals?.live) {
    factors.push({ key: "live", label: "host is live", multiplier: LIVE_HOST_MULTIPLIER });
  }
  // Someone exploiting it now is not slowed down enough by a WAF to rank it lower.
  if (signals?.waf && !row.knownExploited && WAF_MITIGATED_CATEGORIES.has(row.category)) {
    factors.push({ key: "waf", label: `behind a WAF (${signals.waf})`, multiplier: WAF_MULTIPLIER });
  }

  const exploitability = exploitabilityMultiplier(row);
  if (row.exploitabilityAssessment && exploitability !== 1) {
    const { band, nonIntrusive } = row.exploitabilityAssessment;
    factors.push({ key: "exploitability", label: `exploitability ${bandText(band, nonIntrusive).toLowerCase()}`, multiplier: exploitability });
  }

  const score = factors.reduce((s, f) => s * f.multiplier, base);
  return { score: round1(score), base: round1(base), factors };
}

/** "High severity, KEV listed, on a high-criticality site". */
export function explainFactors(factors: PriorityFactor[]): string {
  return factors.map((f) => f.label).join(", ");
}

/**
 * Pure: the estate's open, untriaged, non-info findings, most urgent first.
 * Ties fall back to findingsView's usual order (severity, KEV, EPSS, age), so
 * the list is stable between requests.
 */
export function rankFindings(
  rows: FindingRow[],
  targets: ReadonlyMap<string, TargetContext>,
  signals: ReadonlyMap<string, HostSignals>
): PrioritisedFinding[] {
  const scored = rows
    .filter((r) => r.triage === null)
    .map((row) => ({ row, ...scoreFinding(row, targets.get(row.host) ?? DEFAULT_TARGET_CONTEXT, signals.get(row.host)) }))
    .filter((s) => s.base > 0);
  scored.sort((a, b) => b.score - a.score || compareFindings(a.row, b.row));
  return scored.map((s, i) => ({
    ...s.row,
    priority: { rank: i + 1, score: s.score, base: s.base, factors: s.factors, reason: explainFactors(s.factors) },
  }));
}

/**
 * Pure: per-host signals from each host's latest completed scan. WAF from the
 * whatwaf.waf-detected finding (its title carries the name); live from that
 * host's own HTTP-layer findings, or from an http-probe.live:<host> finding in
 * any host's scan (httpx probing a sibling subdomain).
 */
export function buildHostSignals(detailByHost: ReadonlyMap<string, HostDetail>): Map<string, HostSignals> {
  const signals = new Map<string, HostSignals>();
  const get = (host: string) => {
    let s = signals.get(host);
    if (!s) {
      s = { live: false, waf: null };
      signals.set(host, s);
    }
    return s;
  };
  for (const [host, detail] of detailByHost) {
    const own = get(host);
    for (const f of detail.findings) {
      const checkId = f.checkId ?? "";
      const category = checkId.split(".")[0];
      if (HTTP_EVIDENCE_CATEGORIES.has(category)) own.live = true;
      if (checkId === "whatwaf.waf-detected") {
        own.waf = f.title?.split(": ").slice(1).join(": ").trim() || "detected";
      }
      if (checkId.startsWith("http-probe.live:")) {
        const probed = checkId.slice("http-probe.live:".length).toLowerCase();
        if (probed) get(probed).live = true;
      }
    }
  }
  return signals;
}

function asCriticality(value: unknown): Criticality {
  return (CRITICALITIES as readonly unknown[]).includes(value) ? (value as Criticality) : "normal";
}

function asEnvironment(value: unknown): Environment | null {
  return (ENVIRONMENTS as readonly unknown[]).includes(value) ? (value as Environment) : null;
}

/** Pure: monitored_targets rows to per-host context. Two rows for one host
 *  (http and https) take the higher criticality. */
export function buildTargetContexts(
  rows: Array<{ target_url: string; criticality?: unknown; environment?: unknown }>
): Map<string, TargetContext> {
  const order: Record<Criticality, number> = { low: 0, normal: 1, high: 2 };
  const contexts = new Map<string, TargetContext>();
  for (const r of rows) {
    const host = hostOf(r.target_url);
    if (!host) continue;
    const next: TargetContext = { criticality: asCriticality(r.criticality), environment: asEnvironment(r.environment) };
    const prev = contexts.get(host);
    if (!prev || order[next.criticality] > order[prev.criticality]) {
      contexts.set(host, { criticality: next.criticality, environment: next.environment ?? prev?.environment ?? null });
    }
  }
  return contexts;
}

export type TargetContextResult = {
  /** False before migration 067: every site ranks as normal. */
  available: boolean;
  /** False when the read failed: the ranking used defaults, so say so. */
  complete: boolean;
  contexts: Map<string, TargetContext>;
};

/** The only I/O here. A failed read degrades to "every site normal" with
 *  complete: false, so the list still shows but is marked partial. */
export async function loadTargetContexts(supabaseAdmin: SupabaseClient, ownerId: string): Promise<TargetContextResult> {
  const { data, error } = await supabaseAdmin
    .from("monitored_targets")
    .select("target_url, criticality, environment")
    .eq("owner", ownerId);
  if (error) {
    if (isMissingSchemaError(error)) return { available: false, complete: true, contexts: new Map() };
    return { available: true, complete: false, contexts: new Map() };
  }
  return { available: true, complete: true, contexts: buildTargetContexts((data ?? []) as Array<{ target_url: string }>) };
}

export type FixFirstList = {
  /** The top `limit` of the ranked list. */
  items: PrioritisedFinding[];
  /** How many open, untriaged findings the full ranked list holds. */
  total: number;
  /** False when something the rank depends on couldn't be read (scan detail,
   *  target criticality) or the open list was truncated: show it as partial. */
  complete: boolean;
};

/**
 * The estate's "fix this first" list for the dashboard and the scheduled
 * report. `host` narrows it to one site (a report scoped to one target).
 * Null when findings can't be read at all, which is never "nothing to fix";
 * before migration 043 there is no lifecycle and the list is empty.
 */
export async function loadFixFirstList(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  opts: { limit: number; host?: string | null; now?: Date }
): Promise<FixFirstList | null> {
  const [view, targets] = await Promise.all([
    loadFindingsView(supabaseAdmin, ownerId, opts.now ?? new Date()),
    loadTargetContexts(supabaseAdmin, ownerId),
  ]);
  if (!view.ok) return null;
  const rows = opts.host ? view.data.rows.filter((r) => r.host === opts.host) : view.data.rows;
  const ranked = rankFindings(rows, targets.contexts, buildHostSignals(view.data.detailByHost));
  return {
    items: ranked.slice(0, Math.max(0, opts.limit)),
    total: ranked.length,
    complete: targets.complete && view.data.detailComplete && !view.data.truncated,
  };
}
