// "How you compare" (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 4): a
// score next to how other sites scored. KnowBe4's free phishing test is built
// on the same idea: a number on its own means little; a number against your
// peers is a reason to act and to share.
//
// Dark until SCORE_BENCHMARK_ENABLED=true (owner decision 6: aggregate use
// and the privacy-notice line). Off, nothing is recorded or shown.
//
// Honesty rules:
//   - Free-check scores are compared only with free checks, scan scores only
//     with scans (migration 083): the two come from different checks.
//   - Nothing is shown until a group has MIN_GROUP sites, so a handful of
//     results is never dressed up as a benchmark, and no single site can be
//     inferred from it.
//   - The comparison is "better than N% of the sites checked here", never a
//     national or industry claim.
import type { SupabaseClient } from "@supabase/supabase-js";

export const MIN_GROUP = 50;
export const WINDOW_DAYS = 90;

export type Benchmark = { betterThanPercent: number; groupSize: number; windowDays: number; kind: "free_check" | "scan" };

export function isBenchmarkEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env.SCORE_BENCHMARK_ENABLED === "true";
}

/** Pure. The share of the group that scored lower, or null below MIN_GROUP or for nonsense counts. */
export function benchmarkFrom(counts: { total: number; lower: number } | null, kind: Benchmark["kind"], windowDays = WINDOW_DAYS): Benchmark | null {
  if (!counts) return null;
  const { total, lower } = counts;
  if (!Number.isFinite(total) || !Number.isFinite(lower) || total < MIN_GROUP || lower < 0 || lower > total) return null;
  return { betterThanPercent: Math.floor((lower / total) * 100), groupSize: total, windowDays, kind };
}

/** Pure. The sentence shown beside a score. */
export function benchmarkSentence(b: Benchmark): string {
  const what = b.kind === "free_check" ? "sites given this free check" : "sites scanned with Hebrides Cyber";
  const group = `${b.groupSize.toLocaleString("en-GB")} ${what} in the last ${b.windowDays} days`;
  if (b.betterThanPercent === 0) return `Lower than the other ${group}.`;
  return `Better than ${b.betterThanPercent}% of the ${group}.`;
}

function firstRow(data: unknown): { total: number; lower: number } | null {
  const row = Array.isArray(data) ? data[0] : data;
  if (!row || typeof row !== "object") return null;
  const r = row as { total?: unknown; lower?: unknown };
  const total = Number(r.total);
  const lower = Number(r.lower);
  return Number.isFinite(total) && Number.isFinite(lower) ? { total, lower } : null;
}

/** Free check: compared with other free checks. Null when off, too few, or on any failure. */
export async function freeCheckBenchmark(db: SupabaseClient, score: number): Promise<Benchmark | null> {
  if (!isBenchmarkEnabled()) return null;
  try {
    const { data, error } = await db.rpc("instant_check_score_counts", { p_score: Math.round(score), p_days: WINDOW_DAYS });
    return error ? null : benchmarkFrom(firstRow(data), "free_check");
  } catch {
    return null;
  }
}

/** Records a free-check score (score and time only). Best-effort; off means nothing is written. */
export async function recordFreeCheckScore(db: SupabaseClient, score: number): Promise<void> {
  if (!isBenchmarkEnabled()) return;
  try {
    await db.from("instant_check_scores").insert({ score: Math.max(0, Math.min(100, Math.round(score))) });
  } catch {
    /* best-effort */
  }
}

/** Full scan: compared with other owners' sites' latest scan scores. Null when off, too few, or on any failure. */
export async function scanBenchmark(db: SupabaseClient, score: number, ownerId: string): Promise<Benchmark | null> {
  if (!isBenchmarkEnabled()) return null;
  try {
    const { data, error } = await db.rpc("scan_score_counts", { p_score: Math.round(score), p_days: WINDOW_DAYS, p_exclude_owner: ownerId });
    return error ? null : benchmarkFrom(firstRow(data), "scan");
  } catch {
    return null;
  }
}
