// Score planner (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 1): "what
// would my score be if I fixed these?", and "what's the fewest fixes that gets
// me to Good?". Pure, so the report card, the weekly email and the API all
// agree.
//
// A scan's score is 100 minus the sum of its findings' penalties, floored at 0
// (riskScore.ts). Fixing a finding removes exactly its penalty, so a projection
// needs only two things: the penalty of each finding, and the total penalty
// behind the stored score.
//
// The stored score is the anchor, not a recomputation. Findings marked false
// positive before the scan didn't count, and older scans were priced under an
// earlier model, so recomputing could disagree with the number the customer
// sees. While the score is above 0, the total is exactly 100 - score (to
// rounding). At 0 the total is unknown beyond "at least 100", so the planner
// uses the larger of 100 and the sum of the findings it can see: the
// projection then stays conservative (never promises more than the fixes can
// deliver).
//
// It's an estimate and says so: the real score comes from the next scan, and
// "Check it's fixed" confirms each fix.
//
// Imported by client components, so it stays free of server modules: the
// rating bands are restated here and scorePlanner.test.ts pins them to
// executiveReport.ts's ratingFor.
import { findingPenalty } from "./scanners/riskScore";
import type { FixDifficulty } from "./scanners/fixDifficulty";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITIES)[number];

/** The rating bands customers see (executiveReport.ts's ratingFor), as targets, highest first. */
export const RATING_TARGETS = [
  { label: "Strong", minScore: 90 },
  { label: "Good", minScore: 75 },
  { label: "Needs attention", minScore: 50 },
] as const;

export type PlannerFinding = {
  checkId?: string;
  severity?: string;
  title?: string;
  cvssScore?: number;
  threatIntel?: { knownExploited?: boolean; ransomware?: boolean; epss?: number };
  fixDifficulty?: FixDifficulty;
};

export type PlanCandidate = {
  checkId: string;
  title: string;
  severity: Severity;
  /** Points this fix is worth on the score (before rounding and the 100 cap). */
  points: number;
  fixDifficulty?: FixDifficulty;
};

export type ScorePlan = {
  current: number;
  target: number;
  /** True when the chosen fixes reach the target. */
  reachable: boolean;
  /** The fewest fixes, largest first; empty when already at or above the target. */
  fixes: PlanCandidate[];
  projected: number;
};

const DIFFICULTY_RANK: Record<FixDifficulty, number> = { trivial: 0, easy: 1, moderate: 2, hard: 3 };

function normaliseSeverity(value: unknown): Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value) ? (value as Severity) : "info";
}

/** Pure. The findings a customer could fix to move the score: keyed by checkId, worth at least a point. Largest first, then easiest. */
export function planCandidates(findings: readonly PlannerFinding[]): PlanCandidate[] {
  const seen = new Set<string>();
  const out: PlanCandidate[] = [];
  for (const f of findings) {
    if (!f.checkId || seen.has(f.checkId)) continue;
    const severity = normaliseSeverity(f.severity);
    const points = findingPenalty({ severity, cvssScore: f.cvssScore, threatIntel: f.threatIntel });
    if (points <= 0) continue;
    seen.add(f.checkId);
    out.push({ checkId: f.checkId, title: f.title?.trim() || f.checkId, severity, points, ...(f.fixDifficulty ? { fixDifficulty: f.fixDifficulty } : {}) });
  }
  return out.sort(
    (a, b) =>
      b.points - a.points ||
      (a.fixDifficulty ? DIFFICULTY_RANK[a.fixDifficulty] : 9) - (b.fixDifficulty ? DIFFICULTY_RANK[b.fixDifficulty] : 9) ||
      a.checkId.localeCompare(b.checkId)
  );
}

/** Pure. The total penalty behind `score`, given the penalties we can see (see the header). */
export function totalPenalty(score: number, visiblePoints: number): number {
  const s = Math.max(0, Math.min(100, Math.round(score)));
  return s > 0 ? 100 - s : Math.max(100, visiblePoints);
}

/** Pure. The score after removing `removedPoints` of penalty from a scan scored `score`. */
export function projectScore(score: number, visiblePoints: number, removedPoints: number): number {
  const total = totalPenalty(score, visiblePoints);
  return Math.max(0, Math.min(100, Math.round(100 - Math.max(0, total - removedPoints))));
}

/** Pure. The projected score if the given checkIds were fixed. Unknown ids are ignored. */
export function projectWithFixes(score: number, candidates: readonly PlanCandidate[], fixedCheckIds: Iterable<string>): number {
  const fixed = new Set(fixedCheckIds);
  const visible = candidates.reduce((s, c) => s + c.points, 0);
  const removed = candidates.reduce((s, c) => s + (fixed.has(c.checkId) ? c.points : 0), 0);
  return projectScore(score, visible, removed);
}

/**
 * Pure. The fewest fixes that take `score` to `target`. Every fix removes its
 * own penalty independently, so taking the largest first is optimal for the
 * count; ties go to the easier fix. `include` forces findings into the plan
 * first (the weekly email's suggestion), and the rest are filled in largest
 * first.
 */
export function planToTarget(score: number, candidates: readonly PlanCandidate[], target: number, opts: { include?: readonly string[] } = {}): ScorePlan {
  const current = projectScore(score, candidates.reduce((s, c) => s + c.points, 0), 0);
  if (current >= target) return { current, target, reachable: true, fixes: [], projected: current };

  const forced = new Set(opts.include ?? []);
  const ordered = [...candidates.filter((c) => forced.has(c.checkId)), ...candidates.filter((c) => !forced.has(c.checkId))];
  const fixes: PlanCandidate[] = [];
  let projected = current;
  for (const c of ordered) {
    if (projected >= target && !forced.has(c.checkId)) break;
    fixes.push(c);
    projected = projectWithFixes(score, candidates, fixes.map((f) => f.checkId));
  }
  return { current, target, reachable: projected >= target, fixes, projected };
}

/** Pure. The next rating band above `score`, or null at Strong. */
export function nextRatingTarget(score: number): (typeof RATING_TARGETS)[number] | null {
  const above = RATING_TARGETS.filter((t) => t.minScore > score);
  return above.length ? above[above.length - 1] : null;
}

/** Pure. The rating label for a score, as customers see it (matches ratingFor). */
export function ratingLabel(score: number): string {
  return RATING_TARGETS.find((t) => score >= t.minScore)?.label ?? "At risk";
}
