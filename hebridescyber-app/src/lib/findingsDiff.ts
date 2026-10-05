// Compares the findings of two scans of the same target to answer "what
// changed since last time" — the basis of the New/Fixed filter on the scan
// detail page. Pure function: takes two Finding arrays, no I/O, so it works
// equally whether the caller sourced them from a fresh scan or an old one.
//
// Matching is by Finding.checkId, not by title/detail — titles routinely embed
// a count or a version number that changes without the underlying issue
// changing (see the comment on Finding.checkId in ./scanners/index.ts).
// Findings from scans predating checkId simply have it undefined and never
// match anything, which is the conservatively correct behaviour: we cannot
// know whether an untagged old finding is "the same" as a new tagged one.
import type { Finding } from "./scanners";
import { findingCheckIds } from "./findingConsolidation";

export type DiffStatus = "new" | "fixed" | "unchanged";

export type DiffedFinding = Finding & { status: DiffStatus };

export type FindingsDiff = {
  /** Present in `current` but not in `previous` — newly introduced. */
  added: DiffedFinding[];
  /** Present in `previous` but not in `current` — resolved since last scan. */
  fixed: DiffedFinding[];
  /** Present in both — carried straight from `current` (its up-to-date text). */
  unchanged: DiffedFinding[];
};

// Cross-tool consolidation (findingConsolidation.ts) folds duplicates into a
// canonical finding and records their checkIds in `corroboratedBy`. A finding
// therefore stands for all of those ids here: a scan from before the
// consolidation holding the old nuclei/ZAP finding must not read as "fixed"
// when the same issue now lives on its canonical, nor the canonical as "new".
export function diffFindings(current: Finding[], previous: Finding[]): FindingsDiff {
  // Only real checkIds go in these lookups — a finding with no checkId is
  // simply never inserted, so it can never be "found" as a match in either
  // direction, which is what makes untagged findings always read as new/fixed
  // rather than accidentally coinciding on a synthesised fallback key.
  const previousCheckIds = new Set(previous.flatMap(findingCheckIds));
  const currentCheckIds = new Set(current.flatMap(findingCheckIds));

  const added: DiffedFinding[] = [];
  const unchanged: DiffedFinding[] = [];

  for (const f of current) {
    if (findingCheckIds(f).some((id) => previousCheckIds.has(id))) {
      unchanged.push({ ...f, status: "unchanged" });
    } else {
      added.push({ ...f, status: "new" });
    }
  }

  const fixed: DiffedFinding[] = previous
    .filter((f) => !findingCheckIds(f).some((id) => currentCheckIds.has(id)))
    .map((f) => ({ ...f, status: "fixed" }));

  return { added, fixed, unchanged };
}
