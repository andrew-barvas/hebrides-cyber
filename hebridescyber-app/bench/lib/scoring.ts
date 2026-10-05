// Pure scoring and baseline-diff logic for the accuracy benchmark. No I/O, so
// every rule here is unit-tested without starting a server.
//
// Vocabulary, per module (the checkId prefix before the first "."):
//   TP  an expected finding (mustFind) the scanner reported
//   FN  an expected finding it did not report            -> hurts recall
//   FP  a reported finding nobody expected (not in mustFind/optional)
//                                                         -> hurts precision
// A reported finding that matches mustNotFind is a FP *and* a hard "forbidden"
// failure: those are the false-positive classes we promised never to emit.

export type KnownIssue = {
  /** Exact checkId or prefix pattern ending in "*". */
  checkId: string;
  /** "miss": a finding we should report but don't. "false-positive": one we report but shouldn't. */
  kind: "miss" | "false-positive";
  note: string;
};

export type Expectation = {
  target: string;
  description: string;
  mustFind: string[];
  mustNotFind: string[];
  /** Tolerated either way and never scored (environmental noise, e.g. tech-detected). */
  optional: string[];
  /** Tracked defects: still scored, but they do not hard-fail the run. */
  knownIssues: KnownIssue[];
};

export type Counts = { tp: number; fp: number; fn: number };

export type Failure = {
  kind: "missing" | "forbidden";
  target: string;
  checkId: string;
};

export type TargetScore = {
  target: string;
  found: string[];
  modules: Record<string, Counts>;
  /** Hard failures: not covered by a knownIssue. */
  failures: Failure[];
  /** Reported findings no expectation mentions (each already counted as a FP). */
  unexpected: string[];
  /** knownIssues that still reproduce, and ones that no longer do (stale). */
  knownIssuesOpen: string[];
  knownIssuesStale: string[];
};

export type ModuleMetrics = Counts & { precision: number; recall: number };

export type Baseline = {
  version: 1;
  modules: Record<string, ModuleMetrics>;
};

export type Regression = {
  module: string;
  metric: "precision" | "recall";
  baseline: number;
  current: number;
};

export type BaselineDiff = {
  regressions: Regression[];
  improvements: Regression[];
  /** Modules scored now that the baseline has never seen. */
  newModules: string[];
  /** Modules in the baseline that produced no data this run. */
  missingModules: string[];
};

/** Module name: the checkId prefix before the first ".". */
export function moduleOf(checkId: string): string {
  const dot = checkId.indexOf(".");
  return dot === -1 ? checkId : checkId.slice(0, dot);
}

/** Exact match, or prefix match when the pattern ends in "*". */
export function matches(pattern: string, checkId: string): boolean {
  return pattern.endsWith("*") ? checkId.startsWith(pattern.slice(0, -1)) : pattern === checkId;
}

function anyMatch(patterns: string[], checkId: string): boolean {
  return patterns.some((p) => matches(p, checkId));
}

function bump(modules: Record<string, Counts>, mod: string, key: keyof Counts): void {
  (modules[mod] ??= { tp: 0, fp: 0, fn: 0 })[key] += 1;
}

function knownFor(expectation: Expectation, kind: KnownIssue["kind"], checkId: string): KnownIssue | undefined {
  return expectation.knownIssues.find((k) => k.kind === kind && matches(k.checkId, checkId));
}

/**
 * Scores one target's reported checkIds against its expectation.
 * `scopeModules` limits FP counting to modules the benchmark actually drives.
 */
export function scoreTarget(expectation: Expectation, reported: string[], scopeModules: readonly string[]): TargetScore {
  const found = [...new Set(reported)].sort();
  const modules: Record<string, Counts> = {};
  const failures: Failure[] = [];
  const unexpected: string[] = [];
  const knownIssuesOpen = new Set<string>();

  for (const pattern of expectation.mustFind) {
    const mod = moduleOf(pattern);
    if (found.some((id) => matches(pattern, id))) {
      bump(modules, mod, "tp");
    } else {
      bump(modules, mod, "fn");
      const known = knownFor(expectation, "miss", pattern);
      if (known) knownIssuesOpen.add(known.checkId);
      else failures.push({ kind: "missing", target: expectation.target, checkId: pattern });
    }
  }

  for (const id of found) {
    const mod = moduleOf(id);
    if (!scopeModules.includes(mod)) continue;
    if (anyMatch(expectation.mustFind, id) || anyMatch(expectation.optional, id)) continue;

    bump(modules, mod, "fp");
    if (anyMatch(expectation.mustNotFind, id)) {
      const known = knownFor(expectation, "false-positive", id);
      if (known) knownIssuesOpen.add(known.checkId);
      else failures.push({ kind: "forbidden", target: expectation.target, checkId: id });
    } else {
      unexpected.push(id);
    }
  }

  // A known issue that no longer reproduces should be deleted from the file.
  const stale = expectation.knownIssues.filter((k) => !knownIssuesOpen.has(k.checkId)).map((k) => k.checkId);

  return {
    target: expectation.target,
    found,
    modules,
    failures,
    unexpected,
    knownIssuesOpen: [...knownIssuesOpen].sort(),
    knownIssuesStale: stale.sort(),
  };
}

const round4 = (n: number): number => Math.round(n * 10_000) / 10_000;

/** Precision/recall from counts. An empty denominator is 1: nothing was wrong. */
export function metricsFor(counts: Counts): ModuleMetrics {
  const reported = counts.tp + counts.fp;
  const expected = counts.tp + counts.fn;
  return {
    ...counts,
    precision: reported === 0 ? 1 : round4(counts.tp / reported),
    recall: expected === 0 ? 1 : round4(counts.tp / expected),
  };
}

/** Sums every target's per-module counts into per-module metrics, sorted by module name. */
export function aggregate(scores: TargetScore[]): Record<string, ModuleMetrics> {
  const totals: Record<string, Counts> = {};
  for (const score of scores) {
    for (const [mod, c] of Object.entries(score.modules)) {
      const t = (totals[mod] ??= { tp: 0, fp: 0, fn: 0 });
      t.tp += c.tp;
      t.fp += c.fp;
      t.fn += c.fn;
    }
  }
  const out: Record<string, ModuleMetrics> = {};
  for (const mod of Object.keys(totals).sort()) out[mod] = metricsFor(totals[mod]);
  return out;
}

export function toBaseline(modules: Record<string, ModuleMetrics>): Baseline {
  return { version: 1, modules };
}

/**
 * Compares current metrics with the committed baseline. A drop in precision or
 * recall beyond `tolerance` is a regression; a rise is an improvement (the
 * caller prints a reminder to refresh the baseline so it ratchets up).
 */
export function diffBaseline(
  current: Record<string, ModuleMetrics>,
  baseline: Baseline,
  tolerance = 0.0001
): BaselineDiff {
  const regressions: Regression[] = [];
  const improvements: Regression[] = [];
  const metrics = ["precision", "recall"] as const;

  for (const mod of Object.keys(current)) {
    const base = baseline.modules[mod];
    if (!base) continue;
    for (const metric of metrics) {
      const delta = current[mod][metric] - base[metric];
      const entry = { module: mod, metric, baseline: base[metric], current: current[mod][metric] };
      if (delta < -tolerance) regressions.push(entry);
      else if (delta > tolerance) improvements.push(entry);
    }
  }

  return {
    regressions,
    improvements,
    newModules: Object.keys(current).filter((m) => !baseline.modules[m]),
    missingModules: Object.keys(baseline.modules).filter((m) => !current[m]),
  };
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`;

/** Fixed-width plain-text table of per-module results. */
export function formatTable(modules: Record<string, ModuleMetrics>, baseline?: Baseline): string {
  const header = ["module", "TP", "FP", "FN", "precision", "recall", "vs baseline"];
  const rows = Object.entries(modules).map(([mod, m]) => {
    const base = baseline?.modules[mod];
    let vs = baseline ? "new" : "-";
    if (base) {
      const dp = m.precision - base.precision;
      const dr = m.recall - base.recall;
      vs = dp === 0 && dr === 0 ? "=" : `${dp < 0 || dr < 0 ? "worse" : "better"}`;
    }
    return [mod, String(m.tp), String(m.fp), String(m.fn), pct(m.precision), pct(m.recall), vs];
  });
  const all = [header, ...rows];
  const widths = header.map((_, i) => Math.max(...all.map((r) => r[i].length)));
  const line = (r: string[]) => r.map((cell, i) => (i === 0 ? cell.padEnd(widths[i]) : cell.padStart(widths[i]))).join("  ");
  return [line(header), widths.map((w) => "-".repeat(w)).join("  "), ...rows.map(line)].join("\n");
}
