// Orchestrates one benchmark run: start each fixture, scan it, score it against
// its expectations, then compare the aggregate with the committed baseline.
// Everything environmental (servers, the scanner, the clock) is injected so the
// whole flow is unit-testable.
import type { SiteHandler } from "../fixtures/sites";
import type { CorpusTarget } from "../corpus";
import type { RunningSite } from "./server";
import {
  aggregate,
  diffBaseline,
  formatTable,
  scoreTarget,
  type Baseline,
  type BaselineDiff,
  type Expectation,
  type ModuleMetrics,
  type TargetScore,
} from "./scoring";

export type RunOptions = {
  corpus: CorpusTarget[];
  expectations: Map<string, Expectation>;
  scan: (url: string) => Promise<string[]>;
  start: (handler: SiteHandler) => Promise<RunningSite>;
  scope: readonly string[];
  /** Committed baseline; null when none exists yet. */
  baseline: Baseline | null;
  /** Restrict the run to these target ids (baseline comparison is skipped). */
  only?: string[];
  now?: () => Date;
};

export type BenchReport = {
  generatedAt: string;
  partial: boolean;
  targets: TargetScore[];
  modules: Record<string, ModuleMetrics>;
  diff: BaselineDiff | null;
  /** Everything that makes the run fail, human-readable. Empty when ok. */
  problems: string[];
  ok: boolean;
};

/** Throws when the corpus and expectation set disagree — that is a setup bug, not a result. */
export function checkConfiguration(corpus: CorpusTarget[], expectations: Map<string, Expectation>): void {
  const ids = new Set(corpus.map((t) => t.id));
  const duplicates = corpus.map((t) => t.id).filter((id, i, all) => all.indexOf(id) !== i);
  if (duplicates.length > 0) throw new Error(`Duplicate corpus target id(s): ${[...new Set(duplicates)].join(", ")}`);
  const missing = [...ids].filter((id) => !expectations.has(id));
  if (missing.length > 0) throw new Error(`No expectations file for target(s): ${missing.join(", ")}`);
  const orphaned = [...expectations.keys()].filter((id) => !ids.has(id));
  if (orphaned.length > 0) throw new Error(`Expectations without a corpus target: ${orphaned.join(", ")}`);
}

export async function runBenchmark(options: RunOptions): Promise<BenchReport> {
  const { corpus, expectations, scan, start, scope, baseline, only } = options;
  checkConfiguration(corpus, expectations);

  const selected = only && only.length > 0 ? corpus.filter((t) => only.includes(t.id)) : corpus;
  if (only && only.length > 0) {
    const unknown = only.filter((id) => !corpus.some((t) => t.id === id));
    if (unknown.length > 0) throw new Error(`Unknown target(s): ${unknown.join(", ")}`);
  }
  const partial = selected.length !== corpus.length;

  const problems: string[] = [];
  const targets: TargetScore[] = [];

  for (const target of selected) {
    const expectation = expectations.get(target.id)!;
    const site = await start(target.create());
    try {
      const reported = await scan(site.url);
      const score = scoreTarget(expectation, reported, scope);
      targets.push(score);
      for (const f of score.failures) {
        problems.push(
          f.kind === "missing"
            ? `${f.target}: expected finding ${f.checkId} was not reported`
            : `${f.target}: forbidden finding ${f.checkId} was reported`
        );
      }
    } catch (err) {
      problems.push(`${target.id}: scan failed (${(err as Error).message})`);
    } finally {
      await site.close();
    }
  }

  const modules = aggregate(targets);

  let diff: BaselineDiff | null = null;
  if (!partial) {
    if (!baseline) {
      problems.push("No baseline found — run `npm run bench -- --update-baseline` and commit bench/baseline.json");
    } else {
      diff = diffBaseline(modules, baseline);
      for (const r of diff.regressions) {
        problems.push(
          `${r.module}: ${r.metric} regressed from ${(r.baseline * 100).toFixed(1)}% to ${(r.current * 100).toFixed(1)}%`
        );
      }
      for (const m of diff.missingModules) problems.push(`${m}: in the baseline but produced no data this run`);
    }
  }

  return {
    generatedAt: (options.now ?? (() => new Date()))().toISOString(),
    partial,
    targets,
    modules,
    diff,
    problems,
    ok: problems.length === 0,
  };
}

/** Plain-text summary for the console / CI log. */
export function renderReport(report: BenchReport, baseline: Baseline | null): string {
  const lines: string[] = [];
  lines.push(formatTable(report.modules, report.partial ? undefined : (baseline ?? undefined)));
  lines.push("");

  const open = report.targets.flatMap((t) => t.knownIssuesOpen.map((id) => `${t.target}: ${id}`));
  if (open.length > 0) lines.push(`Known issues still reproducing (${open.length}): ${open.join("; ")}`);
  const stale = report.targets.flatMap((t) => t.knownIssuesStale.map((id) => `${t.target}: ${id}`));
  if (stale.length > 0) lines.push(`Known issues that no longer reproduce — remove them: ${stale.join("; ")}`);
  const unexpected = report.targets.flatMap((t) => t.unexpected.map((id) => `${t.target}: ${id}`));
  if (unexpected.length > 0) {
    lines.push(`Unexpected findings (counted as false positives; add to mustFind/optional/mustNotFind): ${unexpected.join("; ")}`);
  }
  if (report.diff && report.diff.improvements.length > 0) {
    lines.push("Improved vs baseline — refresh it with `npm run bench -- --update-baseline` to lock the gain in.");
  }
  if (report.diff && report.diff.newModules.length > 0) {
    lines.push(`Modules not in the baseline yet: ${report.diff.newModules.join(", ")}`);
  }
  if (report.partial) lines.push("Partial run (--target): baseline comparison skipped.");

  lines.push("");
  if (report.ok) {
    lines.push("PASS");
  } else {
    lines.push("FAIL");
    for (const p of report.problems) lines.push(`  - ${p}`);
  }
  return lines.join("\n");
}
