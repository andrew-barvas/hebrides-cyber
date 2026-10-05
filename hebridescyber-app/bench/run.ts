// CLI entry point: `npm run bench`.
//   npm run bench                       run everything, compare with bench/baseline.json
//   npm run bench -- --target a,b       run a subset (no baseline comparison)
//   npm run bench -- --update-baseline  rewrite bench/baseline.json from this run
// Exit codes: 0 pass, 1 regression / hard failure, 2 setup error.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CORPUS } from "./corpus";
import { loadExpectations } from "./lib/expectations";
import { BENCH_MODULES, scanTarget } from "./lib/scan";
import { renderReport, runBenchmark } from "./lib/runner";
import { startSite } from "./lib/server";
import { toBaseline, type Baseline } from "./lib/scoring";

const here = path.dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = path.join(here, "baseline.json");
const REPORT_PATH = path.join(here, "reports", "latest.json");

function readBaseline(): Baseline | null {
  if (!existsSync(BASELINE_PATH)) return null;
  return JSON.parse(readFileSync(BASELINE_PATH, "utf8")) as Baseline;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const update = args.includes("--update-baseline");
  const targetArg = args.indexOf("--target");
  const only = targetArg !== -1 ? (args[targetArg + 1] ?? "").split(",").filter(Boolean) : undefined;

  const baseline = readBaseline();
  const report = await runBenchmark({
    corpus: CORPUS,
    expectations: loadExpectations(path.join(here, "expectations"), BENCH_MODULES),
    scan: scanTarget,
    start: startSite,
    scope: BENCH_MODULES,
    baseline: update ? null : baseline,
    only,
  });

  mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + "\n");

  if (update) {
    if (report.partial) {
      console.error("Refusing to update the baseline from a partial (--target) run.");
      return 2;
    }
    // Hard failures (a must-find missing, a must-not-find present) are never baselined.
    const hard = report.problems.filter((p) => !p.startsWith("No baseline"));
    console.log(renderReport({ ...report, problems: hard, ok: hard.length === 0 }, baseline));
    if (hard.length > 0) return 1;
    writeFileSync(BASELINE_PATH, JSON.stringify(toBaseline(report.modules), null, 2) + "\n");
    console.log(`Baseline written to ${path.relative(process.cwd(), BASELINE_PATH)}`);
    return 0;
  }

  console.log(renderReport(report, baseline));
  console.log(`\nReport written to ${path.relative(process.cwd(), REPORT_PATH)}`);
  return report.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err: Error) => {
    console.error(`Benchmark setup error: ${err.message}`);
    process.exit(2);
  }
);
