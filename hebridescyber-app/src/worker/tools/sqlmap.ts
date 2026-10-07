// sqlmap integration — SQL injection detection.
//
// Runs sqlmap in batch mode against the target URL (crawling to depth 2 and
// testing the forms it finds). Requires the `sqlmap` command (installed in
// scheduled-scans.yml via pip3); returns "not_configured" when it is missing.
//
// Output reading lives in sqlmapOutput.ts, written against output captured
// from a real sqlmap run (fixtures/sqlmap/). Two facts shaped this module:
// sqlmap exits 0 even when it cannot reach the target, and it writes results
// to <output-dir>/<host>/log and results-*.csv (not output.log).
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md): "completed, not
// vulnerable" requires proof that sqlmap ran to its closing line and tested at
// least one parameter. An unreachable target or an unfinished run is "error",
// and a run with nothing to test is "not_applicable" — never a clean result,
// since findingLifecycle only treats "completed" as covered.

import { execTool } from "../../lib/execTool";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { countParametersTested, mergeInjectionPoints, parseReportedBlocks, parseResultsCsv, runProblem, type InjectionPoint } from "./sqlmapOutput";

const execFileAsync = execTool;

const SQLMAP_TIMEOUT_MS = 180_000;
// A crawl-and-test run prints thousands of lines; the default 1 MB maxBuffer
// kills the process mid-run and discards what it had already found.
const SQLMAP_MAX_BUFFER = 64 * 1024 * 1024;
const MAX_FINDINGS = 50;

export type SqlmapFinding = {
  parameter: string;
  /** Where the parameter lives: GET, POST, Cookie, URI ... */
  place: string;
  type: "SQL Injection";
  /** sqlmap's own technique titles, e.g. "boolean-based blind". */
  techniques: string[];
  dbms: string | null;
  /** The page it was found on, when sqlmap's results file names it. */
  url: string | null;
};

export type SqlmapResult =
  | { status: "completed"; vulnerable: boolean; findings: SqlmapFinding[]; parametersTested: number }
  | { status: "not_configured"; vulnerable: false; findings: [] }
  /** Ran, but there were no parameters or forms to test: says nothing about the site. */
  | { status: "not_applicable"; vulnerable: false; findings: []; note: string }
  | { status: "error"; vulnerable: false; findings: []; note: string };

/** What sqlmap left in its output directory: per-host logs and the results CSV. */
async function readOutputDir(outputDir: string): Promise<InjectionPoint[][]> {
  const sources: InjectionPoint[][] = [];
  for (const entry of await readdir(outputDir, { withFileTypes: true })) {
    const path = join(outputDir, entry.name);
    if (entry.isDirectory()) {
      const log = await readFile(join(path, "log"), "utf8").catch(() => "");
      sources.push(parseReportedBlocks(log));
    } else if (/^results-.*\.csv$/.test(entry.name)) {
      sources.push(parseResultsCsv(await readFile(path, "utf8")));
    }
  }
  return sources;
}

export async function runSqlmap(targetUrl: string): Promise<SqlmapResult> {
  const outputDir = await mkdtemp(join(tmpdir(), `sqlmap-${randomUUID()}-`));
  let stdout = "";
  let runFailure: string | null = null;

  try {
    const run = await execFileAsync(
      "sqlmap",
      [
        "--url", targetUrl,
        "--batch", // never prompt
        "--output-dir", outputDir,
        "--level", "1",
        "--risk", "1",
        "--timeout", "30",
        "--retries", "1",
        "--random-agent",
        "--forms", // test form parameters
        "--crawl", "2",
      ],
      { timeout: SQLMAP_TIMEOUT_MS, maxBuffer: SQLMAP_MAX_BUFFER }
    );
    stdout = run.stdout;
  } catch (err) {
    const error = err as NodeJS.ErrnoException & { stdout?: string };
    if (error.code === "ENOENT") {
      await rm(outputDir, { recursive: true, force: true });
      return { status: "not_configured", vulnerable: false, findings: [] };
    }
    // A timeout or non-zero exit still leaves what sqlmap had found.
    stdout = error.stdout ?? "";
    runFailure = `sqlmap exited: ${error.message}`;
  }

  try {
    const points = mergeInjectionPoints([parseReportedBlocks(stdout), ...(await readOutputDir(outputDir))]).slice(0, MAX_FINDINGS);
    const tested = countParametersTested(stdout);

    // A reported injection point is evidence even if the run didn't finish.
    if (points.length > 0) {
      const findings = points.map((p) => ({ ...p, type: "SQL Injection" as const }));
      return { status: "completed", vulnerable: true, findings, parametersTested: tested };
    }
    // Nothing found proves nothing unless the run completed and tested something.
    const problem = runFailure ?? runProblem(stdout);
    if (problem) return { status: "error", vulnerable: false, findings: [], note: problem };
    if (tested === 0) {
      return { status: "not_applicable", vulnerable: false, findings: [], note: "sqlmap found no parameters or forms to test" };
    }
    return { status: "completed", vulnerable: false, findings: [], parametersTested: tested };
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
}
