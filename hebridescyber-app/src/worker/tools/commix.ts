// commix integration — dedicated OS command injection confirmation.
//
// A dedicated tool confirms a specific vulnerability class far more reliably
// than a generic DAST rule, as sqlmap.ts does for SQL injection. Requires the
// `commix` command (installed in scheduled-scans.yml); returns "not_configured"
// when it is missing.
//
// Output reading lives in commixOutput.ts, written against output captured
// from a real commix v4.2 run (fixtures/commix/). Facts that shaped this
// module: `--batch` auto-answers commix's prompts; `--crawl=1` was removed
// because it skips the URL's own query parameter when no links are found; and
// the positive-finding wording has not been captured yet, so a run that ends
// without a recognised closing line is an "error", never a clean result.

import { execTool } from "../../lib/execTool";
import { parseInjections, parametersRuledOut, runProblem } from "./commixOutput";

const execFileAsync = execTool;

const COMMIX_TIMEOUT_MS = 120_000;
const COMMIX_MAX_BUFFER = 32 * 1024 * 1024;

export type CommixFinding = {
  parameter: string;
  /** Where the parameter lives: GET, POST, Cookie ... */
  place: string;
};

export type CommixResult =
  | { status: "completed"; vulnerable: boolean; findings: CommixFinding[]; parametersTested: number }
  | { status: "not_configured"; vulnerable: false; findings: [] }
  /** Ran, but there was nothing to test: says nothing about the site. */
  | { status: "not_applicable"; vulnerable: false; findings: []; note: string }
  | { status: "error"; vulnerable: false; findings: []; note: string };

export async function runCommix(targetUrl: string): Promise<CommixResult> {
  let stdout = "";
  let runFailure: string | null = null;
  try {
    const run = await execFileAsync("commix", ["--url", targetUrl, "--batch"], { timeout: COMMIX_TIMEOUT_MS, maxBuffer: COMMIX_MAX_BUFFER });
    stdout = run.stdout;
  } catch (err) {
    const error = err as NodeJS.ErrnoException & { stdout?: string };
    if (error.code === "ENOENT") return { status: "not_configured", vulnerable: false, findings: [] };
    // A timeout or non-zero exit still leaves what commix had printed.
    stdout = error.stdout ?? "";
    runFailure = `commix exited: ${error.message}`;
  }

  const findings = parseInjections(stdout);
  // A reported injection is evidence even if the run didn't finish.
  if (findings.length > 0) return { status: "completed", vulnerable: true, findings, parametersTested: Math.max(parametersRuledOut(stdout), findings.length) };

  if (runFailure) return { status: "error", vulnerable: false, findings: [], note: runFailure };
  const problem = runProblem(stdout);
  if (problem?.kind === "not_applicable") return { status: "not_applicable", vulnerable: false, findings: [], note: problem.note };
  if (problem) return { status: "error", vulnerable: false, findings: [], note: problem.note };
  return { status: "completed", vulnerable: false, findings: [], parametersTested: parametersRuledOut(stdout) };
}
