// commix integration — dedicated OS command injection confirmation.
//
// Same precedent as sqlmap.ts and xsser.ts: a dedicated, specialised tool
// confirms exploitability of a specific vulnerability class far more
// reliably than a generic DAST active-scan rule. commix (COMMand
// Injection eXploiter) is explicitly modelled on sqlmap's own design and
// batch-mode CLI conventions, so its integration here mirrors sqlmap.ts
// closely.
//
// CONFIDENCE NOTE, same as xsser.ts: this module was written without a
// real commix binary available to test against. `--batch` (never prompt,
// matching sqlmap's own flag) is a well-documented commix flag; the
// vulnerability-found marker parsed below is believed correct but not
// verified end-to-end. The ENOENT/not_configured contract means a wrong
// flag or parser miss degrades to "found nothing" silently, never a crash
// or a false finding.
//
// Requires the `commix` command (installed in scheduled-scans.yml's `work`
// job). Returns gracefully when the binary is missing.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const COMMIX_TIMEOUT_MS = 120_000;

export type CommixFinding = {
  parameter: string;
};

export type CommixResult =
  | { status: "completed"; vulnerable: boolean; findings: CommixFinding[] }
  | { status: "not_configured"; vulnerable: false; findings: [] }
  | { status: "error"; vulnerable: false; findings: []; note: string };

export async function runCommix(targetUrl: string): Promise<CommixResult> {
  try {
    const { stdout } = await execFileAsync(
      "commix",
      [
        "--url", targetUrl,
        "--batch", // never prompt, accept commix's own defaults — matches sqlmap.ts's identical flag
        "--crawl=1",
      ],
      { timeout: COMMIX_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );

    // commix reports a confirmed injection via a line naming the
    // vulnerable parameter — this pattern is the least certain part of
    // this module (see header note). Matched defensively: a miss here
    // just means zero findings, not an error.
    const findings: CommixFinding[] = [];
    const foundPattern = /parameter '(.+?)' (?:seems|is) (?:injectable|vulnerable)/gi;
    let match: RegExpExecArray | null;
    while ((match = foundPattern.exec(stdout)) !== null) {
      findings.push({ parameter: match[1] });
    }

    return { status: "completed", vulnerable: findings.length > 0, findings };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", vulnerable: false, findings: [] };
    }
    return {
      status: "error",
      vulnerable: false,
      findings: [],
      note: `commix exited: ${error.message}`,
    };
  }
}
