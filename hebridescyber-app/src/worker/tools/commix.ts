// commix integration — dedicated OS command injection confirmation.
//
// Same precedent as sqlmap.ts: a dedicated, specialised tool
// confirms exploitability of a specific vulnerability class far more
// reliably than a generic DAST active-scan rule. commix (COMMand
// Injection eXploiter) is explicitly modelled on sqlmap's own design and
// batch-mode CLI conventions, so its integration here mirrors sqlmap.ts
// closely.
//
// CONFIDENCE NOTE (updated, docs/ENHANCEMENTS.md E-18): verified against a
// real commix v4.2 binary (git clone, run locally) against a deliberately
// vulnerable local test target — `--url`/`--batch` are confirmed correct
// (`--batch` auto-answers every interactive prompt with commix's own
// sensible default, matching sqlmap's identical flag), and the real
// detection pipeline (heuristic → classic results-based → time-based blind
// → file-based semi-blind) was observed correctly progressing end-to-end
// against a genuine injection point.
//
// A `--crawl=1` flag that used to be here was REMOVED after confirming it
// causes a real bug: when commix's crawler finds "no usable links" on the
// target page, it stops without ever testing the URL's own query
// parameter — so a target whose only injectable parameter is already in
// the URL (the common case for a DAST-style scan) would be silently
// skipped entirely. Confirmed by running with and without the flag against
// the same target: with it, commix reported "No usable links found" and
// exited; without it, commix proceeded to test the parameter directly.
//
// Still not independently confirmed: the exact wording of the
// vulnerability-found marker parsed below. Live verification runs against
// time/file-based blind techniques are slow (many timed requests) and both
// were stopped before reaching a natural "confirmed" line — source tracing
// (`commix`'s own `checks.py`) suggests the real message may not exactly
// match this regex in every injection-type case (e.g. HTTP-header
// injections vs. GET-parameter injections build the message differently).
// The ENOENT/not_configured contract means a wrong flag or parser miss
// still degrades to "found nothing" silently, never a crash or a false
// finding — but don't treat this regex as fully proven.
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
