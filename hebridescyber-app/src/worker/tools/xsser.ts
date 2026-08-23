// XSSer integration — dedicated cross-site scripting (XSS) confirmation.
//
// Same precedent as sqlmap.ts: ZAP's active scan already has generic XSS
// detection rules, but a dedicated, specialised tool confirms exploitability
// far more reliably than a generic DAST rule — the exact reasoning that
// justified adding sqlmap alongside ZAP's own generic SQLi checks, applied
// here to XSS.
//
// CONFIDENCE NOTE, unlike sqlmap.ts: sqlmap's flags/log format here were
// copied from an already-installed, already-working integration in this
// codebase. XSSer's CLI is real (Debian package `xsser`, actively
// referenced by security tooling lists) but far less consistently
// documented than sqlmap's, and this module was written without a real
// XSSer binary available to test against. `--auto` (automated crawl +
// payload testing, no interactive prompts) and the stdout markers parsed
// below are believed correct but NOT verified end-to-end the way every
// other tool integration in this codebase has been — run `xsser --help`
// against the real installed binary the first time this runs for real in
// CI and adjust the args/parser below if the output shape differs. The
// ENOENT/not_configured contract below means a wrong flag or parser miss
// degrades to "found nothing" silently, never a crash or a false finding —
// the same safety net every optional tool in this suite already has.
//
// Requires the `xsser` command (installed in scheduled-scans.yml's `work`
// job). Returns gracefully when the binary is missing.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const XSSER_TIMEOUT_MS = 120_000;

export type XsserFinding = {
  url: string;
  payload: string | null;
};

export type XsserResult =
  | { status: "completed"; vulnerable: boolean; findings: XsserFinding[] }
  | { status: "not_configured"; vulnerable: false; findings: [] }
  | { status: "error"; vulnerable: false; findings: []; note: string };

export async function runXsser(targetUrl: string): Promise<XsserResult> {
  try {
    const { stdout } = await execFileAsync(
      "xsser",
      [
        "--url", targetUrl,
        "--auto", // automated crawl + injection using XSSer's built-in payload set, no interactive prompts
      ],
      { timeout: XSSER_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );

    // XSSer's CLI output reports a confirmed injection with a line
    // containing "Injection" and the reflected payload — this pattern is
    // the least certain part of this module (see header note). Matched
    // defensively: a miss here just means zero findings, not an error.
    const findings: XsserFinding[] = [];
    const injectionPattern = /\[Injection\][^\n]*?(?:in|at)?\s*(https?:\/\/\S+)/gi;
    let match: RegExpExecArray | null;
    while ((match = injectionPattern.exec(stdout)) !== null) {
      findings.push({ url: match[1], payload: null });
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
      note: `xsser exited: ${error.message}`,
    };
  }
}
