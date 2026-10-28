// WhatWaf integration — WAF detection and fingerprinting.
//
// Returns the WAF WhatWaf identified, or `waf: null` when WhatWaf positively
// reported that there is none; scanExecution.ts's runExtendedTools() turns
// that into the whatwaf.* findings. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.
//
// Evidence discipline: "no WAF" is a medium finding, so it needs WhatWaf's own
// final verdict. Empty output, a traceback or any output without one of the
// verdict lines below is "error" (not run), never a clean "no WAF". WhatWaf
// reports no confidence score, so none is invented here; `evidence` quotes
// the verdict line.
//
// What v1.9 prints to stdout, read from its source (content/__init__.py's
// detection_main; lib/formatter.py prefixes each line with an ANSI-coloured
// "[HH:MM:SS]" stamp and a level tag):
//   one WAF:       [FIREWALL] detected website protection identified as '<name>'
//   several WAFs:  [FIREWALL] <name>   (one line each, no header)
//   unidentified:  [INFO] target seems to be behind some kind of protection for the following reasons:
//   no WAF:        [SUCCESS] no protection identified on target
// "[WARN] no protection identified on target, verifying" comes BEFORE the
// verification requests that can still find protection, so it is not a verdict.
//
// Flags: `-J/--json` writes a file under ~/.whatwaf (and only with -F), never
// stdout, so it isn't passed. `--skip` skips WhatWaf's bypass analysis, which
// fires its tamper payloads at the target for results we don't use.
//
// WhatWaf asks "create an issue?" (raw_input) after an unidentified or "behind
// some kind of protection" verdict and has no flag to skip it. With stdin closed
// that raises EOFError and the process exits non-zero, AFTER printing the
// verdict. So a failed exit still carries stdout, and a WAF verdict in it is
// kept. A non-zero exit never yields "no WAF": that needs a clean run. Seen in
// the real-binary integration run, not in a recorded fixture yet.

import { execTool } from "../../lib/execTool";

const execFileAsync = execTool;

// A real v1.9 run against a plain local server took ~88s at --throttle 3 (about 24
// detection requests), only just inside the old 90s limit.
const WHATWAF_TIMEOUT_MS = 120_000;

export const WHATWAF_ARGS = ["--ra", "--throttle", "1", "--skip"] as const;

export type WhatWafResult =
  | {
      status: "completed";
      /** The WAF WhatWaf identified; null only when it reported there is none. */
      waf: string | null;
      vendor: string | null;
      /** What WhatWaf reported, quoted into the finding. */
      evidence: string;
    }
  | { status: "not_configured" }
  | { status: "error"; note: string };

const ANSI = /\x1b\[[0-9;]*m/g;
const FIREWALL_LINE = /\[FIREWALL\] (.+)$/;
const SINGLE_WAF = /^detected website protection identified as '(.+)'$/;
const UNIDENTIFIED_WAF = /\[INFO\] target seems to be behind some kind of protection/;
const NO_WAF = /\[SUCCESS\] no protection identified on target$/;

function quote(line: string): string {
  return `WhatWaf reported: "${line.replace(/^\[\d{2}:\d{2}:\d{2}\]/, "").slice(0, 200)}".`;
}

export function parseWhatWafOutput(stdout: string): Exclude<WhatWafResult, { status: "not_configured" }> {
  const lines = stdout.replace(ANSI, "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return { status: "error", note: "whatwaf produced no output" };

  const firewallLines = lines.filter((l) => FIREWALL_LINE.test(l));
  const names = firewallLines.map((l) => {
    const reported = (l.match(FIREWALL_LINE) as RegExpMatchArray)[1].trim();
    return reported.match(SINGLE_WAF)?.[1].trim() ?? reported;
  });
  const unidentified = lines.find((l) => UNIDENTIFIED_WAF.test(l));
  const noWaf = lines.find((l) => NO_WAF.test(l));

  if (noWaf && (names.length > 0 || unidentified)) {
    return { status: "error", note: "whatwaf reported both a protection and no protection" };
  }
  if (names.length > 0) {
    return { status: "completed", waf: names.join(", "), vendor: null, evidence: firewallLines.map(quote).join(" ") };
  }
  if (unidentified) return { status: "completed", waf: "Unidentified WAF", vendor: null, evidence: quote(unidentified) };
  if (noWaf) return { status: "completed", waf: null, vendor: null, evidence: quote(noWaf) };
  return { status: "error", note: "whatwaf output had no verdict line, so it says nothing about a WAF" };
}

export async function runWhatWaf(targetUrl: string): Promise<WhatWafResult> {
  try {
    const { stdout } = await execFileAsync(
      "whatwaf",
      ["-u", targetUrl, ...WHATWAF_ARGS],
      { timeout: WHATWAF_TIMEOUT_MS }
    );
    return parseWhatWafOutput(stdout);
  } catch (err) {
    const error = err as NodeJS.ErrnoException & { stdout?: unknown; killed?: boolean };
    if (error.code === "ENOENT") {
      return { status: "not_configured" };
    }
    if (!error.killed && typeof error.stdout === "string") {
      const verdict = parseWhatWafOutput(error.stdout);
      if (verdict.status === "completed" && verdict.waf !== null) return verdict;
    }
    return {
      status: "error",
      note: `whatwaf exited with error: ${error.message}`,
    };
  }
}
