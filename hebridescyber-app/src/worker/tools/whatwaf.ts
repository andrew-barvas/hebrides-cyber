// WhatWaf integration — WAF detection and fingerprinting.
//
// Returns the WAF WhatWaf identified, or `waf: null` when WhatWaf positively
// reported that there is none; scanExecution.ts's runExtendedTools() turns
// that into the whatwaf.* findings. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.
//
// Evidence discipline: "no WAF" is a medium finding, so it needs WhatWaf to
// have said so — JSON `is_protected: false`, or an explicit "no WAF" /
// "unprotected" line. Empty output, a traceback, a changed format or JSON
// with neither field is "error" (not run), never a clean "no WAF". WhatWaf
// reports no confidence score, so none is invented here; `evidence` quotes
// what it did report.
//
// Not yet checked against a real WhatWaf binary (there is no captured-output
// fixture or integration test, unlike katana/dalfox), so its real output may
// well land on "error" until a parser is built from a recorded run.

import { execTool } from "../../lib/execTool";

const execFileAsync = execTool;

const WHATWAF_TIMEOUT_MS = 90_000;

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

type WhatWafJsonOutput = {
  firewall_name?: unknown;
  firewall_url?: unknown;
  is_protected?: unknown;
};

const NO_WAF_TEXT = /no waf|unprotected/i;
const UNREAD_OUTPUT = "whatwaf output could not be interpreted, so it says nothing about a WAF";

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

export function parseWhatWafOutput(stdout: string): Exclude<WhatWafResult, { status: "not_configured" }> {
  const text = stdout.trim();
  if (!text) return { status: "error", note: "whatwaf produced no output" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    const line = text.split(/\r?\n/).find((l) => NO_WAF_TEXT.test(l));
    if (line) return { status: "completed", waf: null, vendor: null, evidence: `WhatWaf reported: "${line.trim().slice(0, 200)}".` };
    return { status: "error", note: UNREAD_OUTPUT };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { status: "error", note: UNREAD_OUTPUT };

  const json = parsed as WhatWafJsonOutput;
  const name = nonEmptyString(json.firewall_name);
  if (json.is_protected === false) {
    if (name) return { status: "error", note: `whatwaf reported is_protected: false but named a firewall (${name.slice(0, 100)})` };
    return { status: "completed", waf: null, vendor: null, evidence: "WhatWaf reported is_protected: false." };
  }
  if (name) return { status: "completed", waf: name, vendor: nonEmptyString(json.firewall_url), evidence: `WhatWaf identified the firewall as ${name}.` };
  if (json.is_protected === true) {
    return { status: "completed", waf: "Unidentified WAF", vendor: null, evidence: "WhatWaf reported is_protected: true but did not name the firewall." };
  }
  return { status: "error", note: "whatwaf output had neither is_protected nor firewall_name" };
}

export async function runWhatWaf(targetUrl: string): Promise<WhatWafResult> {
  try {
    const { stdout } = await execFileAsync(
      "whatwaf",
      ["-u", targetUrl, "--json", "--ra", "--throttle", "3"],
      { timeout: WHATWAF_TIMEOUT_MS }
    );
    return parseWhatWafOutput(stdout);
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured" };
    }
    return {
      status: "error",
      note: `whatwaf exited with error: ${error.message}`,
    };
  }
}
