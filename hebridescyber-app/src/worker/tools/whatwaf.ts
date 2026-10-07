// WhatWaf integration — WAF detection and fingerprinting.
//
// Returns the detected WAF name/vendor and confidence, plus a Finding[] for
// wiring into scanExecution.ts's runExtendedTools() the same way every other
// extended tool does. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.

import { execTool } from "../../lib/execTool";

const execFileAsync = execTool;

const WHATWAF_TIMEOUT_MS = 90_000;

export type WhatWafResult =
  | {
      status: "completed";
      waf: string | null;
      vendor: string | null;
      confidence: number;
    }
  | { status: "not_configured" }
  | { status: "error"; note: string };

type WhatWafJsonOutput = {
  firewall_name?: string;
  firewall_url?: string;
  is_protected?: boolean;
};

export async function runWhatWaf(targetUrl: string): Promise<WhatWafResult> {
  try {
    const { stdout } = await execFileAsync(
      "whatwaf",
      ["-u", targetUrl, "--json", "--ra", "--throttle", "3"],
      { timeout: WHATWAF_TIMEOUT_MS }
    );

    let parsed: WhatWafJsonOutput;
    try {
      parsed = JSON.parse(stdout.trim());
    } catch {
      if (stdout.toLowerCase().includes("no waf") || stdout.toLowerCase().includes("unprotected")) {
        return { status: "completed", waf: null, vendor: null, confidence: 90 };
      }
      return { status: "completed", waf: null, vendor: null, confidence: 0 };
    }

    if (parsed.is_protected === false || !parsed.firewall_name) {
      return { status: "completed", waf: null, vendor: null, confidence: 90 };
    }

    return {
      status: "completed",
      waf: parsed.firewall_name ?? null,
      vendor: parsed.firewall_url ?? null,
      confidence: 85,
    };
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
