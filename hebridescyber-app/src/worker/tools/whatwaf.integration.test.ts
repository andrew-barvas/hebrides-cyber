// Runs the real whatwaf binary against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs whatwaf installed and the app
// running, as the tool-integration CI job arranges.
//
// This is the first time WhatWaf v1.9's real stdout is checked against
// parseWhatWafOutput rather than lines transcribed from its source. The local
// app is a plain HTTP server with no WAF in front of it, so WhatWaf's own final
// verdict is "[SUCCESS] no protection identified on target" — the one line the
// parser treats as a trustworthy "no WAF" (empty output or a traceback is an
// error, never a clean result).
import { describe, it, expect } from "vitest";
import { runWhatWaf } from "./whatwaf";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("whatwaf against the local test app", () => {
  it("reports no WAF on the unprotected local server, on WhatWaf's own final verdict", async () => {
    const result = await runWhatWaf(`${base}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.waf).toBeNull();
    expect(result.evidence).toContain("no protection identified on target");
  }, 120_000);

  it("reports an unreachable target as an error, not a clean 'no WAF' result", async () => {
    const result = await runWhatWaf("http://127.0.0.1:9/");
    expect(result.status).toBe("error");
  }, 120_000);
});
