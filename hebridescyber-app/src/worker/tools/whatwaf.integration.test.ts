// Runs the real whatwaf binary against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs whatwaf installed and the app
// running, as the tool-integration CI job arranges.
//
// This exercises WhatWaf v1.9's real stdout against runWhatWaf for the first
// time, and reality differs from the obvious guess: WhatWaf does NOT report the
// plain local server as "no protection". It infers "some kind of protection"
// (the app's status code and header values change when a payload is appended),
// prints the "[INFO] target seems to be behind some kind of protection" verdict,
// then hits an interactive "create an issue?" raw_input prompt it has no flag to
// skip — which EOFErrors on execTool's closed stdin and makes whatwaf exit
// non-zero AFTER printing the verdict. whatwaf.ts keeps a WAF verdict already in
// that stdout on such a crash, so the result is a completed "Unidentified WAF",
// never a fabricated "no WAF". The per-test timeout is above whatwaf.ts's own
// 120s timeout so that, if a run ever stalls, its timeout decides the result
// rather than vitest killing the test.
import { describe, it, expect } from "vitest";
import { runWhatWaf } from "./whatwaf";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("whatwaf against the local test app", () => {
  it("keeps the unidentified-protection verdict WhatWaf prints before its prompt crash", async () => {
    const result = await runWhatWaf(`${base}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.waf).toBe("Unidentified WAF");
    expect(result.evidence).toContain("behind some kind of protection");
  }, 180_000);

  it("reports an unreachable target as an error, not a clean 'no WAF' result", async () => {
    const result = await runWhatWaf("http://127.0.0.1:9/");
    expect(result.status).toBe("error");
  }, 180_000);
});
