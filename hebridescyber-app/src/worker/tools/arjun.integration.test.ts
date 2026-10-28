// Runs the real arjun binary against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs arjun installed and the app
// running, as the tool-integration CI job arranges.
//
// This is the test that caught arjun.ts parsing its -oJ output as an array when
// arjun actually writes an object keyed by URL — the old wrapper silently
// returned zero parameters on every real scan, and its unit test encoded the
// same wrong shape.
import { describe, it, expect } from "vitest";
import { runArjun } from "./arjun";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("arjun against the local test app", () => {
  it("discovers the reflected 'q' parameter on /search", async () => {
    // /search reflects its `q` value into the body, so arjun's canary injection
    // produces a clear differential and `q` is in arjun's built-in wordlist.
    const result = await runArjun(`${base}/search`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const allParams = result.parameters.flatMap((p) => p.params);
    expect(allParams, `arjun should have discovered 'q'; got ${JSON.stringify(result.parameters)}`).toContain("q");
  }, 200_000);
});
