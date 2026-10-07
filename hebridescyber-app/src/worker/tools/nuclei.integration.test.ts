// Runs the real nuclei against the local test app (tests/fixtures/test-app)
// through runNuclei, as a scheduled scan does. Skipped unless
// RUN_TOOL_INTEGRATION=1: it needs nuclei installed (it fetches its templates
// on first run) and the app running, as the tool-integration CI job arranges.
//
// Regression: nuclei reads targets from a piped stdin, and execFile left
// stdin open, so nuclei waited for input until it was killed at the timeout,
// on every scan, with no results (see src/lib/execTool.ts).
import { describe, it, expect } from "vitest";
import { runNuclei } from "./nuclei";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("nuclei against the local test app", () => {
  it("finishes the scan instead of being killed at the timeout", async () => {
    const started = Date.now();
    const result = await runNuclei(`${base}/`, []);
    expect(result).toMatchObject({ status: "completed" });
    expect(Date.now() - started).toBeLessThan(110_000);
  }, 200_000);
});
