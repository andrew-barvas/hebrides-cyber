// Runs the real dalfox binary against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs dalfox installed and the
// app running, as the tool-integration CI job arranges.
import { describe, it, expect } from "vitest";
import { runDalfox } from "./dalfox";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("dalfox against the local test app", () => {
  it("confirms the reflected XSS on /search?q=", async () => {
    const result = await runDalfox(`${base}/search?q=hello`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].param).toBe("q");
  }, 120_000);

  it("is clean against the JSON API endpoint, with no injectable parameter", async () => {
    const result = await runDalfox(`${base}/api/health`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.findings).toEqual([]);
  }, 120_000);
});
