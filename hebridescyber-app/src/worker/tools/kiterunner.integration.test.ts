// Runs the real kiterunner (`kr`) against the local test app
// (tests/fixtures/test-app). Skipped unless RUN_TOOL_INTEGRATION=1: it needs
// `kr` installed, a compiled .kite at KITERUNNER_WORDLIST, and the app
// running, as the tool-integration CI job arranges.
import { describe, it, expect } from "vitest";
import { runKiterunner } from "./kiterunner";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("kiterunner against the local test app", () => {
  it("discovers the API routes that exist and drops the misses", async () => {
    const result = await runKiterunner(base);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const paths = Object.fromEntries(result.endpoints.map((e) => [e.path, e.statusCode]));
    expect(paths["/api/health"]).toBe(200);
    expect(paths["/api/admin"]).toBe(401);
    expect(paths["/api/nope"]).toBeUndefined(); // 404 filtered out
  }, 200_000);
});
