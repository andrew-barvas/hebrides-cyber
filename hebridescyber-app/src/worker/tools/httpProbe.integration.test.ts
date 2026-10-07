// Runs the real httpx against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs httpx installed and the app
// running, as the tool-integration CI job arranges. Verifies the wrapper's
// -json parsing against a real binary, the way the fixture-based unit test in
// src/lib/scanners/hostProbe.test.ts can't.
import { describe, it, expect } from "vitest";
import { runHttpProbe } from "../../lib/scanners/hostProbe";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("httpx against the local test app", () => {
  it("reports the live host with its status, title and detected tech", async () => {
    const result = await runHttpProbe(`${base}/`, [`${base}/api/admin`]);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);

    const root = result.results.find((r) => r.url === base || r.url === `${base}/`);
    expect(root, "root host should be probed").toBeDefined();
    expect(root?.statusCode).toBe(200);
    expect(root?.title).toBe("Test App Home");
    expect(root?.tech.join(",")).toContain("Python");

    const admin = result.results.find((r) => r.url.endsWith("/api/admin"));
    expect(admin?.statusCode).toBe(401);
  }, 200_000);
});
