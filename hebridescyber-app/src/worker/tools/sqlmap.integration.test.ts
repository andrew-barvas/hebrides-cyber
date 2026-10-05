// Runs the real sqlmap against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs sqlmap installed and the app
// running, as the tool-integration CI job arranges.
import { describe, it, expect } from "vitest";
import { runSqlmap } from "./sqlmap";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("sqlmap against the local test app", () => {
  it("reports the known SQL injection with its page and DBMS", async () => {
    const result = await runSqlmap(`${base}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${result.status}`);
    expect(result.vulnerable).toBe(true);
    expect(result.findings.some((f) => f.parameter === "id" && f.place === "GET" && f.dbms === "SQLite")).toBe(true);
  }, 200_000);

  it("reports an unreachable target as an error, not a clean result", async () => {
    const result = await runSqlmap("http://127.0.0.1:9/");
    expect(result.status).toBe("error");
  }, 200_000);
});
