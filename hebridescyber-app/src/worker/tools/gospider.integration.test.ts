// Runs the real gospider against the local test app (tests/fixtures/test-app).
// Skipped unless RUN_TOOL_INTEGRATION=1: it needs gospider installed and the
// app running, as the tool-integration CI job arranges.
import { describe, it, expect } from "vitest";
import { runGospider } from "./gospider";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("gospider against the local test app", () => {
  it("finds the API paths named in the site's script, the S3 bucket, and no third-party URL", async () => {
    const result = await runGospider(`${base}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const of = (type: string) => result.endpoints.filter((e) => e.type === type).map((e) => e.value);
    expect(of("js-endpoint").sort()).toEqual([`${base}/api/internal/admin/export`, `${base}/api/v1/users`]);
    expect(of("js-file")).toContain(`${base}/static/app.js`);
    expect(of("aws-s3")).toEqual(["acme-uploads.s3.amazonaws.com"]);
    expect(of("url")).toContain(`${base}/item?id=1`);
    expect(JSON.stringify(result.endpoints)).not.toContain("cdn.example.org");
  }, 200_000);
});
