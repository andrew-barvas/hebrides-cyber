// Runs the real ffuf against the local test app (tests/fixtures/test-app),
// through runContentDiscovery. Skipped unless RUN_TOOL_INTEGRATION=1: it needs
// ffuf installed and the app running, as the tool-integration CI job arranges.
//
// Self-contained wordlist: the curated production list (content-dirs.txt)
// targets real-world sensitive paths, not this toy app's routes, so the test
// writes its own tiny wordlist of the app's known paths and points
// CONTENT_DISCOVERY_WORDLIST at it. This exercises the real binary + the -of
// json parser end to end against known statuses.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runContentDiscovery } from "./contentDiscovery";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";
const wordlist = join(tmpdir(), "content-discovery-it-wordlist.txt");
let prevWordlist: string | undefined;

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("ffuf against the local test app", () => {
  beforeAll(() => {
    writeFileSync(wordlist, ["api/health", "api/admin", "item", "search", "definitely-not-here-xyz"].join("\n"), "utf8");
    prevWordlist = process.env.CONTENT_DISCOVERY_WORDLIST;
    process.env.CONTENT_DISCOVERY_WORDLIST = wordlist;
  });
  afterAll(() => {
    if (prevWordlist === undefined) delete process.env.CONTENT_DISCOVERY_WORDLIST;
    else process.env.CONTENT_DISCOVERY_WORDLIST = prevWordlist;
    rmSync(wordlist, { force: true });
  });

  it("discovers the reachable paths with their real status codes and drops the 404", async () => {
    const result = await runContentDiscovery(base);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const byPath = new Map(result.hits.map((h) => [h.path, h.status]));
    expect(byPath.get("api/health")).toBe(200);
    expect(byPath.get("api/admin")).toBe(401);
    expect(byPath.has("definitely-not-here-xyz")).toBe(false); // 404 not matched
  }, 200_000);
});
