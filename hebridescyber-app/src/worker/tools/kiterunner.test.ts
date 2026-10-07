import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";

const { execToolMock } = vi.hoisted(() => ({ execToolMock: vi.fn() }));
vi.mock("../../lib/execTool", () => ({ execTool: execToolMock }));

import { parseKiterunnerOutput, runKiterunner } from "./kiterunner";

// Real kiterunner v1.0.2 output; see fixtures/kiterunner/README.md.
const REAL = readFileSync(`${process.cwd()}/src/worker/tools/fixtures/kiterunner/scan-1.0.2.jsonl`, "utf8");

describe("parseKiterunnerOutput (real v1.0.2 JSON output)", () => {
  it("reports each discovered endpoint once, with its status and length", () => {
    expect(parseKiterunnerOutput(REAL)).toEqual([
      { method: "GET", path: "/api/health", statusCode: 200, contentLength: 15 },
      { method: "GET", path: "/api/admin", statusCode: 401, contentLength: 24 },
    ]);
  });

  it("skips progress/log lines and anything that isn't a JSON object", () => {
    const out = ['{"level":"info","message":"finished quick scan"}', "not json", "", '{"method":"GET","path":"/a","responses":[{"sc":200,"len":5}]}'].join("\n");
    expect(parseKiterunnerOutput(out)).toEqual([{ method: "GET", path: "/a", statusCode: 200, contentLength: 5 }]);
  });

  it("ignores a route with no usable response, and defaults a missing length to 0", () => {
    const out = [
      '{"method":"GET","path":"/no-responses","responses":[]}',
      '{"method":"GET","path":"/bad-sc","responses":[{"len":9}]}',
      '{"method":"POST","path":"/ok","responses":[{"sc":201}]}',
    ].join("\n");
    expect(parseKiterunnerOutput(out)).toEqual([{ method: "POST", path: "/ok", statusCode: 201, contentLength: 0 }]);
  });
});

describe("runKiterunner", () => {
  const WORDLIST = "/tmp/routes.kite";
  beforeEach(() => {
    execToolMock.mockReset();
    process.env.KITERUNNER_WORDLIST = WORDLIST;
  });
  afterEach(() => {
    delete process.env.KITERUNNER_WORDLIST;
  });

  it("no-ops with not_configured when no wordlist is set, without spawning anything", async () => {
    delete process.env.KITERUNNER_WORDLIST;
    expect(await runKiterunner("https://example.com")).toEqual({ status: "not_configured" });
    expect(execToolMock).not.toHaveBeenCalled();
  });

  it("scans with the JSON format, the configured wordlist and 404/429 filtered out", async () => {
    execToolMock.mockResolvedValueOnce({ stdout: REAL, stderr: "" });
    const result = await runKiterunner("https://example.com");
    expect(result.status).toBe("completed");
    const [bin, args] = execToolMock.mock.calls[0] as [string, string[]];
    expect(bin).toBe("kr");
    expect(args.slice(0, 7)).toEqual(["scan", "https://example.com", "-w", WORDLIST, "-o", "json", "-q"]);
    expect(args).toEqual(expect.arrayContaining(["--fail-status-codes", "404,429", "--kitebuilder-full-scan"]));
    expect(args).not.toContain("--wildcard-detection"); // valueless flag defaults on; passing a value breaks kr's arg parsing
  });

  it("returns not_configured when the binary is absent", async () => {
    const err = new Error("spawn kr ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execToolMock.mockRejectedValueOnce(err);
    expect(await runKiterunner("https://example.com")).toEqual({ status: "not_configured" });
  });

  it("returns error on non-ENOENT failure", async () => {
    execToolMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runKiterunner("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("timeout");
  });
});
