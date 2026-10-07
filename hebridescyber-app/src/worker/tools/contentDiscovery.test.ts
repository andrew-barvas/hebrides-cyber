import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";

const { execToolMock } = vi.hoisted(() => ({ execToolMock: vi.fn() }));
vi.mock("../../lib/execTool", () => ({ execTool: execToolMock }));

import { parseFfufOutput, buildContentDiscoveryFindings, runContentDiscovery, type ContentDiscoveryHit } from "./contentDiscovery";

// Real ffuf v2.1.0 -of json output; see fixtures/ffuf/README.md.
const REAL = readFileSync(`${process.cwd()}/src/worker/tools/fixtures/ffuf/scan-2.1.0.json`, "utf8");

describe("parseFfufOutput (real v2.1.0 -of json output)", () => {
  it("maps each result to its path, url, status, length and content-type, deduped", () => {
    const hits = parseFfufOutput(REAL);
    expect(hits).toEqual([
      { path: "api/health", url: "http://127.0.0.1:8096/api/health", status: 200, length: 15, contentType: "text/html" },
      { path: "item", url: "http://127.0.0.1:8096/item", status: 200, length: 26, contentType: "text/html" },
      { path: "api/admin", url: "http://127.0.0.1:8096/api/admin", status: 401, length: 24, contentType: "application/json" },
      { path: "search", url: "http://127.0.0.1:8096/search", status: 200, length: 39, contentType: "text/html" },
    ]);
  });

  it("returns [] for non-JSON or a resultless document", () => {
    expect(parseFfufOutput("not json")).toEqual([]);
    expect(parseFfufOutput('{"results":[]}')).toEqual([]);
    expect(parseFfufOutput("{}")).toEqual([]);
  });
});

describe("buildContentDiscoveryFindings", () => {
  const hit = (over: Partial<ContentDiscoveryHit>): ContentDiscoveryHit => ({ path: "x", url: "https://e.com/x", status: 200, length: 1, contentType: "text/html", ...over });

  it("emits one low finding per path, keyed by path, sorted", () => {
    const findings = buildContentDiscoveryFindings([
      hit({ path: "admin", url: "https://e.com/admin", status: 200 }),
      hit({ path: "backup", url: "https://e.com/backup", status: 401 }),
    ]);
    expect(findings.map((f) => f.checkId)).toEqual(["content-discovery.found:admin", "content-discovery.found:backup"]);
    expect(findings.every((f) => f.severity === "low")).toBe(true);
    expect(findings[0].detail).toContain("200");
    expect(findings[0].remediation).toBeTruthy();
  });

  it("caps per-path rows at 25 and rolls the rest into one info summary", () => {
    const many = Array.from({ length: 30 }, (_, i) => hit({ path: `p${String(i).padStart(2, "0")}`, url: `https://e.com/p${String(i).padStart(2, "0")}` }));
    const findings = buildContentDiscoveryFindings(many);
    expect(findings.filter((f) => (f.checkId ?? "").startsWith("content-discovery.found:"))).toHaveLength(25);
    expect(findings.find((f) => f.checkId === "content-discovery.found-additional")?.title).toContain("5 further");
  });

  it("returns nothing for no hits", () => {
    expect(buildContentDiscoveryFindings([])).toEqual([]);
  });
});

describe("runContentDiscovery", () => {
  beforeEach(() => {
    execToolMock.mockReset();
    process.env.CONTENT_DISCOVERY_WORDLIST = "/tmp/wl.txt";
    // Default calibration: the probe path 404s (a normal site), so no -fs filter.
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 404, text: () => Promise.resolve("") }));
  });
  afterEach(() => {
    delete process.env.CONTENT_DISCOVERY_WORDLIST;
    vi.unstubAllGlobals();
  });

  it("not_configured when no wordlist is set, without spawning anything", async () => {
    delete process.env.CONTENT_DISCOVERY_WORDLIST;
    expect(await runContentDiscovery("https://example.com")).toEqual({ status: "not_configured" });
    expect(execToolMock).not.toHaveBeenCalled();
  });

  it("not_configured when the binary is absent (ENOENT)", async () => {
    const err = new Error("spawn ffuf ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execToolMock.mockRejectedValueOnce(err);
    expect(await runContentDiscovery("https://example.com")).toEqual({ status: "not_configured" });
  });

  it("builds the ffuf args: FUZZ on the origin, json output, rate/time caps; no size filter for a normal 404 site", async () => {
    execToolMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    await runContentDiscovery("https://example.com/some/path");
    const [bin, args] = execToolMock.mock.calls[0] as [string, string[]];
    expect(bin).toBe("ffuf");
    expect(args[args.indexOf("-u") + 1]).toBe("https://example.com/FUZZ"); // origin only, not /some/path
    expect(args).toEqual(expect.arrayContaining(["-of", "json", "-rate", "20", "-maxtime", "120"]));
    expect(args).not.toContain("-fs"); // 404 calibration → no catch-all filter
  });

  it("adds -fs <size> when the site is a catch-all (answers a missing path with success)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 200, text: () => Promise.resolve("SHELL") }));
    execToolMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    await runContentDiscovery("https://spa.example.com");
    const [, args] = execToolMock.mock.calls[0] as [string, string[]];
    expect(args[args.indexOf("-fs") + 1]).toBe("5"); // "SHELL".length
  });

  it("error on an invalid URL without spawning anything", async () => {
    expect(await runContentDiscovery("not a url")).toEqual({ status: "error", note: "Invalid URL" });
    expect(execToolMock).not.toHaveBeenCalled();
  });
});
