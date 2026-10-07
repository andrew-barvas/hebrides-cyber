import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";

const { execToolMock } = vi.hoisted(() => ({ execToolMock: vi.fn() }));
vi.mock("../execTool", () => ({ execTool: execToolMock }));

import { parseHttpxOutput, runHttpProbe, buildHttpProbeFindings, type HttpProbeRecord } from "./hostProbe";

function rec(over: Partial<HttpProbeRecord>): HttpProbeRecord {
  return { input: "", url: "", host: "", port: "", scheme: "https", statusCode: 200, contentLength: 0, title: null, webserver: null, tech: [], ...over };
}

// Real httpx v1.6.10 -json output; see fixtures/httpx/README.md.
const REAL = readFileSync(`${process.cwd()}/src/lib/scanners/fixtures/httpx/probe-1.6.10.jsonl`, "utf8");

describe("parseHttpxOutput (real v1.6.10 -json output)", () => {
  it("maps each live host to its url, status, title, server and tech", () => {
    expect(parseHttpxOutput(REAL)).toEqual([
      { input: "http://127.0.0.1:8097/api/admin", url: "http://127.0.0.1:8097/api/admin", host: "127.0.0.1", port: "8097", scheme: "http", statusCode: 401, contentLength: 24, title: null, webserver: "BaseHTTP/0.6 Python/3.11.15", tech: ["Python:3.11.15"] },
      { input: "http://127.0.0.1:8097/api/health", url: "http://127.0.0.1:8097/api/health", host: "127.0.0.1", port: "8097", scheme: "http", statusCode: 200, contentLength: 15, title: null, webserver: "BaseHTTP/0.6 Python/3.11.15", tech: ["Python:3.11.15"] },
      { input: "http://127.0.0.1:8097", url: "http://127.0.0.1:8097", host: "127.0.0.1", port: "8097", scheme: "http", statusCode: 200, contentLength: 212, title: "Test App Home", webserver: "BaseHTTP/0.6 Python/3.11.15", tech: ["Python:3.11.15"] },
    ]);
  });

  it("skips non-JSON lines, drops failed probes, and dedupes by url", () => {
    const out = [
      "banner text, not json",
      '{"url":"https://a.example","status_code":200,"failed":false}',
      '{"url":"https://a.example","status_code":500,"failed":false}', // duplicate url
      '{"url":"https://down.example","status_code":0,"failed":true}', // never connected
      '{"host":"no-url.example","status_code":200}', // no url
    ].join("\n");
    expect(parseHttpxOutput(out)).toEqual([
      { input: "https://a.example", url: "https://a.example", host: "", port: "", scheme: "", statusCode: 200, contentLength: 0, title: null, webserver: null, tech: [] },
    ]);
  });
});

describe("runHttpProbe", () => {
  beforeEach(() => execToolMock.mockReset());

  it("probes the target plus discovered hosts via -u (never stdin), deduped and capped", async () => {
    execToolMock.mockResolvedValueOnce({ stdout: REAL, stderr: "" });
    const result = await runHttpProbe("https://example.com", ["api.example.com", "api.example.com", "admin.example.com"]);
    expect(result.status).toBe("completed");
    const [bin, args] = execToolMock.mock.calls[0] as [string, string[]];
    expect(bin).toBe("httpx");
    const uIndex = args.indexOf("-u");
    expect(uIndex).toBeGreaterThanOrEqual(0);
    // Primary (URL-normalised) first, then discovered hosts with the repeat deduped.
    expect(args[uIndex + 1]).toBe("https://example.com/,api.example.com,admin.example.com");
    expect(args).toEqual(expect.arrayContaining(["-json", "-silent", "-status-code", "-title", "-tech-detect", "-tls-grab"]));
  });

  it("returns not_configured when the binary is absent", async () => {
    const err = new Error("spawn httpx ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execToolMock.mockRejectedValueOnce(err);
    expect(await runHttpProbe("https://example.com")).toEqual({ status: "not_configured", results: [] });
  });

  it("keeps partial stdout when httpx exits non-zero but printed hosts", async () => {
    const err = Object.assign(new Error("timeout"), { stdout: '{"url":"https://a.example","status_code":200,"failed":false}' });
    execToolMock.mockRejectedValueOnce(err);
    const result = await runHttpProbe("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.results).toHaveLength(1);
  });

  it("returns error on a non-ENOENT failure with no usable stdout", async () => {
    execToolMock.mockRejectedValueOnce(new Error("boom"));
    const result = await runHttpProbe("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("boom");
  });

  it("returns error for an invalid target URL without spawning anything", async () => {
    expect(await runHttpProbe("not a url")).toEqual({ status: "error", results: [], note: "Invalid URL" });
    expect(execToolMock).not.toHaveBeenCalled();
  });
});

describe("buildHttpProbeFindings", () => {
  it("emits one info finding per discovered host, excluding the scanned target itself", () => {
    const findings = buildHttpProbeFindings("https://example.com", [
      rec({ host: "example.com", url: "https://example.com", title: "Home", tech: ["Next.js"] }), // the target — base suite covers it
      rec({ host: "admin.example.com", url: "https://admin.example.com", statusCode: 200, title: "Admin", tech: ["Grafana"], webserver: "nginx" }),
      rec({ host: "staging.example.com", url: "https://staging.example.com", statusCode: 401 }),
    ]);
    expect(findings.map((f) => f.checkId)).toEqual(["http-probe.live:admin.example.com", "http-probe.live:staging.example.com"]);
    expect(findings.every((f) => f.severity === "info")).toBe(true);
    expect(findings[0].title).toBe("Live host: https://admin.example.com");
    expect(findings[0].detail).toContain("[200]");
    expect(findings[0].detail).toContain('"Admin"');
    expect(findings[0].detail).toContain("tech: Grafana");
    expect(findings[0].detail).toContain("server: nginx");
    expect(findings[0].remediation).toBeTruthy();
  });

  it("dedupes by host and rolls up beyond the cap into one summary finding", () => {
    const many = Array.from({ length: 30 }, (_, i) => rec({ host: `h${String(i).padStart(2, "0")}.example.com`, url: `https://h${String(i).padStart(2, "0")}.example.com` }));
    // add a duplicate host — must not double-count
    many.push(rec({ host: "h00.example.com", url: "https://h00.example.com/dup" }));
    const findings = buildHttpProbeFindings("https://example.com", many);
    expect(findings.filter((f) => (f.checkId ?? "").startsWith("http-probe.live:"))).toHaveLength(25);
    const summary = findings.find((f) => f.checkId === "http-probe.live-additional");
    expect(summary).toBeDefined();
    expect(summary?.title).toContain("5 further live host(s)");
  });

  it("returns nothing when only the scanned target is live", () => {
    expect(buildHttpProbeFindings("https://example.com", [rec({ host: "example.com", url: "https://example.com" })])).toEqual([]);
  });
});
