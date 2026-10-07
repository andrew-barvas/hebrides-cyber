import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";

const { execFileMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
}));

vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
  default: { execFile: (...args: unknown[]) => execFileMock(...args) },
}));
vi.mock("node:util", () => ({
  promisify: () => execFileMock,
  default: { promisify: () => execFileMock },
}));

import { parseGospiderOutput, runGospider } from "./gospider";

// Real gospider v1.1.6 output; see fixtures/gospider/README.md.
const REAL = readFileSync(`${process.cwd()}/src/worker/tools/fixtures/gospider/js-app-1.1.6.txt`, "utf8");
const TARGET = "http://127.0.0.1:8098/";

beforeEach(() => {
  execFileMock.mockReset();
});

describe("parseGospiderOutput (real v1.1.6 output)", () => {
  const endpoints = parseGospiderOutput(REAL, TARGET);
  const of = (type: string) => endpoints.filter((e) => e.type === type).map((e) => e.value);

  it("takes endpoints from the paths found inside the site's scripts, once each, as absolute URLs", () => {
    expect(of("js-endpoint")).toEqual(["http://127.0.0.1:8098/api/v1/users", "http://127.0.0.1:8098/api/internal/admin/export"]);
  });

  it("never counts a script file, or a third-party URL named in a script, as an endpoint", () => {
    expect(of("js-endpoint")).not.toContain("http://127.0.0.1:8098/static/app.js");
    expect(endpoints.map((e) => e.value).join(" ")).not.toContain("cdn.example.org");
    expect(of("js-file")).toEqual(["http://127.0.0.1:8098/static/app.js"]);
  });

  it("reads S3 bucket hosts from the aws type", () => {
    expect(of("aws-s3")).toEqual(["acme-uploads.s3.amazonaws.com"]);
  });

  it("keeps crawled pages, and skips the plain-text status lines gospider prints alongside JSON", () => {
    expect(of("url")).toEqual(["http://127.0.0.1:8098/", "http://127.0.0.1:8098/about"]);
    expect(endpoints.every((e) => !e.source.startsWith("[code-"))).toBe(true);
  });
});

describe("parseGospiderOutput edge cases", () => {
  const line = (type: string, output: string, source = "body") => JSON.stringify({ input: "https://example.com/", source, type, output });

  it("keeps only same-host page URLs, since metadataLeak.ts fetches them", () => {
    const out = [line("url", "https://example.com/a"), line("url", "https://other.example.net/b"), line("url", "not a url")].join("\n");
    expect(parseGospiderOutput(out, "https://example.com").map((e) => e.value)).toEqual(["https://example.com/a"]);
  });

  it("ignores linkfinder strings that aren't paths, protocol-relative URLs and non-web schemes", () => {
    const out = [line("linkfinder", "text/html"), line("linkfinder", "//cdn.example.net/x.js"), line("linkfinder", "javascript:void(0)"), line("linkfinder", "/ok")].join("\n");
    expect(parseGospiderOutput(out, "https://example.com").map((e) => e.value)).toEqual(["https://example.com/ok"]);
  });

  it("maps subdomains and forms, treats unknown types as pages, and skips broken or empty lines", () => {
    const out = [line("subdomains", "api.example.com"), line("form", "https://example.com/login"), line("weird", "https://example.com/w"), "{not json", JSON.stringify({ type: "url" }), ""].join("\n");
    expect(parseGospiderOutput(out, "https://example.com")).toEqual([
      { source: "body", type: "subdomain", value: "api.example.com" },
      { source: "body", type: "form", value: "https://example.com/login" },
      { source: "body", type: "url", value: "https://example.com/w" },
    ]);
  });

  it("falls back to input as the source", () => {
    const out = JSON.stringify({ input: "https://example.com/", type: "aws", output: "b.s3.amazonaws.com" });
    expect(parseGospiderOutput(out, "https://example.com")[0].source).toBe("https://example.com/");
    expect(parseGospiderOutput(JSON.stringify({ type: "aws", output: "c.s3.amazonaws.com" }), "https://example.com")[0].source).toBe("");
  });
});

describe("runGospider", () => {
  it("runs a bounded crawl without third-party URL sources", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: REAL, stderr: "" });
    const result = await runGospider(TARGET);
    expect(result.status).toBe("completed");
    const [bin, args] = execFileMock.mock.calls[0] as [string, string[]];
    expect(bin).toBe("gospider");
    expect(args).toEqual(["-s", TARGET, "-c", "5", "-d", "2", "--json", "-t", "1", "--timeout", "10", "--sitemap", "--robots"]);
    expect(args).not.toContain("-a");
  });

  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn gospider ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    expect(await runGospider("https://example.com")).toEqual({ status: "not_configured" });
  });

  it("returns error on non-ENOENT failure", async () => {
    execFileMock.mockRejectedValueOnce(new Error("command failed"));
    const result = await runGospider("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("command failed");
  });
});
