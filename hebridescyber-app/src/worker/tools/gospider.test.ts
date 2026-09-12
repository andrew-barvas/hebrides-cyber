import { describe, it, expect, vi, beforeEach } from "vitest";

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

import { runGospider } from "./gospider";

beforeEach(() => {
  execFileMock.mockReset();
});

describe("runGospider", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn gospider ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runGospider("https://example.com");
    expect(result).toEqual({ status: "not_configured" });
  });

  it("parses JSON output lines", async () => {
    const lines = [
      JSON.stringify({ input: "https://example.com", source: "https://example.com", type: "url", output: "https://example.com/about" }),
      JSON.stringify({ source: "https://example.com/app.js", type: "javascript", output: "https://example.com/api/users" }),
      JSON.stringify({ source: "https://example.com", type: "aws-s3", output: "https://mybucket.s3.amazonaws.com" }),
    ].join("\n");

    execFileMock.mockResolvedValueOnce({ stdout: lines, stderr: "" });
    const result = await runGospider("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.endpoints).toContainEqual({ source: "https://example.com", type: "url", value: "https://example.com/about" });
    expect(result.endpoints).toContainEqual({ source: "https://example.com/app.js", type: "js-endpoint", value: "https://example.com/api/users" });
    expect(result.endpoints).toContainEqual({ source: "https://example.com", type: "aws-s3", value: "https://mybucket.s3.amazonaws.com" });
  });

  it("falls back to plain text format", async () => {
    const stdout = "[linkfinder] - https://example.com/app.js - /api/secret\n[form] - https://example.com - https://example.com/login\n";
    execFileMock.mockResolvedValueOnce({ stdout, stderr: "" });
    const result = await runGospider("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.endpoints).toContainEqual({ source: "https://example.com/app.js", type: "js-endpoint", value: "/api/secret" });
    expect(result.endpoints).toContainEqual({ source: "https://example.com", type: "form", value: "https://example.com/login" });
  });

  it("deduplicates endpoints by value", async () => {
    const lines = [
      JSON.stringify({ source: "a", type: "url", output: "https://example.com/dup" }),
      JSON.stringify({ source: "b", type: "url", output: "https://example.com/dup" }),
    ].join("\n");
    execFileMock.mockResolvedValueOnce({ stdout: lines, stderr: "" });
    const result = await runGospider("https://example.com");
    if (result.status !== "completed") return;
    expect(result.endpoints.filter((e) => e.value === "https://example.com/dup")).toHaveLength(1);
  });

  it("returns error on non-ENOENT failure", async () => {
    execFileMock.mockRejectedValueOnce(new Error("command failed"));
    const result = await runGospider("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("command failed");
  });
});
