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

import { runKiterunner } from "./kiterunner";

beforeEach(() => {
  execFileMock.mockReset();
});

describe("runKiterunner", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn kr ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runKiterunner("https://example.com");
    expect(result).toEqual({ status: "not_configured" });
  });

  it("parses endpoint output", async () => {
    const stdout = [
      "GET     200  1234  /api/v1/users",
      "POST    201  567   /api/v1/orders",
      "# comment line",
      "",
      "DELETE  204  0     /api/v1/sessions",
    ].join("\n");

    execFileMock.mockResolvedValueOnce({ stdout, stderr: "" });
    const result = await runKiterunner("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.endpoints).toHaveLength(3);
    expect(result.endpoints[0]).toEqual({
      method: "GET",
      path: "/api/v1/users",
      statusCode: 200,
      contentLength: 1234,
    });
  });

  it("deduplicates endpoints by method+path", async () => {
    const stdout = "GET     200  100  /api/test\nGET     200  200  /api/test\n";
    execFileMock.mockResolvedValueOnce({ stdout, stderr: "" });
    const result = await runKiterunner("https://example.com");
    if (result.status !== "completed") return;
    expect(result.endpoints).toHaveLength(1);
  });

  it("returns error on non-ENOENT failure", async () => {
    execFileMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runKiterunner("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("timeout");
  });
});
