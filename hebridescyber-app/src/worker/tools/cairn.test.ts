import { describe, it, expect, vi, beforeEach } from "vitest";

const { execFileMock, readFileMock, writeFileMock, unlinkMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  readFileMock: vi.fn(),
  writeFileMock: vi.fn().mockResolvedValue(undefined),
  unlinkMock: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
  default: { execFile: (...args: unknown[]) => execFileMock(...args) },
}));
vi.mock("node:util", () => ({
  promisify: () => execFileMock,
  default: { promisify: () => execFileMock },
}));
vi.mock("node:fs/promises", () => ({
  readFile: (...args: unknown[]) => readFileMock(...args),
  writeFile: (...args: unknown[]) => writeFileMock(...args),
  unlink: (...args: unknown[]) => unlinkMock(...args),
  default: {
    readFile: (...args: unknown[]) => readFileMock(...args),
    writeFile: (...args: unknown[]) => writeFileMock(...args),
    unlink: (...args: unknown[]) => unlinkMock(...args),
  },
}));

import { runCairn } from "./cairn";

beforeEach(() => {
  execFileMock.mockReset();
  readFileMock.mockReset();
  writeFileMock.mockReset().mockResolvedValue(undefined);
  unlinkMock.mockReset().mockResolvedValue(undefined);
});

describe("runCairn", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn cairn ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runCairn("https://example.com");
    expect(result).toEqual({ status: "not_configured", findings: [] });
  });

  it("returns completed with parsed findings from JSON array", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockResolvedValueOnce(
      JSON.stringify([
        {
          vulnerability_type: "sqli",
          severity: "critical",
          title: "SQL Injection via search",
          description: "The search endpoint is vulnerable to SQL injection.",
          evidence: "Error: You have an error in your SQL syntax",
          endpoint: "/api/search?q=test",
          cve_ids: ["CVE-2024-1234"],
          exploit_chain: ["Sent payload ' OR 1=1 --", "Database returned all rows"],
        },
      ])
    );

    const result = await runCairn("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toEqual({
      severity: "critical",
      title: "SQL Injection via search",
      detail: "The search endpoint is vulnerable to SQL injection.",
      vulnClass: "sqli",
      evidence: "Error: You have an error in your SQL syntax",
      endpoint: "/api/search?q=test",
      cveIds: ["CVE-2024-1234"],
      exploitSteps: ["Sent payload ' OR 1=1 --", "Database returned all rows"],
    });
  });

  it("returns completed with empty findings when no output file", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockRejectedValueOnce(new Error("ENOENT"));

    const result = await runCairn("https://example.com");
    expect(result).toEqual({ status: "completed", findings: [] });
  });

  it("handles JSONL format", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockResolvedValueOnce(
      "not valid json as first line\n" +
      JSON.stringify({ vulnerability_type: "rce", severity: "critical", title: "RCE found" }) + "\n"
    );

    const result = await runCairn("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].vulnClass).toBe("rce");
  });

  it("handles nested findings property", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockResolvedValueOnce(
      JSON.stringify({
        findings: [
          { vulnerability_type: "xss", severity: "high", title: "Stored XSS" },
        ],
      })
    );

    const result = await runCairn("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].vulnClass).toBe("xss");
  });

  it("writes input file before running cairn", async () => {
    const err = new Error("spawn cairn ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    await runCairn("https://example.com");
    expect(writeFileMock).toHaveBeenCalled();
    const writtenData = JSON.parse(writeFileMock.mock.calls[0][1] as string);
    expect(writtenData.target).toBe("https://example.com");
    expect(writtenData.mode).toBe("scan");
  });

  it("returns error for non-ENOENT failures", async () => {
    execFileMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runCairn("https://example.com");
    expect(result.status).toBe("error");
    expect((result as { note: string }).note).toContain("timeout");
  });

  it("cleans up both input and output files", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockRejectedValueOnce(new Error("ENOENT"));
    await runCairn("https://example.com");
    expect(unlinkMock).toHaveBeenCalledTimes(2);
  });
});
