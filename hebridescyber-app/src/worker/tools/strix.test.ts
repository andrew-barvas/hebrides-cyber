import { describe, it, expect, vi, beforeEach } from "vitest";

const { execFileMock, readFileMock, unlinkMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  readFileMock: vi.fn(),
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
  unlink: (...args: unknown[]) => unlinkMock(...args),
  default: {
    readFile: (...args: unknown[]) => readFileMock(...args),
    unlink: (...args: unknown[]) => unlinkMock(...args),
  },
}));

import { runStrix } from "./strix";

beforeEach(() => {
  execFileMock.mockReset();
  readFileMock.mockReset();
  unlinkMock.mockReset().mockResolvedValue(undefined);
});

describe("runStrix", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn strix ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runStrix("https://example.com");
    expect(result).toEqual({ status: "not_configured", findings: [] });
  });

  it("returns completed with parsed findings", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockResolvedValueOnce(
      JSON.stringify({
        vulnerability_class: "sqli",
        severity: "critical",
        title: "SQL Injection in login form",
        description: "The login form is vulnerable to SQL injection via the username parameter.",
        exploit_proof: "' OR 1=1 --",
        remediation: "Use parameterised queries.",
      }) + "\n"
    );

    const result = await runStrix("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toEqual({
      severity: "critical",
      title: "SQL Injection in login form",
      detail: "The login form is vulnerable to SQL injection via the username parameter.",
      vulnClass: "sqli",
      exploit: "' OR 1=1 --",
      agentRemediation: "Use parameterised queries.",
    });
  });

  it("returns completed with empty findings when no output file", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockRejectedValueOnce(new Error("ENOENT"));

    const result = await runStrix("https://example.com");
    expect(result).toEqual({ status: "completed", findings: [] });
  });

  it("handles multiple findings in JSONL format", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    const lines = [
      JSON.stringify({ vulnerability_class: "xss", severity: "high", title: "Reflected XSS" }),
      JSON.stringify({ vulnerability_class: "ssrf", severity: "critical", title: "SSRF via redirect" }),
    ].join("\n");
    readFileMock.mockResolvedValueOnce(lines);

    const result = await runStrix("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].vulnClass).toBe("xss");
    expect(result.findings[1].vulnClass).toBe("ssrf");
  });

  it("skips malformed JSON lines", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "" });
    readFileMock.mockResolvedValueOnce(
      "not valid json\n" +
      JSON.stringify({ vulnerability_class: "rce", severity: "critical", title: "RCE found" }) + "\n"
    );

    const result = await runStrix("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].vulnClass).toBe("rce");
  });

  it("returns error for non-ENOENT failures", async () => {
    execFileMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runStrix("https://example.com");
    expect(result.status).toBe("error");
    expect((result as { note: string }).note).toContain("timeout");
  });
});
