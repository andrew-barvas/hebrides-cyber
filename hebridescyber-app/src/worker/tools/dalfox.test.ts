import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const { execFileMock, readFileMock, unlinkMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  readFileMock: vi.fn(),
  unlinkMock: vi.fn(),
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

import { runDalfox } from "./dalfox";

const reflected = readFileSync(join(__dirname, "fixtures", "dalfox", "reflected.json"), "utf8");
const clean = readFileSync(join(__dirname, "fixtures", "dalfox", "clean.json"), "utf8");
const unreachable = readFileSync(join(__dirname, "fixtures", "dalfox", "unreachable.json"), "utf8");

beforeEach(() => {
  execFileMock.mockReset();
  readFileMock.mockReset();
  unlinkMock.mockReset().mockResolvedValue(undefined);
});

describe("runDalfox", () => {
  it("is not_configured when the binary is missing", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("spawn dalfox ENOENT"), { code: "ENOENT" }));
    expect(await runDalfox("http://127.0.0.1:8099/search?q=hello")).toEqual({ status: "not_configured", findings: [] });
  });

  it("reports the confirmed XSS from the real positive run, and passes -f json -o", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockResolvedValueOnce(reflected);
    const result = await runDalfox("http://127.0.0.1:8099/search?q=hello");
    expect(result).toEqual({
      status: "completed",
      findings: [{ param: "q", severity: "high", payload: "<svg onload=alert(1) class=dlx1bce23b4>", evidence: "DOM verification successful for param q (DOM marker)", cwe: "CWE-79" }],
    });
    const args = execFileMock.mock.calls[0][1] as string[];
    expect(args).toEqual(["scan", "http://127.0.0.1:8099/search?q=hello", "-f", "json", "-o", expect.stringContaining("dalfox-"), "--no-color"]);
  });

  it("is completed with no findings for the real clean run", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockResolvedValueOnce(clean);
    expect(await runDalfox("http://127.0.0.1:8099/api/health")).toEqual({ status: "completed", findings: [] });
  });

  it("is an error, never clean, when dalfox never reached the target", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockResolvedValueOnce(unreachable);
    const result = await runDalfox("http://127.0.0.1:9999/nope?x=1");
    expect(result.status).toBe("error");
  });

  it("is completed with no findings when the output file is missing", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockRejectedValueOnce(new Error("ENOENT"));
    expect(await runDalfox("http://127.0.0.1:8099/")).toEqual({ status: "completed", findings: [] });
  });

  it("is an error on a non-ENOENT failure with no output file, and still cleans up", async () => {
    execFileMock.mockRejectedValueOnce(new Error("process killed"));
    readFileMock.mockRejectedValueOnce(new Error("ENOENT"));
    const result = await runDalfox("http://127.0.0.1:8099/");
    expect(result).toMatchObject({ status: "error" });
    if (result.status === "error") expect(result.note).toContain("process killed");
    expect(unlinkMock).toHaveBeenCalled();
  });

  it("reports the findings even though dalfox exits non-zero when it finds a vulnerability", async () => {
    // Confirmed against the real binary: exit 1 on the positive run, exit 0 when clean.
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("Command failed"), {}));
    readFileMock.mockResolvedValueOnce(reflected);
    const result = await runDalfox("http://127.0.0.1:8099/search?q=hello");
    expect(result.status).toBe("completed");
    if (result.status === "completed") expect(result.findings).toHaveLength(1);
  });

  it("is an error when the output isn't dalfox's JSON shape", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockResolvedValueOnce("not json");
    expect((await runDalfox("http://127.0.0.1:8099/")).status).toBe("error");
  });
});
