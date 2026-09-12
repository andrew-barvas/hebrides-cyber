import { describe, it, expect, vi, beforeEach } from "vitest";

const { execFileMock, readFileMock, mkdtempMock, rmMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  readFileMock: vi.fn(),
  mkdtempMock: vi.fn(),
  rmMock: vi.fn(),
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
  mkdtemp: (...args: unknown[]) => mkdtempMock(...args),
  rm: (...args: unknown[]) => rmMock(...args),
  default: {
    readFile: (...args: unknown[]) => readFileMock(...args),
    mkdtemp: (...args: unknown[]) => mkdtempMock(...args),
    rm: (...args: unknown[]) => rmMock(...args),
  },
}));

import { runPhoton } from "./photon";

beforeEach(() => {
  execFileMock.mockReset();
  readFileMock.mockReset();
  mkdtempMock.mockReset().mockResolvedValue("/tmp/photon-abc123");
  rmMock.mockReset().mockResolvedValue(undefined);
});

describe("runPhoton", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn photon ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runPhoton("https://example.com");
    expect(result).toEqual({ status: "not_configured" });
  });

  it("parses output files into assets", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockImplementation(async (path: string) => {
      if (path.endsWith("internal.txt")) return "https://example.com/page1\nhttps://example.com/page2\n";
      if (path.endsWith("external.txt")) return "https://cdn.example.com/lib.js\n";
      if (path.endsWith("scripts.txt")) return "https://example.com/api/v1\n";
      if (path.endsWith("emails.txt")) return "admin@example.com\n";
      if (path.endsWith("fuzzable.txt")) return "";
      throw new Error("file not found");
    });

    const result = await runPhoton("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.assets).toContainEqual({ type: "url", value: "https://example.com/page1" });
    expect(result.assets).toContainEqual({ type: "url", value: "https://cdn.example.com/lib.js" });
    expect(result.assets).toContainEqual({ type: "js-endpoint", value: "https://example.com/api/v1" });
    expect(result.assets).toContainEqual({ type: "email", value: "admin@example.com" });
  });

  it("handles missing output files gracefully", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockRejectedValue(new Error("ENOENT"));

    const result = await runPhoton("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.assets).toEqual([]);
  });

  it("returns error on non-ENOENT failure", async () => {
    execFileMock.mockRejectedValueOnce(new Error("timeout exceeded"));
    const result = await runPhoton("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("timeout exceeded");
  });

  it("cleans up temp directory after completion", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockRejectedValue(new Error("ENOENT"));
    await runPhoton("https://example.com");
    expect(rmMock).toHaveBeenCalledWith("/tmp/photon-abc123", { recursive: true, force: true });
  });
});
