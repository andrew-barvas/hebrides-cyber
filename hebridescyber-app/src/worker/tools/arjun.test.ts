import { describe, it, expect, vi, beforeEach } from "vitest";

const { execFileMock, readFileMock, rmMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  readFileMock: vi.fn(),
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
  rm: (...args: unknown[]) => rmMock(...args),
  default: {
    readFile: (...args: unknown[]) => readFileMock(...args),
    rm: (...args: unknown[]) => rmMock(...args),
  },
}));

import { runArjun } from "./arjun";

beforeEach(() => {
  execFileMock.mockReset();
  readFileMock.mockReset();
  rmMock.mockReset().mockResolvedValue(undefined);
});

describe("runArjun", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn arjun ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runArjun("https://example.com");
    expect(result).toEqual({ status: "not_configured" });
  });

  it("parses JSON output with discovered parameters", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    // Real arjun -oJ shape: an object keyed by URL (see arjun core/exporter.py).
    readFileMock.mockResolvedValueOnce(
      JSON.stringify({
        "https://example.com/search": { method: "GET", params: ["q", "page", "sort"], headers: {} },
        "https://example.com/api/data": { method: "POST", params: ["debug"], headers: {} },
      })
    );

    const result = await runArjun("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.parameters).toHaveLength(2);
    expect(result.parameters).toContainEqual({
      url: "https://example.com/search",
      method: "GET",
      params: ["q", "page", "sort"],
    });
    expect(result.parameters).toContainEqual({
      url: "https://example.com/api/data",
      method: "POST",
      params: ["debug"],
    });
  });

  it("keeps its 5 threads: no --stable, which makes arjun single-threaded and time out", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockResolvedValueOnce("{}");

    await runArjun("https://example.com");
    const args = execFileMock.mock.calls[0][1] as string[];
    expect(args).not.toContain("--stable");
    expect(args[args.indexOf("-t") + 1]).toBe("5");
  });

  it("returns empty parameters when output file is missing", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockRejectedValueOnce(new Error("ENOENT"));

    const result = await runArjun("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.parameters).toEqual([]);
  });

  it("filters out entries with no params", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    readFileMock.mockResolvedValueOnce(
      JSON.stringify({
        "https://example.com/empty": { method: "GET", params: [], headers: {} },
        "https://example.com/found": { method: "GET", params: ["id"], headers: {} },
      })
    );

    const result = await runArjun("https://example.com");
    if (result.status !== "completed") return;
    expect(result.parameters).toHaveLength(1);
    expect(result.parameters[0].url).toBe("https://example.com/found");
  });

  it("returns error on non-ENOENT failure", async () => {
    execFileMock.mockRejectedValueOnce(new Error("process killed"));
    const result = await runArjun("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("process killed");
  });
});
