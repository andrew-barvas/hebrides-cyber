import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const { execFileMock } = vi.hoisted(() => ({ execFileMock: vi.fn() }));
vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
  default: { execFile: (...args: unknown[]) => execFileMock(...args) },
}));
vi.mock("node:util", () => ({
  promisify: () => execFileMock,
  default: { promisify: () => execFileMock },
}));

import { runCommix } from "./commix";

const clean = readFileSync(join(__dirname, "fixtures", "commix", "clean.stdout.txt"), "utf8");

beforeEach(() => execFileMock.mockReset());

describe("runCommix", () => {
  it("is not_configured when the binary is missing", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("spawn commix ENOENT"), { code: "ENOENT" }));
    expect((await runCommix("https://www.example.com/")).status).toBe("not_configured");
  });

  it("is completed and clean for the real negative run, and runs in batch mode", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: clean, stderr: "" });
    expect(await runCommix("https://www.example.com/?q=a")).toEqual({ status: "completed", vulnerable: false, findings: [], parametersTested: 1 });
    expect(execFileMock.mock.calls[0][1]).toEqual(["--url", "https://www.example.com/?q=a", "--batch"]);
  });

  it("reports an injection", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "The GET parameter 'addr' seems injectable via classic", stderr: "" });
    const r = await runCommix("https://www.example.com/?addr=1");
    expect(r).toMatchObject({ status: "completed", vulnerable: true, findings: [{ parameter: "addr", place: "GET" }], parametersTested: 1 });
  });

  it("keeps an injection found before a timeout", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("timed out"), { stdout: "POST parameter 'h' is vulnerable" }));
    expect(await runCommix("https://www.example.com/")).toMatchObject({ status: "completed", vulnerable: true });
  });

  it("is an error when the run failed with nothing found", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("timed out"), {}));
    expect(await runCommix("https://www.example.com/")).toMatchObject({ status: "error", note: "commix exited: timed out" });
  });

  it("is not_applicable when there is nothing to test", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "[critical] No parameter(s) found for testing", stderr: "" });
    expect((await runCommix("https://www.example.com/")).status).toBe("not_applicable");
  });

  it("is an error when the target was unreachable or the run unfinished", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "[critical] Unable to connect to the target URL", stderr: "" });
    expect((await runCommix("https://www.example.com/")).status).toBe("error");
  });
});
