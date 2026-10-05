import { describe, it, expect, vi, beforeEach } from "vitest";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

import { runSqlmap } from "./sqlmap";

const fixture = (name: string) => readFileSync(join(__dirname, "fixtures", "sqlmap", name), "utf8");

/** Stands in for sqlmap: lays out its output directory as the real one does, then returns its console text. */
function fakeRun(opts: { stdout: string; hostLog?: string; csv?: string; emptyHostDir?: boolean }) {
  execFileMock.mockImplementationOnce(async (_bin: string, args: string[]) => {
    const dir = args[args.indexOf("--output-dir") + 1];
    if (opts.hostLog !== undefined) {
      mkdirSync(join(dir, "127.0.0.1"));
      writeFileSync(join(dir, "127.0.0.1", "log"), opts.hostLog);
    }
    if (opts.emptyHostDir) {
      mkdirSync(join(dir, "other-host"));
      writeFileSync(join(dir, "notes.txt"), "unrelated");
    }
    if (opts.csv !== undefined) writeFileSync(join(dir, "results-10052026_0652pm.csv"), opts.csv);
    return { stdout: opts.stdout, stderr: "" };
  });
}

function outputDirOf(): string {
  const call = execFileMock.mock.calls[0];
  const args = call[1] as string[];
  return args[args.indexOf("--output-dir") + 1];
}

beforeEach(() => {
  execFileMock.mockReset();
});

describe("runSqlmap", () => {
  it("is not_configured when the binary is missing", async () => {
    const err = new Error("spawn sqlmap ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    expect(await runSqlmap("https://example.com")).toEqual({ status: "not_configured", vulnerable: false, findings: [] });
  });

  it("raises the output buffer and passes the documented flags", async () => {
    fakeRun({ stdout: fixture("clean.stdout.txt") });
    await runSqlmap("https://example.com/");
    const [bin, args, options] = execFileMock.mock.calls[0] as [string, string[], { maxBuffer: number; timeout: number }];
    expect(bin).toBe("sqlmap");
    expect(args).toEqual(expect.arrayContaining(["--url", "https://example.com/", "--batch", "--forms", "--crawl", "2"]));
    expect(options.maxBuffer).toBeGreaterThanOrEqual(32 * 1024 * 1024);
  });

  it("reports the injection point from real output, with the page from the results file", async () => {
    fakeRun({ stdout: fixture("vulnerable.stdout.txt"), hostLog: fixture("vulnerable.host-log.txt"), csv: fixture("vulnerable.results.csv") });
    const result = await runSqlmap("http://127.0.0.1:8099/");
    if (result.status !== "completed") throw new Error(`unexpected ${result.status}`);
    expect(result.vulnerable).toBe(true);
    expect(result.parametersTested).toBe(2);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ parameter: "id", place: "GET", dbms: "SQLite", url: "http://127.0.0.1:8099/item?id=1", type: "SQL Injection" });
    expect(result.findings[0].techniques).toContain("UNION query");
  });

  it("finds the injection point from the host log alone when console output was lost", async () => {
    fakeRun({ stdout: "", hostLog: fixture("vulnerable.host-log.txt") });
    const result = await runSqlmap("http://127.0.0.1:8099/");
    expect(result).toMatchObject({ status: "completed", vulnerable: true });
  });

  it("finds it from the results file alone", async () => {
    fakeRun({ stdout: "", csv: fixture("vulnerable.results.csv") });
    const result = await runSqlmap("http://127.0.0.1:8099/");
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.findings[0]).toMatchObject({ parameter: "id", dbms: null });
  });

  it("ignores a host directory with no log file", async () => {
    fakeRun({ stdout: fixture("clean.stdout.txt"), emptyHostDir: true });
    expect(await runSqlmap("http://127.0.0.1:8098/")).toMatchObject({ status: "completed", vulnerable: false });
  });

  it("is completed and clean only when it finished and tested parameters", async () => {
    fakeRun({ stdout: fixture("clean.stdout.txt"), hostLog: "", csv: fixture("clean.results.csv") });
    expect(await runSqlmap("http://127.0.0.1:8098/")).toEqual({ status: "completed", vulnerable: false, findings: [], parametersTested: 2 });
  });

  it("reports an unreachable target as an error, not a clean result", async () => {
    fakeRun({ stdout: fixture("unreachable.stdout.txt") });
    const result = await runSqlmap("http://127.0.0.1:9/");
    expect(result.status).toBe("error");
    if (result.status === "error") expect(result.note).toContain("unable to connect");
  });

  it("says not_applicable when it finished but had nothing to test", async () => {
    fakeRun({ stdout: "[*] starting @ 10:00:00\n[WARNING] no usable links found (with GET parameters) or forms\n[*] ending @ 10:00:01\n" });
    expect(await runSqlmap("http://127.0.0.1:8098/")).toMatchObject({ status: "not_applicable", vulnerable: false });
  });

  it("keeps findings from a run that timed out, and errors when it found nothing", async () => {
    const timeout = Object.assign(new Error("Command failed: timed out"), { stdout: fixture("vulnerable.stdout.txt") });
    execFileMock.mockRejectedValueOnce(timeout);
    expect(await runSqlmap("http://127.0.0.1:8099/")).toMatchObject({ status: "completed", vulnerable: true });

    execFileMock.mockRejectedValueOnce(Object.assign(new Error("Command failed: timed out"), { stdout: "partial output" }));
    const failed = await runSqlmap("http://127.0.0.1:8099/");
    expect(failed).toMatchObject({ status: "error", note: "sqlmap exited: Command failed: timed out" });

    execFileMock.mockRejectedValueOnce(new Error("killed"));
    expect(await runSqlmap("http://127.0.0.1:8099/")).toMatchObject({ status: "error" });
  });

  it("caps the findings and removes its output directory", async () => {
    const rows = Array.from({ length: 60 }, (_, i) => `http://x.test/p?p${i}=1,GET,p${i},B,`).join("\n");
    fakeRun({ stdout: fixture("vulnerable.stdout.txt"), csv: `Target URL,Place,Parameter,Technique(s),Note(s)\n${rows}\n` });
    const result = await runSqlmap("http://x.test/");
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.findings).toHaveLength(50);
    expect(existsSync(outputDirOf())).toBe(false);
  });
});
