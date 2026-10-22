import { describe, it, expect, vi, beforeEach } from "vitest";
// Real output of `opengrep scan` (1.30.0) with sast-rules/ against a small
// sample repository; paths re-homed onto a Linux temp directory.
import fixture from "./fixtures/opengrep-scan.json";

const { execFileMock, mkdtempMock, rmMock, statMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  mkdtempMock: vi.fn(),
  rmMock: vi.fn(),
  statMock: vi.fn(),
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
  mkdtemp: (...args: unknown[]) => mkdtempMock(...args),
  rm: (...args: unknown[]) => rmMock(...args),
  stat: (...args: unknown[]) => statMock(...args),
  default: {
    mkdtemp: (...args: unknown[]) => mkdtempMock(...args),
    rm: (...args: unknown[]) => rmMock(...args),
    stat: (...args: unknown[]) => statMock(...args),
  },
}));
vi.mock("../../lib/githubApp", () => ({ resolveGithubAuth: vi.fn().mockResolvedValue({ token: "", via: "none" }) }));

import {
  buildOpengrepArgs,
  buildSastFindings,
  fatalOpengrepErrors,
  isExcludedPath,
  normaliseRuleId,
  parseOpengrepOutput,
  runSast,
  safeSnippet,
  sastCheckId,
  sastSeverity,
  toRepoRelativePath,
  SAST_MAX_FINDINGS,
  type OpengrepReport,
} from "./sast";

const TOKEN = "ghs_exampleTokenValue123";
const ROOT = "/tmp/hebridescyber-sast-Xq81zP/repo";
const report = fixture as unknown as OpengrepReport;

beforeEach(() => {
  execFileMock.mockReset();
  mkdtempMock.mockReset();
  rmMock.mockReset();
  statMock.mockReset();
  mkdtempMock.mockResolvedValue("/tmp/hebridescyber-sast-Xq81zP");
  rmMock.mockResolvedValue(undefined);
  statMock.mockResolvedValue({ isDirectory: () => true });
});

describe("buildSastFindings (captured opengrep output)", () => {
  const { findings, matches, truncated } = buildSastFindings(report, ROOT);

  it("produces one finding per rule+location (taint duplicates collapsed)", () => {
    // The fixture has 7 results; js-sql-injection reports the same line twice.
    expect(report.results).toHaveLength(7);
    expect(findings).toHaveLength(6);
    expect(matches).toBe(6);
    expect(truncated).toBe(false);
  });

  it("orders the most severe first", () => {
    const ranks = findings.map((f) => ["info", "low", "medium", "high", "critical"].indexOf(f.severity));
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
    expect(findings[0].severity).toBe("critical");
  });

  it("builds a command-injection finding with path, line, CWE and language-specific remediation", () => {
    const f = findings.find((x) => x.checkId?.startsWith("sast.js-command-injection:"));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("critical");
    expect(f!.title).toBe("[SAST] OS command injection in src/routes/users.js:13");
    expect(f!.detail).toContain("`src/routes/users.js` at line 13 (CWE-78)");
    expect(f!.detail).toContain('exec("ping -c 1 " + req.body.host');
    expect(f!.remediation).toContain("execFile(");
    expect(f!.metadata).toMatchObject({ ruleId: "js-command-injection", file: "src/routes/users.js", line: 13, cwe: ["CWE-78"], confidence: "HIGH" });
  });

  it("maps every rule's CWE to a category label (no raw rule ids in titles)", () => {
    const titles = findings.map((f) => f.title).sort();
    expect(titles).toEqual(
      [
        "[SAST] File inclusion in public/cart.php:3",
        "[SAST] OS command injection in src/routes/users.js:13",
        "[SAST] Open redirect in app/views.py:9",
        "[SAST] SQL injection in src/routes/users.js:8",
        "[SAST] TLS certificate verification disabled in app/views.py:13",
        "[SAST] Unsafe deserialisation in public/cart.php:2",
      ].sort()
    );
  });

  it("never leaks the temp clone directory into a finding", () => {
    for (const f of findings) {
      expect(JSON.stringify(f)).not.toContain("/tmp/");
      expect(JSON.stringify(f)).not.toContain("hebridescyber-sast-");
    }
  });

  it("uses location-only checkIds with no code in them", () => {
    for (const f of findings) expect(f.checkId).toMatch(/^sast\.[a-z0-9-]+:[0-9a-f]{16}$/);
  });
});

describe("sastCheckId", () => {
  it("is stable and changes with any of rule, path or line", () => {
    const a = sastCheckId("js-sql-injection", "src/a.js", 10);
    expect(a).toBe(sastCheckId("js-sql-injection", "src/a.js", 10));
    expect(a).not.toBe(sastCheckId("js-sql-injection", "src/a.js", 11));
    expect(a).not.toBe(sastCheckId("js-sql-injection", "src/b.js", 10));
    expect(a).not.toBe(sastCheckId("js-code-injection", "src/a.js", 10));
  });
});

describe("normaliseRuleId", () => {
  it("strips a path-derived prefix and odd characters", () => {
    expect(normaliseRuleId("sast-rules.javascript.js-sql-injection")).toBe("js-sql-injection");
    expect(normaliseRuleId("Weird Rule_ID")).toBe("weird-rule-id");
    expect(normaliseRuleId(undefined)).toBe("unknown-rule");
  });
});

describe("toRepoRelativePath", () => {
  it("strips the clone root, including Windows separators", () => {
    expect(toRepoRelativePath(`${ROOT}/src/a.js`, ROOT)).toBe("src/a.js");
    expect(toRepoRelativePath("C:\\tmp\\x\\repo\\src\\a.js", "C:\\tmp\\x\\repo")).toBe("src/a.js");
  });

  it("strips a temp prefix even if the root doesn't match", () => {
    expect(toRepoRelativePath("/private/tmp/hebridescyber-sast-abc/repo/app.py", "/tmp/other")).toBe("app.py");
  });
});

describe("excludes", () => {
  it.each(["node_modules/x/index.js", "vendor/lib/a.php", "dist/app.js", "build/a.js", ".next/server/a.js", "tests/test_app.py", "src/__tests__/a.ts", "spec/fixtures/a.js", "public/app.min.js", "src/a.test.ts", "app/test_views.py", "sast-rules/php/rule.php"])(
    "excludes %s",
    (p) => expect(isExcludedPath(p)).toBe(true)
  );

  it.each(["src/routes/users.js", "app/views.py", "public/cart.php", "src/latest.js", "src/contest/app.js"])("keeps %s", (p) =>
    expect(isExcludedPath(p)).toBe(false)
  );

  it("filters excluded paths out of results even if the engine returned them", () => {
    const r: OpengrepReport = {
      results: [
        { check_id: "js-sql-injection", path: `${ROOT}/node_modules/pkg/a.js`, start: { line: 1 }, extra: { severity: "ERROR", metadata: { cwe: ["CWE-89"] } } },
        { check_id: "js-sql-injection", path: `${ROOT}/src/a.js`, start: { line: 2 }, extra: { severity: "ERROR", metadata: { cwe: ["CWE-89"] } } },
      ],
    };
    expect(buildSastFindings(r, ROOT).findings.map((f) => f.title)).toEqual(["[SAST] SQL injection in src/a.js:2"]);
  });

  it("passes every exclude, the size cap and bare rule ids to opengrep", () => {
    const args = buildOpengrepArgs("/app/sast-rules", "/tmp/x/repo");
    expect(args.slice(0, 3)).toEqual(["scan", "--config", "/app/sast-rules"]);
    expect(args).toEqual(expect.arrayContaining(["--json", "--no-rewrite-rule-ids", "--disable-version-check", "--max-target-bytes", "500000"]));
    for (const dir of ["node_modules", "vendor", "dist", "build", ".next", "test", "tests", "__tests__", "fixtures"]) {
      expect(args[args.indexOf(dir) - 1]).toBe("--exclude");
    }
    expect(args).toContain("*.min.js");
    expect(args).not.toContain("--exclude-minified-files"); // rejected by the 1.30.0 CLI
    expect(args[args.length - 1]).toBe("/tmp/x/repo");
  });
});

describe("caps", () => {
  it(`keeps the ${SAST_MAX_FINDINGS} most severe and reports truncation`, () => {
    const results = Array.from({ length: 80 }, (_, i) => ({
      check_id: i < 10 ? "js-code-injection" : "js-open-redirect",
      path: `${ROOT}/src/f${i}.js`,
      start: { line: 1 },
      extra: { severity: i < 10 ? "ERROR" : "WARNING", metadata: { cwe: [i < 10 ? "CWE-95" : "CWE-601"], severity: i < 10 ? "critical" : "medium" } },
    }));
    const out = buildSastFindings({ results }, ROOT);
    expect(out.findings).toHaveLength(SAST_MAX_FINDINGS);
    expect(out.matches).toBe(80);
    expect(out.truncated).toBe(true);
    expect(out.findings.filter((f) => f.severity === "critical")).toHaveLength(10);
  });
});

describe("sastSeverity", () => {
  it("prefers the rule's metadata severity", () => {
    expect(sastSeverity("WARNING", { severity: "critical" })).toBe("critical");
  });
  it("maps engine severities when metadata has none", () => {
    expect(sastSeverity("ERROR", {})).toBe("high");
    expect(sastSeverity("WARNING", undefined)).toBe("medium");
    expect(sastSeverity("INFO", {})).toBe("low");
  });
  it("downgrades low-confidence rules one step", () => {
    expect(sastSeverity("ERROR", { severity: "high", confidence: "LOW" })).toBe("medium");
  });
});

describe("safeSnippet", () => {
  it("masks token-like string literals and caps length", () => {
    expect(safeSnippet('jwt.verify(t, "example_signing_key_value", { algorithms: ["none"] })')).toBe(
      'jwt.verify(t, "***", { algorithms: ["none"] })'
    );
    expect(safeSnippet('db.query("SELECT * FROM users WHERE id = " + id)')).toContain("SELECT * FROM users");
    expect(safeSnippet("x".repeat(500))!.length).toBe(200);
  });
  it("returns null for absent or login-gated lines", () => {
    expect(safeSnippet(undefined)).toBeNull();
    expect(safeSnippet("requires login")).toBeNull();
  });
});

describe("parseOpengrepOutput / fatalOpengrepErrors", () => {
  it("rejects non-JSON and JSON without results", () => {
    expect(() => parseOpengrepOutput("Scanning...")).toThrow();
    expect(() => parseOpengrepOutput("{}")).toThrow("no results array");
  });
  it("treats rule-level errors as fatal and per-file errors as not", () => {
    expect(fatalOpengrepErrors({ results: [], errors: [{ level: "error", message: "Invalid rule schema" }] })).toEqual(["Invalid rule schema"]);
    expect(fatalOpengrepErrors({ results: [], errors: [{ level: "warn", message: "x" }, { level: "error", path: "a.js", message: "Syntax error" }] })).toEqual([]);
  });
});

describe("runSast", () => {
  const fixtureStdout = JSON.stringify(fixture);

  function mockTools(scan: () => Promise<{ stdout: string; stderr: string }>) {
    execFileMock.mockImplementation(async (cmd: string, args: string[]) => {
      if (cmd === "opengrep" && args[0] === "--version") return { stdout: "1.30.0\n", stderr: "" };
      if (cmd === "git") return { stdout: "", stderr: "" };
      if (cmd === "opengrep" && args[0] === "scan") return scan();
      throw new Error(`unexpected command ${cmd}`);
    });
  }

  it("returns not_applicable with no repository, without running anything", async () => {
    expect(await runSast({ githubRepo: null })).toMatchObject({ status: "not_applicable" });
    expect(await runSast({ githubRepo: "not a repo" })).toMatchObject({ status: "not_applicable" });
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it("returns not_configured when opengrep is missing, before cloning", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("spawn opengrep ENOENT"), { code: "ENOENT" }));
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/app/sast-rules" });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("opengrep is not installed") });
    expect(execFileMock).toHaveBeenCalledTimes(1);
    expect(mkdtempMock).not.toHaveBeenCalled();
  });

  it("returns not_configured when the rule pack is missing", async () => {
    statMock.mockRejectedValueOnce(Object.assign(new Error("ENOENT"), { code: "ENOENT" }));
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/nope" });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("rule pack") });
  });

  it("returns not_configured with no GitHub token", async () => {
    mockTools(async () => ({ stdout: fixtureStdout, stderr: "" }));
    const result = await runSast({ githubRepo: "acme/app", rulesDir: "/app/sast-rules" });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("No GitHub access") });
  });

  it("clones, scans and returns findings", async () => {
    mockTools(async () => ({ stdout: fixtureStdout, stderr: "" }));
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/app/sast-rules" });
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.findings).toHaveLength(6);
    expect(result.filesScanned).toBe(3);
    expect(result.note).toBeUndefined();
    expect(rmMock).toHaveBeenCalledWith("/tmp/hebridescyber-sast-Xq81zP", { recursive: true, force: true });
    const scanArgs = execFileMock.mock.calls.find((c) => c[0] === "opengrep" && (c[1] as string[])[0] === "scan")![1] as string[];
    expect(scanArgs[scanArgs.length - 1]).toMatch(/hebridescyber-sast-Xq81zP[\\/]repo$/);
  });

  it("reports a clone failure as an error without the token", async () => {
    execFileMock.mockImplementation(async (cmd: string) => {
      if (cmd === "opengrep") return { stdout: "1.30.0", stderr: "" };
      throw Object.assign(new Error(`fatal: https://x-access-token:${TOKEN}@github.com/acme/app.git not found`), { code: 128 });
    });
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/app/sast-rules" });
    expect(result.status).toBe("error");
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it("reports a failed scan as an error, never an empty completed result", async () => {
    mockTools(async () => {
      throw Object.assign(new Error("Command failed"), { code: 2, stderr: "Error: invalid configuration" });
    });
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/app/sast-rules" });
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("exit 2") });
  });

  it("reports a timeout as an error", async () => {
    mockTools(async () => {
      throw Object.assign(new Error("killed"), { killed: true });
    });
    expect((await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/r" })).status).toBe("error");
  });

  it("reports unparseable output as an error", async () => {
    mockTools(async () => ({ stdout: "not json", stderr: "" }));
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/r" });
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("could not parse") });
  });

  it("reports rule/config errors as an error even with exit 0", async () => {
    mockTools(async () => ({ stdout: JSON.stringify({ results: [], errors: [{ level: "error", message: "Invalid rule" }] }), stderr: "" }));
    expect((await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/r" })).status).toBe("error");
  });

  it("notes per-file errors and an empty repository without failing", async () => {
    mockTools(async () => ({
      stdout: JSON.stringify({ results: [], errors: [{ level: "warn", path: "a.js", message: "Syntax error" }], paths: { scanned: [] } }),
      stderr: "",
    }));
    const result = await runSast({ githubRepo: "acme/app", githubToken: TOKEN, rulesDir: "/r" });
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.note).toContain("1 file(s) could not be fully analysed");
    expect(result.note).toContain("No JavaScript/TypeScript, Python or PHP files");
  });
});
