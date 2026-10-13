import { describe, it, expect, vi, beforeEach } from "vitest";
// Real output of `zizmor --format json` (v1.30.1) against a small sample
// repository with two workflow files; paths re-homed onto a Linux temp
// directory (see fixtures/zizmor-scan.json's header for the sample YAML).
import fixture from "./fixtures/zizmor-scan.json";

const { execFileMock, mkdtempMock, rmMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
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
  mkdtemp: (...args: unknown[]) => mkdtempMock(...args),
  rm: (...args: unknown[]) => rmMock(...args),
  default: {
    mkdtemp: (...args: unknown[]) => mkdtempMock(...args),
    rm: (...args: unknown[]) => rmMock(...args),
  },
}));
vi.mock("../../lib/githubApp", () => ({ resolveGithubAuth: vi.fn().mockResolvedValue({ token: "", via: "none" }) }));

import {
  buildWorkflowSecurityFindings,
  buildZizmorArgs,
  normaliseIdent,
  parseZizmorOutput,
  runWorkflowSecurity,
  safeFeatureSnippet,
  toRepoRelativePath,
  workflowSecurityCheckId,
  workflowSecuritySeverity,
  WORKFLOW_SECURITY_MAX_FINDINGS,
  type ZizmorFinding,
} from "./workflowSecurity";

const TOKEN = "ghs_exampleTokenValue123";
const ROOT = "/tmp/tmp.7ffC37lB0s/hebridescyber-workflowsec-Xq81zP/repo";
const report = fixture as unknown as ZizmorFinding[];

beforeEach(() => {
  execFileMock.mockReset();
  mkdtempMock.mockReset();
  rmMock.mockReset();
  mkdtempMock.mockResolvedValue("/tmp/tmp.7ffC37lB0s/hebridescyber-workflowsec-Xq81zP");
  rmMock.mockResolvedValue(undefined);
});

describe("buildWorkflowSecurityFindings (captured zizmor output)", () => {
  const { findings, matches, truncated } = buildWorkflowSecurityFindings(report, ROOT);

  it("produces one finding per ident+location (6 real findings, no collisions)", () => {
    expect(report).toHaveLength(6);
    expect(findings).toHaveLength(6);
    expect(matches).toBe(6);
    expect(truncated).toBe(false);
  });

  it("orders the most severe first", () => {
    const ranks = findings.map((f) => ["info", "low", "medium", "high", "critical"].indexOf(f.severity));
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
  });

  it("builds a template-injection finding with path, line, snippet and remediation", () => {
    const f = findings.find((x) => x.checkId?.startsWith("workflow-security.template-injection:"));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high");
    expect(f!.title).toBe("[Workflow security] Script/command injection in .github/workflows/vulnerable.yml:16");
    expect(f!.detail).toContain(".github/workflows/vulnerable.yml` at line 16");
    expect(f!.detail).toContain('echo "Hello ${{ github.event.issue.title }}"');
    expect(f!.remediation).toContain("env:");
    expect(f!.remediation).toContain("https://docs.zizmor.sh/audits/#template-injection");
    expect(f!.metadata).toMatchObject({ ident: "template-injection", file: ".github/workflows/vulnerable.yml", line: 16, confidence: "High" });
  });

  it("maps each ident to a category label (no raw idents in titles)", () => {
    const titles = findings.map((f) => f.title).sort();
    expect(titles).toEqual(
      [
        "[Workflow security] Credential exposure in .github/workflows/safe.yml:13",
        "[Workflow security] Credential exposure in .github/workflows/vulnerable.yml:13",
        "[Workflow security] Insecure workflow trigger in .github/workflows/vulnerable.yml:2",
        "[Workflow security] Script/command injection in .github/workflows/vulnerable.yml:16",
        "[Workflow security] Action/dependency supply-chain integrity in .github/workflows/vulnerable.yml:13",
        "[Workflow security] Action/dependency supply-chain integrity in .github/workflows/vulnerable.yml:14",
      ].sort()
    );
  });

  it("never leaks the temp clone directory into a finding", () => {
    for (const f of findings) {
      expect(JSON.stringify(f)).not.toContain("/tmp/");
      expect(JSON.stringify(f)).not.toContain("hebridescyber-workflowsec-");
    }
  });

  it("uses location-only checkIds with no code in them", () => {
    for (const f of findings) expect(f.checkId).toMatch(/^workflow-security\.[a-z0-9-]+:[0-9a-f]{16}$/);
  });
});

describe("workflowSecurityCheckId", () => {
  it("is stable and changes with any of ident, path or line", () => {
    const a = workflowSecurityCheckId("unpinned-uses", ".github/workflows/ci.yml", 10);
    expect(a).toBe(workflowSecurityCheckId("unpinned-uses", ".github/workflows/ci.yml", 10));
    expect(a).not.toBe(workflowSecurityCheckId("unpinned-uses", ".github/workflows/ci.yml", 11));
    expect(a).not.toBe(workflowSecurityCheckId("unpinned-uses", ".github/workflows/other.yml", 10));
    expect(a).not.toBe(workflowSecurityCheckId("template-injection", ".github/workflows/ci.yml", 10));
  });
});

describe("normaliseIdent", () => {
  it("strips odd characters and falls back for empty input", () => {
    expect(normaliseIdent("unpinned-uses")).toBe("unpinned-uses");
    expect(normaliseIdent("Weird Ident_Name")).toBe("weird-ident-name");
    expect(normaliseIdent(undefined)).toBe("unknown-rule");
  });
});

describe("toRepoRelativePath", () => {
  it("strips the clone root, including Windows separators", () => {
    expect(toRepoRelativePath(`${ROOT}/.github/workflows/ci.yml`, ROOT)).toBe(".github/workflows/ci.yml");
    expect(toRepoRelativePath("C:\\tmp\\x\\repo\\.github\\workflows\\ci.yml", "C:\\tmp\\x\\repo")).toBe(".github/workflows/ci.yml");
  });

  it("strips a temp prefix even if the root doesn't match", () => {
    expect(toRepoRelativePath("/private/tmp/hebridescyber-workflowsec-abc/repo/.github/workflows/ci.yml", "/tmp/other")).toBe(
      ".github/workflows/ci.yml"
    );
  });
});

describe("workflowSecuritySeverity", () => {
  it("maps zizmor's own severity scale case-insensitively", () => {
    expect(workflowSecuritySeverity("High")).toBe("high");
    expect(workflowSecuritySeverity("Medium")).toBe("medium");
    expect(workflowSecuritySeverity("Low")).toBe("low");
    expect(workflowSecuritySeverity("Informational")).toBe("info");
    expect(workflowSecuritySeverity(undefined)).toBe("info");
  });
});

describe("safeFeatureSnippet", () => {
  it("takes the first non-blank line and caps length", () => {
    expect(safeFeatureSnippet("uses: actions/checkout@v4")).toBe("uses: actions/checkout@v4");
    expect(safeFeatureSnippet("on:\n  pull_request_target:")).toBe("on:");
    expect(safeFeatureSnippet("x".repeat(500))!.length).toBe(200);
    expect(safeFeatureSnippet(undefined)).toBeNull();
  });
});

describe("primary-location selection", () => {
  it("picks the Primary-kind location, ignoring Hidden/Related ones", () => {
    const multi: ZizmorFinding[] = [
      {
        ident: "template-injection",
        determinations: { severity: "High", confidence: "High" },
        locations: [
          {
            symbolic: { key: { Local: { verbatim_path: `${ROOT}/.github/workflows/ci.yml` } }, kind: "Hidden" },
            concrete: { location: { start_point: { row: 10, column: 0 }, end_point: { row: 10, column: 5 } }, feature: "wrong line" },
          },
          {
            symbolic: { key: { Local: { verbatim_path: `${ROOT}/.github/workflows/ci.yml` } }, kind: "Primary" },
            concrete: { location: { start_point: { row: 15, column: 0 }, end_point: { row: 15, column: 5 } }, feature: "right line" },
          },
          {
            symbolic: { key: { Local: { verbatim_path: `${ROOT}/.github/workflows/ci.yml` } }, kind: "Related" },
            concrete: { location: { start_point: { row: 20, column: 0 }, end_point: { row: 20, column: 5 } }, feature: "also wrong" },
          },
        ],
      },
    ];
    const { findings } = buildWorkflowSecurityFindings(multi, ROOT);
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain(":16"); // row 15 (0-indexed) + 1
    expect(findings[0].detail).toContain("right line");
  });
});

describe("parseZizmorOutput", () => {
  it("rejects non-JSON and JSON that isn't an array", () => {
    expect(() => parseZizmorOutput("not json")).toThrow();
    expect(() => parseZizmorOutput("{}")).toThrow("not a JSON array");
  });
  it("accepts an empty array (a clean repository)", () => {
    expect(parseZizmorOutput("[]")).toEqual([]);
  });
});

describe("buildZizmorArgs", () => {
  it("always disables exit codes and progress, and requests JSON", () => {
    const args = buildZizmorArgs("/tmp/x/repo", "ghs_token");
    expect(args).toEqual(["--no-exit-codes", "--no-progress", "--format", "json", "--gh-token", "ghs_token", "/tmp/x/repo"]);
  });
  it("omits --gh-token when no token is available", () => {
    const args = buildZizmorArgs("/tmp/x/repo", undefined);
    expect(args).not.toContain("--gh-token");
    expect(args[args.length - 1]).toBe("/tmp/x/repo");
  });
});

describe("caps", () => {
  it(`keeps the ${WORKFLOW_SECURITY_MAX_FINDINGS} most severe and reports truncation`, () => {
    const many: ZizmorFinding[] = Array.from({ length: 80 }, (_, i) => ({
      ident: "unpinned-uses",
      determinations: { severity: i < 10 ? "High" : "Low", confidence: "High" },
      locations: [
        {
          symbolic: { key: { Local: { verbatim_path: `${ROOT}/.github/workflows/w${i}.yml` } }, kind: "Primary" },
          concrete: { location: { start_point: { row: 0, column: 0 }, end_point: { row: 0, column: 5 } }, feature: "uses: x/y@v1" },
        },
      ],
    }));
    const out = buildWorkflowSecurityFindings(many, ROOT);
    expect(out.findings).toHaveLength(WORKFLOW_SECURITY_MAX_FINDINGS);
    expect(out.matches).toBe(80);
    expect(out.truncated).toBe(true);
    expect(out.findings.filter((f) => f.severity === "high")).toHaveLength(10);
  });
});

describe("runWorkflowSecurity", () => {
  const fixtureStdout = JSON.stringify(fixture);

  function mockTools(scan: () => Promise<{ stdout: string; stderr: string }>) {
    execFileMock.mockImplementation(async (cmd: string, args: string[]) => {
      if (cmd === "zizmor" && args[0] === "--version") return { stdout: "zizmor 1.30.1\n", stderr: "" };
      if (cmd === "git") return { stdout: "", stderr: "" };
      if (cmd === "zizmor") return scan();
      throw new Error(`unexpected command ${cmd}`);
    });
  }

  it("returns not_applicable with no repository, without running anything", async () => {
    expect(await runWorkflowSecurity({ githubRepo: null })).toMatchObject({ status: "not_applicable" });
    expect(await runWorkflowSecurity({ githubRepo: "not a repo" })).toMatchObject({ status: "not_applicable" });
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it("returns not_configured when zizmor is missing, before cloning", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("spawn zizmor ENOENT"), { code: "ENOENT" }));
    const result = await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("zizmor is not installed") });
    expect(execFileMock).toHaveBeenCalledTimes(1);
    expect(mkdtempMock).not.toHaveBeenCalled();
  });

  it("returns not_configured with no GitHub token", async () => {
    mockTools(async () => ({ stdout: fixtureStdout, stderr: "" }));
    const result = await runWorkflowSecurity({ githubRepo: "acme/app" });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("No GitHub access") });
  });

  it("clones, scans and returns findings", async () => {
    mockTools(async () => ({ stdout: fixtureStdout, stderr: "" }));
    const result = await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.findings).toHaveLength(6);
    expect(result.note).toBeUndefined();
    expect(rmMock).toHaveBeenCalledWith("/tmp/tmp.7ffC37lB0s/hebridescyber-workflowsec-Xq81zP", { recursive: true, force: true });
    const scanArgs = execFileMock.mock.calls.find((c) => c[0] === "zizmor" && (c[1] as string[]).includes("--format"))![1] as string[];
    expect(scanArgs).toContain("--gh-token");
    expect(scanArgs[scanArgs.length - 1]).toMatch(/hebridescyber-workflowsec-Xq81zP[\\/]repo$/);
  });

  it("reports a clone failure as an error without the token", async () => {
    execFileMock.mockImplementation(async (cmd: string) => {
      if (cmd === "zizmor") return { stdout: "zizmor 1.30.1", stderr: "" };
      throw Object.assign(new Error(`fatal: https://x-access-token:${TOKEN}@github.com/acme/app.git not found`), { code: 128 });
    });
    const result = await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result.status).toBe("error");
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it("reports a failed scan as an error, never an empty completed result", async () => {
    mockTools(async () => {
      throw Object.assign(new Error("Command failed"), { code: 1, stderr: "fatal: no audit was performed" });
    });
    const result = await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("exit 1") });
  });

  it("reports a timeout as an error", async () => {
    mockTools(async () => {
      throw Object.assign(new Error("killed"), { killed: true });
    });
    expect((await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN })).status).toBe("error");
  });

  it("reports unparseable output as an error", async () => {
    mockTools(async () => ({ stdout: "not json", stderr: "" }));
    const result = await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("could not parse") });
  });

  it("completes with no findings for a clean repository", async () => {
    mockTools(async () => ({ stdout: "[]", stderr: "" }));
    const result = await runWorkflowSecurity({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result).toMatchObject({ status: "completed", findings: [], matches: 0 });
  });
});
