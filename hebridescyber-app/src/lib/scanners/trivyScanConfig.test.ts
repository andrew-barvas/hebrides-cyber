// scanTrivyConfig() end to end with git/trivy mocked — checks it still works
// on top of the shared src/lib/repoClone.ts helper.
import { describe, it, expect, vi, beforeEach } from "vitest";

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
  default: { mkdtemp: (...args: unknown[]) => mkdtempMock(...args), rm: (...args: unknown[]) => rmMock(...args) },
}));
vi.mock("../githubApp", () => ({ resolveGithubAuth: vi.fn().mockResolvedValue({ token: "", via: "none" }) }));

import { scanTrivyConfig } from "./trivyScan";

const TOKEN = "ghs_exampleTokenValue123";

beforeEach(() => {
  execFileMock.mockReset();
  mkdtempMock.mockReset();
  rmMock.mockReset();
  mkdtempMock.mockResolvedValue("/tmp/hebridescyber-trivy-abc");
  rmMock.mockResolvedValue(undefined);
});

describe("scanTrivyConfig", () => {
  it("returns not_applicable without a repo", async () => {
    expect((await scanTrivyConfig({ githubRepo: null })).status).toBe("not_applicable");
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it("returns not_configured without any GitHub token", async () => {
    expect((await scanTrivyConfig({ githubRepo: "acme/app" })).status).toBe("not_configured");
  });

  it("clones shallowly, runs trivy config on the clone and builds findings", async () => {
    execFileMock.mockImplementation(async (cmd: string) => {
      if (cmd === "git") return { stdout: "", stderr: "" };
      return {
        stdout: JSON.stringify({
          Results: [{ Target: "main.tf", Misconfigurations: [{ ID: "AVD-AWS-0107", Severity: "HIGH", Title: "Open ingress" }] }],
        }),
        stderr: "",
      };
    });

    const result = await scanTrivyConfig({ githubRepo: "acme/app", githubToken: TOKEN });

    expect(result.status).toBe("completed");
    expect(result.findings[0].checkId).toBe("trivy-config.misconfiguration:AVD-AWS-0107:main.tf");
    const gitArgs = execFileMock.mock.calls[0][1] as string[];
    expect(gitArgs).toEqual(expect.arrayContaining(["--depth", "1"]));
    const trivyCall = execFileMock.mock.calls[1] as [string, string[]];
    expect(trivyCall[0]).toBe("trivy");
    expect(trivyCall[1][0]).toBe("config");
    expect(trivyCall[1][1]).toMatch(/hebridescyber-trivy-abc[\\/]repo$/);
    expect(rmMock).toHaveBeenCalledWith("/tmp/hebridescyber-trivy-abc", { recursive: true, force: true });
  });

  it("reports not_configured when trivy is missing", async () => {
    execFileMock.mockImplementation(async (cmd: string) => {
      if (cmd === "git") return { stdout: "", stderr: "" };
      throw Object.assign(new Error("spawn trivy ENOENT"), { code: "ENOENT" });
    });
    const result = await scanTrivyConfig({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("trivy is not installed") });
  });

  it("reports not_configured when git is missing", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("spawn git ENOENT"), { code: "ENOENT" }));
    const result = await scanTrivyConfig({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result).toMatchObject({ status: "not_configured", note: expect.stringContaining("git is not installed") });
  });

  it("reports a clone failure as an error without the token", async () => {
    execFileMock.mockRejectedValueOnce(
      Object.assign(new Error(`git clone https://x-access-token:${TOKEN}@github.com/acme/app.git failed`), { code: 128 })
    );
    const result = await scanTrivyConfig({ githubRepo: "acme/app", githubToken: TOKEN });
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).not.toContain(TOKEN);
  });
});
