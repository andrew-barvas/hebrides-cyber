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

import { isValidGithubRepo, nonInteractiveGitEnv, sanitiseGitOutput, withShallowClone } from "./repoClone";

const TOKEN = "ghs_exampleTokenValue123";

beforeEach(() => {
  execFileMock.mockReset();
  mkdtempMock.mockReset();
  rmMock.mockReset();
  mkdtempMock.mockResolvedValue("/tmp/hebridescyber-test-abc");
  rmMock.mockResolvedValue(undefined);
});

describe("sanitiseGitOutput", () => {
  it("removes the token and any URL userinfo", () => {
    const text = `fatal: unable to access 'https://x-access-token:${TOKEN}@github.com/acme/app.git/': 403`;
    const out = sanitiseGitOutput(text, TOKEN);
    expect(out).not.toContain(TOKEN);
    expect(out).toContain("https://***@github.com/acme/app.git");
  });

  it("strips userinfo even when the token is empty", () => {
    expect(sanitiseGitOutput("https://user:pass@github.com/x", "")).toBe("https://***@github.com/x");
  });
});

describe("isValidGithubRepo", () => {
  it.each(["acme/app", "a-b.c/d_e"])("accepts %s", (repo) => expect(isValidGithubRepo(repo)).toBe(true));
  it.each(["", "acme", "acme/app/extra", "../etc", "acme/..", "acme/app;rm -rf", null, undefined])("rejects %s", (repo) =>
    expect(isValidGithubRepo(repo)).toBe(false)
  );
});

describe("nonInteractiveGitEnv", () => {
  it("disables prompts and LFS downloads", () => {
    const env = nonInteractiveGitEnv();
    expect(env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(env.GIT_LFS_SKIP_SMUDGE).toBe("1");
  });
});

describe("withShallowClone", () => {
  it("clones at depth 1 without a credential helper or symlinks, runs the callback, then cleans up", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    const fn = vi.fn().mockResolvedValue("scanned");

    const result = await withShallowClone("acme/app", TOKEN, { tempPrefix: "hebridescyber-test-" }, fn);

    expect(result).toEqual({ ok: true, value: "scanned" });
    const [cmd, args, opts] = execFileMock.mock.calls[0] as [string, string[], { timeout: number; env: NodeJS.ProcessEnv }];
    expect(cmd).toBe("git");
    expect(args).toEqual(expect.arrayContaining(["credential.helper=", "core.symlinks=false", "--depth", "1", "--no-recurse-submodules"]));
    expect(args).toContain(`https://x-access-token:${TOKEN}@github.com/acme/app.git`);
    expect(opts.timeout).toBe(60_000);
    expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(fn).toHaveBeenCalledWith(expect.stringMatching(/hebridescyber-test-abc[\\/]repo$/));
    expect(rmMock).toHaveBeenCalledWith("/tmp/hebridescyber-test-abc", { recursive: true, force: true });
  });

  it("reports git_missing on ENOENT and still cleans up", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("spawn git ENOENT"), { code: "ENOENT" }));
    const fn = vi.fn();
    const result = await withShallowClone("acme/app", TOKEN, { tempPrefix: "p-" }, fn);
    expect(result).toEqual({ ok: false, failure: { reason: "git_missing", note: "git is not installed in this environment." } });
    expect(fn).not.toHaveBeenCalled();
    expect(rmMock).toHaveBeenCalled();
  });

  it("reports a timeout when git is killed", async () => {
    execFileMock.mockRejectedValueOnce(Object.assign(new Error("killed"), { killed: true }));
    const result = await withShallowClone("acme/app", TOKEN, { tempPrefix: "p-", timeoutMs: 5000 }, vi.fn());
    expect(result).toMatchObject({ ok: false, failure: { reason: "timeout", note: "clone of acme/app exceeded 5s" } });
  });

  it("never returns the token in a clone failure note", async () => {
    execFileMock.mockRejectedValueOnce(
      Object.assign(new Error(`Command failed: git clone https://x-access-token:${TOKEN}@github.com/acme/app.git: Repository not found`), { code: 128 })
    );
    const result = await withShallowClone("acme/app", TOKEN, { tempPrefix: "p-" }, vi.fn());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.reason).toBe("failed");
    expect(result.failure.note).not.toContain(TOKEN);
    expect(result.failure.note).toContain("Repository not found");
  });

  it("reports a temp-directory failure without trying to clone", async () => {
    mkdtempMock.mockRejectedValueOnce(new Error("EACCES"));
    const result = await withShallowClone("acme/app", TOKEN, { tempPrefix: "p-" }, vi.fn());
    expect(result).toMatchObject({ ok: false, failure: { reason: "tempdir" } });
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it("rejects an invalid repo name before touching the disk", async () => {
    const result = await withShallowClone("acme/../../etc", TOKEN, { tempPrefix: "p-" }, vi.fn());
    expect(result).toMatchObject({ ok: false, failure: { reason: "invalid_repo" } });
    expect(mkdtempMock).not.toHaveBeenCalled();
  });

  it("cleans up when the callback throws, and lets the error propagate", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    await expect(
      withShallowClone("acme/app", TOKEN, { tempPrefix: "p-" }, async () => {
        throw new Error("scanner crashed");
      })
    ).rejects.toThrow("scanner crashed");
    expect(rmMock).toHaveBeenCalled();
  });
});
