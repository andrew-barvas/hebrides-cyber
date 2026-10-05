// Shared shallow clone of a customer's connected GitHub repository, for the
// repo-backed checks that need the current tree on disk (trivyScan.ts's
// config mode, src/worker/tools/sast.ts). One implementation of the three
// things that are easy to get subtly wrong:
//
//   1. The GitHub token is embedded in the clone URL, so it lands in git's
//      error text. Every string that leaves here goes through
//      sanitiseGitOutput() — never log or return a raw git error.
//   2. git must never prompt or reach for an ambient credential helper: a
//      private repo we lack access to has to fail fast, not hang until the
//      timeout. Hence `-c credential.helper=` and GIT_TERMINAL_PROMPT=0.
//   3. The temp directory (which holds the token in .git/config) is removed
//      on every path, including a throw inside the caller's callback.
//
// Hardening for scanning untrusted repositories: symlinks are checked out as
// plain files (core.symlinks=false) so a link to /etc or the runner's home
// can't pull files from outside the clone into a scan; submodules are not
// fetched; Git LFS objects are not downloaded.
//
// secretScan.ts keeps its own full-history clone (it needs every commit,
// this helper deliberately takes only the latest one) but shares the
// sanitiser.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const execFileAsync = promisify(execFile);

export const DEFAULT_CLONE_TIMEOUT_MS = 60_000;

const GITHUB_REPO_PATTERN = /^[\w.-]+\/[\w.-]+$/;

/** `owner/repo`, with nothing that could escape a URL path or a directory name. */
export function isValidGithubRepo(githubRepo: string | null | undefined): githubRepo is string {
  return typeof githubRepo === "string" && GITHUB_REPO_PATTERN.test(githubRepo) && !githubRepo.includes("..");
}

/**
 * Removes the token, and any URL userinfo that survived, from text that might
 * be stored or shown (git error messages echo the clone URL).
 */
export function sanitiseGitOutput(text: string, token: string): string {
  let out = text;
  if (token) out = out.split(token).join("***");
  return out.replace(/https:\/\/[^@\s/]+:[^@\s/]+@/g, "https://***@");
}

/** Environment for a non-interactive git that never asks for credentials. */
export function nonInteractiveGitEnv(): NodeJS.ProcessEnv {
  return { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GCM_INTERACTIVE: "never", GIT_LFS_SKIP_SMUDGE: "1" };
}

export type CloneFailure =
  | { reason: "invalid_repo"; note: string }
  | { reason: "git_missing"; note: string }
  | { reason: "tempdir"; note: string }
  | { reason: "timeout"; note: string }
  | { reason: "failed"; note: string };

export type WithCloneResult<T> = { ok: true; value: T } | { ok: false; failure: CloneFailure };

export type ShallowCloneOptions = {
  /** mkdtemp prefix, e.g. "hebridescyber-sast-". */
  tempPrefix: string;
  timeoutMs?: number;
};

type ExecFailure = { code?: string | number; killed?: boolean; signal?: string | null; message?: string };

/**
 * Clones `githubRepo` at depth 1 into a fresh temp directory, runs `fn` with
 * the clone's path, and removes the directory afterwards whatever happens.
 * Clone failures come back as `{ ok: false }` with a token-free note; an
 * exception thrown by `fn` itself propagates (after cleanup).
 */
export async function withShallowClone<T>(
  githubRepo: string,
  token: string,
  options: ShallowCloneOptions,
  fn: (cloneDir: string) => Promise<T>
): Promise<WithCloneResult<T>> {
  if (!isValidGithubRepo(githubRepo)) {
    return { ok: false, failure: { reason: "invalid_repo", note: "githubRepo must look like 'owner/repo'." } };
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_CLONE_TIMEOUT_MS;

  let workDir: string;
  try {
    workDir = await mkdtemp(join(tmpdir(), options.tempPrefix));
  } catch (err) {
    return { ok: false, failure: { reason: "tempdir", note: `could not create temp directory: ${(err as Error).message}` } };
  }

  const cloneDir = join(workDir, "repo");
  try {
    try {
      await execFileAsync(
        "git",
        [
          "-c", "credential.helper=",
          "-c", "core.symlinks=false",
          "clone",
          "--quiet",
          "--depth", "1",
          "--single-branch",
          "--no-recurse-submodules",
          `https://x-access-token:${token}@github.com/${githubRepo}.git`,
          cloneDir,
        ],
        { timeout: timeoutMs, maxBuffer: 1024 * 1024, env: nonInteractiveGitEnv() }
      );
    } catch (err) {
      const failure = err as ExecFailure;
      if (failure.code === "ENOENT") {
        return { ok: false, failure: { reason: "git_missing", note: "git is not installed in this environment." } };
      }
      if (failure.killed) {
        return { ok: false, failure: { reason: "timeout", note: `clone of ${githubRepo} exceeded ${Math.round(timeoutMs / 1000)}s` } };
      }
      return {
        ok: false,
        failure: { reason: "failed", note: sanitiseGitOutput(`could not clone ${githubRepo}: ${failure.message ?? "unknown git error"}`, token) },
      };
    }
    return { ok: true, value: await fn(cloneDir) };
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
  }
}
