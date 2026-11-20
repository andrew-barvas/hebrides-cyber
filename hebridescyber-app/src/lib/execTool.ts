// Runs a scanner CLI the way every wrapper in src/worker/tools and
// src/lib/scanners does (promisified execFile), but with the child's stdin
// closed.
//
// Node gives the child an open pipe for stdin and never closes it. Tools that
// read extra targets from a piped stdin (nuclei, gospider) then wait for input
// forever: run like that, nuclei 3.3.9 printed nothing and was killed at its
// timeout, while with stdin closed the same run finished in under a second
// (checked 2026-10-06). So every scheduled scan's nuclei step timed out
// without results. Closing stdin also turns any interactive prompt into an
// immediate end-of-input instead of a hang.
//
// Inside a halted scan (src/lib/toolHalt.ts) it also registers the child so a
// stop can kill it, and refuses to start anything once the scan is halted.
import { execFile, type ChildProcess, type ExecFileOptions } from "node:child_process";
import { promisify } from "node:util";
import { ToolHaltedError, currentHalt } from "./toolHalt";

const execFileAsync = promisify(execFile);

export function execTool(file: string, args: readonly string[], options: ExecFileOptions = {}): Promise<{ stdout: string; stderr: string }> {
  const halt = currentHalt();
  if (halt?.halted) return Promise.reject(new ToolHaltedError(halt.reason ?? "stopped"));
  const pending = execFileAsync(file, args, options) as Promise<{ stdout: string; stderr: string }> & { child?: ChildProcess };
  pending?.child?.stdin?.end();
  if (halt && pending?.child) halt.register(pending.child);
  return pending;
}
