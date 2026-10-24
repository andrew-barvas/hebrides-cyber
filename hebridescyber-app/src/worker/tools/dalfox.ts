// Dalfox integration — dedicated XSS depth scanning.
//
// Uses the dalfox binary (Apache 2.0, https://github.com/hahwul/dalfox),
// pinned and SHA-256-verified in scheduled-scans.yml and tool-integration.yml.
// Returns { status: "not_configured" } when the binary is absent, so the
// worker continues gracefully instead of failing the whole scan job.
//
// Output reading lives in dalfoxOutput.ts, written against JSON captured
// from a real Dalfox v3.2.4 run (fixtures/dalfox/). `-f json -o <file>` is
// how Dalfox itself recommends machine-readable output (`dalfox scan -h`);
// stdout is log lines, not the report.
//
// Dalfox exits 1 when it finds a vulnerability (confirmed against the real
// binary: exit 0 on a clean run, exit 1 on the positive run) — the same
// "evidence found" signal commix.ts already treats this way, not a failure.
// The output file is still written either way, so it is always read and
// parsed first; only a run that leaves no readable, well-formed output
// becomes `error`.

import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { execTool } from "../../lib/execTool";
import { parseDalfoxOutput, type DalfoxFinding } from "./dalfoxOutput";

const execFileAsync = execTool;

const DALFOX_TIMEOUT_MS = 120_000;

export type DalfoxResult =
  | { status: "completed"; findings: DalfoxFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "error"; findings: []; note: string };

export async function runDalfox(targetUrl: string): Promise<DalfoxResult> {
  const tmpFile = `/tmp/dalfox-${randomUUID()}.json`;
  let runFailure: string | null = null;

  try {
    await execFileAsync("dalfox", ["scan", targetUrl, "-f", "json", "-o", tmpFile, "--no-color"], { timeout: DALFOX_TIMEOUT_MS });
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") return { status: "not_configured", findings: [] };
    // Dalfox exits 1 when it finds a vulnerability — not a failure. The
    // output file is still written, so it's read below regardless.
    runFailure = `dalfox exited with error: ${error.message}`;
  }

  try {
    const raw = await readFile(tmpFile, "utf8");
    const parsed = parseDalfoxOutput(raw);
    if (parsed) {
      if (parsed.unreachable) return { status: "error", findings: [], note: "dalfox could not reach the target" };
      return { status: "completed", findings: parsed.findings };
    }
    if (!runFailure) runFailure = "dalfox output was not the expected JSON shape";
  } catch {
    // dalfox produced no readable output file — fall through to runFailure/clean below
  } finally {
    unlink(tmpFile).catch(() => undefined);
  }

  if (runFailure) return { status: "error", findings: [], note: runFailure };
  return { status: "completed", findings: [] };
}
