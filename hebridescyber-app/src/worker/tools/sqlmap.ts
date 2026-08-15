// sqlmap integration — SQL injection detection.
//
// Runs sqlmap in batch mode against the target URL. Requires the `sqlmap`
// command to be available (installed in worker.Dockerfile via pip3).
// Returns gracefully when the binary is missing.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const execFileAsync = promisify(execFile);

const SQLMAP_TIMEOUT_MS = 180_000;

export type SqlmapFinding = {
  parameter: string;
  type: string;
  dbms: string | null;
};

export type SqlmapResult =
  | { status: "completed"; vulnerable: boolean; findings: SqlmapFinding[] }
  | { status: "not_configured"; vulnerable: false; findings: [] }
  | { status: "error"; vulnerable: false; findings: []; note: string };

export async function runSqlmap(targetUrl: string): Promise<SqlmapResult> {
  const outputDir = await mkdtemp(join(tmpdir(), `sqlmap-${randomUUID()}-`));
  const logFile = join(outputDir, "output.log");

  try {
    await execFileAsync(
      "sqlmap",
      [
        "--url", targetUrl,
        "--batch",           // never prompt
        "--output-dir", outputDir,
        "--level", "1",
        "--risk", "1",
        "--timeout", "30",
        "--retries", "1",
        "--random-agent",
        "--forms",           // test form parameters
        "--crawl", "2",
      ],
      { timeout: SQLMAP_TIMEOUT_MS }
    );

    let log = "";
    try {
      log = await readFile(logFile, "utf8");
    } catch {
      log = "";
    }

    // Parse findings from sqlmap log — look for injection-found markers.
    const findings: SqlmapFinding[] = [];
    const foundPattern = /\[\d+:\d+:\d+\] \[INFO\] GET parameter '(.+?)' is vulnerable\./g;
    const dbmsPattern = /back-end DBMS: (.+)/;

    let match: RegExpExecArray | null;
    while ((match = foundPattern.exec(log)) !== null) {
      const dbmsMatch = dbmsPattern.exec(log);
      findings.push({
        parameter: match[1],
        type: "SQL Injection",
        dbms: dbmsMatch ? dbmsMatch[1].trim() : null,
      });
    }

    return { status: "completed", vulnerable: findings.length > 0, findings };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", vulnerable: false, findings: [] };
    }
    return {
      status: "error",
      vulnerable: false,
      findings: [],
      note: `sqlmap exited: ${error.message}`,
    };
  } finally {
    unlink(logFile).catch(() => undefined);
  }
}
