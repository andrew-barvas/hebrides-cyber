// Nuclei scanner integration.
//
// Uses the nuclei binary (pinned to v3.3.9 in worker.Dockerfile). When the
// binary is absent, returns { status: "not_configured" } so the worker
// continues gracefully instead of failing the whole scan job.
//
// targetUrl has already been SSRF-validated by run-scan before it was
// enqueued — the worker trusts it.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const execFileAsync = promisify(execFile);

const NUCLEI_TIMEOUT_MS = 120_000; // 120 seconds

export type NucleiFinding = {
  severity: string;
  title: string;
  detail: string;
  templateId: string;
};

export type NucleiResult =
  | { status: "completed"; findings: NucleiFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "error"; findings: []; note: string };

type NucleiJsonEntry = {
  "template-id"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
  };
  "matched-at"?: string;
  description?: string;
};

export async function runNuclei(targetUrl: string): Promise<NucleiResult> {
  const tmpFile = `/tmp/nuclei-${randomUUID()}.json`;

  try {
    await execFileAsync(
      "nuclei",
      [
        "-target", targetUrl,
        "-json-export", tmpFile,
        "-silent",
        "-timeout", "120",
      ],
      { timeout: NUCLEI_TIMEOUT_MS }
    );

    let raw: string;
    try {
      raw = await readFile(tmpFile, "utf8");
    } catch {
      // nuclei ran but produced no output file — no findings
      return { status: "completed", findings: [] };
    }

    const findings: NucleiFinding[] = [];
    const lines = raw.trim().split("\n").filter(Boolean);

    for (const line of lines) {
      try {
        const entry: NucleiJsonEntry = JSON.parse(line);
        findings.push({
          severity: entry.info?.severity ?? "info",
          title: entry.info?.name ?? entry["template-id"] ?? "Unknown finding",
          detail:
            entry.description ??
            entry.info?.description ??
            `Matched at: ${entry["matched-at"] ?? targetUrl}`,
          templateId: entry["template-id"] ?? "",
        });
      } catch {
        // skip malformed lines
      }
    }

    return { status: "completed", findings };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", findings: [] };
    }
    return {
      status: "error",
      findings: [],
      note: `nuclei exited with error: ${error.message}`,
    };
  } finally {
    // Best-effort cleanup — ignore errors if file was never written
    unlink(tmpFile).catch(() => undefined);
  }
}
