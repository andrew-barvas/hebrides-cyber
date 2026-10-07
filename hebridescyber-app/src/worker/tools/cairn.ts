// Cairn autonomous exploitation engine integration.
//
// AGPL-3.0 ISOLATION MODEL
// Cairn is licensed under AGPL-3.0. To avoid copyleft contamination of this
// proprietary SaaS codebase, Cairn runs ONLY as an isolated standalone binary
// via child_process.execFile — the same subprocess pattern used by every other
// tool in this directory (nuclei, sqlmap, nmap, etc.). This module:
//
//   - Never imports, links, or embeds any Cairn code
//   - Never shares libraries or compiled integrations with Cairn
//   - Communicates exclusively via temporary JSON files on disk (stdin/stdout)
//   - Runs Cairn as a completely separate OS process
//   - Only consumes Cairn's normalized JSON output (data, not code)
//   - Never calls Cairn from inside API routes or the Next.js backend
//   - Runs only inside GitHub Actions runners, never in the SaaS runtime
//
// This is the "aggregate" (not "derivative work") model under AGPL-3.0:
// invoking a program via its CLI and reading its output does not create a
// derivative work. The same legal basis used by every CI system that runs
// AGPL-licensed linters, scanners, or test frameworks.
//
// When the binary is absent, returns { status: "not_configured" } so the
// worker continues gracefully.

import { execTool } from "../../lib/execTool";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const execFileAsync = execTool;

const CAIRN_TIMEOUT_MS = 600_000; // 10 minutes — autonomous exploration is slow

export type CairnFinding = {
  severity: string;
  title: string;
  detail: string;
  vulnClass: string;
  evidence: string;
  endpoint: string;
  cveIds: string[];
  exploitSteps: string[];
};

export type CairnResult =
  | { status: "completed"; findings: CairnFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "error"; findings: []; note: string };

type CairnOutputEntry = {
  vulnerability_type?: string;
  severity?: string;
  title?: string;
  description?: string;
  evidence?: string;
  endpoint?: string;
  cve_ids?: string[];
  exploit_chain?: string[];
  matched_at?: string;
};

function buildCairnInput(targetUrl: string): object {
  return {
    target: targetUrl,
    mode: "scan",
    max_depth: 3,
    timeout_seconds: 540,
    output_format: "json",
  };
}

export async function runCairn(targetUrl: string): Promise<CairnResult> {
  const inputFile = `/tmp/cairn-input-${randomUUID()}.json`;
  const outputFile = `/tmp/cairn-output-${randomUUID()}.json`;

  try {
    await writeFile(inputFile, JSON.stringify(buildCairnInput(targetUrl)));

    await execFileAsync(
      "cairn",
      [
        "scan",
        "--input", inputFile,
        "--output", outputFile,
        "--format", "json",
        "--no-interactive",
      ],
      { timeout: CAIRN_TIMEOUT_MS }
    );

    let raw: string;
    try {
      raw = await readFile(outputFile, "utf8");
    } catch {
      return { status: "completed", findings: [] };
    }

    const findings: CairnFinding[] = [];

    let entries: CairnOutputEntry[];
    try {
      const parsed = JSON.parse(raw);
      entries = Array.isArray(parsed) ? parsed : parsed.findings ?? parsed.results ?? [parsed];
    } catch {
      const lines = raw.trim().split("\n").filter(Boolean);
      entries = [];
      for (const line of lines) {
        try {
          entries.push(JSON.parse(line));
        } catch {
          // skip malformed lines
        }
      }
    }

    for (const entry of entries) {
      findings.push({
        severity: entry.severity ?? "medium",
        title: entry.title ?? entry.vulnerability_type ?? "Unknown finding",
        detail:
          entry.description ??
          `Vulnerability found at: ${entry.endpoint ?? entry.matched_at ?? targetUrl}`,
        vulnClass: entry.vulnerability_type ?? "unknown",
        evidence: entry.evidence ?? "",
        endpoint: entry.endpoint ?? entry.matched_at ?? targetUrl,
        cveIds: entry.cve_ids ?? [],
        exploitSteps: entry.exploit_chain ?? [],
      });
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
      note: `cairn exited with error: ${error.message}`,
    };
  } finally {
    unlink(inputFile).catch(() => undefined);
    unlink(outputFile).catch(() => undefined);
  }
}
