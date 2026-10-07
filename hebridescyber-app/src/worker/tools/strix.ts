// Strix AI pentest agent integration.
//
// Uses the strix CLI (Apache 2.0, https://github.com/usestrix/strix).
// Strix deploys LLM-powered agent teams in Docker sandboxes to discover
// and validate vulnerabilities with proof-of-concept exploits. When the
// binary is absent or the LLM API key isn't configured, returns
// { status: "not_configured" } so the worker continues gracefully.
//
// Strix's output format is JSONL (one JSON object per finding), similar
// to nuclei. Each finding includes a severity, a vulnerability class,
// an exploit proof, and remediation guidance from the agent.
//
// COST NOTE: Strix uses LLM inference internally. Each scan costs $2-5
// in API fees depending on target complexity. Gate behind Agency tier
// or higher — see scanProfiles.ts's "ai-pentest" profile.

import { execTool } from "../../lib/execTool";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const execFileAsync = execTool;

const STRIX_TIMEOUT_MS = 300_000; // 5 minutes — LLM-backed scans are slower

export type StrixFinding = {
  severity: string;
  title: string;
  detail: string;
  vulnClass: string;
  exploit: string;
  agentRemediation: string;
};

export type StrixResult =
  | { status: "completed"; findings: StrixFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "error"; findings: []; note: string };

type StrixJsonEntry = {
  vulnerability_class?: string;
  severity?: string;
  title?: string;
  description?: string;
  exploit_proof?: string;
  remediation?: string;
  matched_at?: string;
};

export async function runStrix(targetUrl: string): Promise<StrixResult> {
  const tmpFile = `/tmp/strix-${randomUUID()}.json`;

  try {
    const env = { ...process.env };
    if (process.env.STRIX_LLM_API_KEY) {
      env.STRIX_API_KEY = process.env.STRIX_LLM_API_KEY;
    }

    await execFileAsync(
      "strix",
      [
        "scan",
        "--target", targetUrl,
        "--output", tmpFile,
        "--format", "json",
        "--mode", "deep",
        "--no-interactive",
      ],
      { timeout: STRIX_TIMEOUT_MS, env }
    );

    let raw: string;
    try {
      raw = await readFile(tmpFile, "utf8");
    } catch {
      return { status: "completed", findings: [] };
    }

    const findings: StrixFinding[] = [];
    const lines = raw.trim().split("\n").filter(Boolean);

    for (const line of lines) {
      try {
        const entry: StrixJsonEntry = JSON.parse(line);
        findings.push({
          severity: entry.severity ?? "medium",
          title: entry.title ?? entry.vulnerability_class ?? "Unknown finding",
          detail:
            entry.description ??
            `Vulnerability found at: ${entry.matched_at ?? targetUrl}`,
          vulnClass: entry.vulnerability_class ?? "unknown",
          exploit: entry.exploit_proof ?? "",
          agentRemediation: entry.remediation ?? "",
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
      note: `strix exited with error: ${error.message}`,
    };
  } finally {
    unlink(tmpFile).catch(() => undefined);
  }
}
