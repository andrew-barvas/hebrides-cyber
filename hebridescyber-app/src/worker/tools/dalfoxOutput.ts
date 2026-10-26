// Reads Dalfox's `-f json` output. Pure: no IO, so it is tested against
// output captured from a real Dalfox v3.2.4 run (fixtures/dalfox/, captured
// 2026-10-23 against tests/fixtures/test-app) rather than a schema read from
// its docs.
//
// What the capture established:
//   - `findings` is an array, empty when nothing is found — never absent.
//   - Each finding's `severity` is capitalised ("High"/"Medium"/"Low"), unlike
//     every other tool wrapper in this codebase, which uses lowercase.
//   - `meta.target_summary[]` has one entry per target with a `status`:
//     "findings" (matches `findings.length`), "clean" (ran fine, nothing
//     found) or "skipped" (never reached the target — `error_code` is set,
//     e.g. "CONNECTION_FAILED"). "skipped" must parse as an error, never a
//     clean result (CLAUDE.md rule 7) — a target Dalfox never actually
//     reached says nothing about whether it's vulnerable.
//   - A finding whose `type` is not "V" ("Vulnerable") has not been captured
//     yet (Dalfox's docs mention "G"/"R" for "weak/potential" signals); treat
//     anything other than "V" as not confirmed rather than guessing its
//     meaning.

export type DalfoxFinding = {
  param: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  payload: string;
  evidence: string;
  cwe?: string;
};

type DalfoxJsonFinding = {
  type?: string;
  param?: string;
  severity?: string;
  payload?: string;
  evidence?: string;
  message_str?: string;
  cwe?: string;
};

type DalfoxTargetSummary = {
  target?: string;
  status?: string;
  error_code?: string;
  findings_count?: number;
};

type DalfoxJson = {
  findings?: DalfoxJsonFinding[];
  meta?: { target_summary?: DalfoxTargetSummary[] };
};

const SEVERITY_MAP: Record<string, DalfoxFinding["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

/**
 * Parse Dalfox's JSON report. Returns `null` if the text isn't the shape
 * Dalfox emits at all (never run, or a tool upgrade changed the format) —
 * the caller treats that as an error, not zero findings.
 */
export function parseDalfoxOutput(raw: string): { findings: DalfoxFinding[]; unreachable: boolean } | null {
  let parsed: DalfoxJson;
  try {
    parsed = JSON.parse(raw) as DalfoxJson;
  } catch {
    return null;
  }
  if (!Array.isArray(parsed.findings)) return null;

  const summaries = parsed.meta?.target_summary ?? [];
  // "skipped" (Dalfox never reached the target) is never silently clean.
  const unreachable = summaries.length > 0 && summaries.every((s) => s.status === "skipped");

  const findings: DalfoxFinding[] = [];
  for (const entry of parsed.findings) {
    if (entry.type !== "V") continue; // only Dalfox's own "confirmed vulnerable" verdict
    if (!entry.param) continue;
    const severity = SEVERITY_MAP[(entry.severity ?? "").toLowerCase()] ?? "medium";
    findings.push({
      param: entry.param,
      severity,
      payload: entry.payload ?? "",
      evidence: entry.evidence ?? entry.message_str ?? "",
      ...(entry.cwe ? { cwe: entry.cwe } : {}),
    });
  }
  return { findings, unreachable };
}
