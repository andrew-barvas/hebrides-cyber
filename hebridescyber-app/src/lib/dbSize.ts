// Keeps the Supabase database inside the Free plan's size limit (owner
// decision 2026-11-20: stay on Free). Over the limit Supabase can put the
// project into read-only mode, which would stop scans, sign-ups and
// everything else that writes. db-size-guard.ts reads the real sizes daily,
// warns well before the limit and fails the workflow if it gets close.
//
// Pure helpers here; the database read is in the script.

export const FREE_PLAN_LIMIT_MB = 500;
/** Warn (email + workflow summary) from here. */
export const WARN_AT = 0.7;
/** Fail the workflow (GitHub emails the owner) from here. */
export const FAIL_AT = 0.85;

export type TableSize = { schema: string; table: string; totalBytes: number; dataBytes: number; indexBytes: number; rows: number };
export type SizeLevel = "ok" | "warn" | "fail";
export type SizeAssessment = { level: SizeLevel; usedMb: number; limitMb: number; percent: number };

const MB = 1024 * 1024;

export function assessDbSize(totalBytes: number, limitMb: number = FREE_PLAN_LIMIT_MB): SizeAssessment {
  const usedMb = Math.round((totalBytes / MB) * 10) / 10;
  const ratio = totalBytes / (limitMb * MB);
  const level: SizeLevel = ratio >= FAIL_AT ? "fail" : ratio >= WARN_AT ? "warn" : "ok";
  return { level, usedMb, limitMb, percent: Math.round(ratio * 1000) / 10 };
}

const mb = (bytes: number) => `${(bytes / MB).toFixed(1)} MB`;

/** Markdown: the headline and the largest tables. */
export function sizeReport(assessment: SizeAssessment, tables: readonly TableSize[], top = 12): string {
  const icon = assessment.level === "ok" ? "✅" : assessment.level === "warn" ? "⚠️" : "🛑";
  const lines = [
    `${icon} **Database: ${assessment.usedMb} MB of ${assessment.limitMb} MB (${assessment.percent}%)**`,
    "",
    "| Table | Total | Data | Indexes | Rows (approx.) |",
    "|---|---:|---:|---:|---:|",
    ...tables.slice(0, top).map((t) => `| ${t.schema}.${t.table} | ${mb(t.totalBytes)} | ${mb(t.dataBytes)} | ${mb(t.indexBytes)} | ${t.rows.toLocaleString("en-GB")} |`),
  ];
  return lines.join("\n");
}
