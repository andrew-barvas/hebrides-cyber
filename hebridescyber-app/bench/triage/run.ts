// AI-triage accuracy benchmark: `npm run bench:triage`.
//
// Runs the real triageFinding() pipeline — real prompts, real replayProbe
// allowlist, real model call — against the labeled cases in cases.ts, then
// scores the model's verdict against each case's `expected` ground truth.
//
// Needs AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_KEY / AZURE_OPENAI_DEPLOYMENT
// set (see docs/AI-TRIAGE-DESIGN.md); without them azureChat reports
// "not_configured" and the run exits 2 before scoring anything. This is
// intentionally NOT wired into CI yet (no model credential there) — run it
// by hand after touching aiTriage.ts's prompts, or periodically to catch
// drift in model behaviour. See docs/NEXT-STEPS.md.
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { azureChat, triageFinding, type TriageVerdict } from "../../src/lib/scanners/aiTriage";
import { createReplayBudget } from "../../src/lib/scanners/replayProbe";
import { CASES, type TriageCase } from "./cases";
import { startSite } from "../lib/server";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPORT_PATH = path.join(here, "reports", "latest.json");

type CaseResult = {
  name: string;
  expected: TriageVerdict;
  /** The model's actual verdict, or a non-verdict outcome (skipped/error/not_configured). */
  actual: TriageVerdict | "skipped" | "error" | "not_configured";
  correct: boolean;
  detail?: string;
};

async function runCase(c: TriageCase): Promise<CaseResult> {
  const site = await startSite(c.site);
  try {
    const outcome = await triageFinding(site.url, c.finding, { chat: azureChat, budget: createReplayBudget(4) });
    if (outcome.status === "not_configured") return { name: c.name, expected: c.expected, actual: "not_configured", correct: false };
    if (outcome.status === "error") return { name: c.name, expected: c.expected, actual: "error", correct: false, detail: outcome.message };
    if (outcome.status === "skipped") return { name: c.name, expected: c.expected, actual: "skipped", correct: false, detail: outcome.reason };
    return {
      name: c.name,
      expected: c.expected,
      actual: outcome.record.verdict,
      correct: outcome.record.verdict === c.expected,
      detail: outcome.record.reasoning,
    };
  } finally {
    await site.close();
  }
}

/** Precision/recall for "confirmed" specifically — that's the verdict whose false positives matter most. */
function confirmedPrecisionRecall(results: CaseResult[]): { precision: number | null; recall: number | null } {
  const predictedConfirmed = results.filter((r) => r.actual === "confirmed");
  const truePositives = predictedConfirmed.filter((r) => r.expected === "confirmed").length;
  const actualConfirmed = results.filter((r) => r.expected === "confirmed");
  return {
    precision: predictedConfirmed.length === 0 ? null : truePositives / predictedConfirmed.length,
    recall: actualConfirmed.length === 0 ? null : truePositives / actualConfirmed.length,
  };
}

function pct(n: number | null): string {
  return n === null ? "n/a" : `${(n * 100).toFixed(0)}%`;
}

function renderReport(results: CaseResult[]): string {
  const lines: string[] = [];
  const correct = results.filter((r) => r.correct).length;
  lines.push(`AI triage benchmark: ${correct}/${results.length} cases matched the expected verdict.\n`);
  for (const r of results) {
    const mark = r.correct ? "OK  " : "MISS";
    lines.push(`[${mark}] ${r.name}: expected ${r.expected}, got ${r.actual}${r.detail ? ` — ${r.detail}` : ""}`);
  }
  const { precision, recall } = confirmedPrecisionRecall(results);
  lines.push(`\n"confirmed" precision: ${pct(precision)}  recall: ${pct(recall)}`);
  return lines.join("\n");
}

async function main(): Promise<number> {
  const probe = await azureChat([{ role: "system", content: "ping" }, { role: "user", content: "ping" }]);
  if (probe.status === "not_configured") {
    console.error("AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_KEY / AZURE_OPENAI_DEPLOYMENT are not set — nothing to benchmark. See docs/AI-TRIAGE-DESIGN.md.");
    return 2;
  }

  const results: CaseResult[] = [];
  for (const c of CASES) {
    results.push(await runCase(c));
  }

  mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  writeFileSync(REPORT_PATH, JSON.stringify(results, null, 2) + "\n");

  console.log(renderReport(results));
  console.log(`\nReport written to ${path.relative(process.cwd(), REPORT_PATH)}`);
  return results.every((r) => r.correct) ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err: Error) => {
    console.error(`Benchmark setup error: ${err.message}`);
    process.exit(2);
  }
);
