// Worker scan runner — orchestrates all scanners for a queued job.
//
// Called by the BullMQ worker in index.ts. Reports progress via BullMQ's
// job.updateProgress() so the admin queue view can show live status.

import { Job } from "bullmq";
import { createClient } from "@supabase/supabase-js";
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary } from "../lib/scanners";
import { runNuclei } from "./tools/nuclei";
import { runZap } from "./tools/zap";
import { runSqlmap } from "./tools/sqlmap";
import { runNmap } from "./tools/nmap";
import type { ScanJobData, ScanJobResult } from "../lib/queue";

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
);

export async function processScanJob(
  job: Job<ScanJobData, ScanJobResult>
): Promise<ScanJobResult> {
  const { scanId, targetUrl } = job.data;

  await supabaseAdmin.from("scans").update({ status: "running" }).eq("id", scanId);
  await job.updateProgress(5);

  // --- Core checks (TLS, headers, DNS, exposure, fingerprint, ports) ----------
  const coreResults = await runAllChecks(targetUrl);
  await job.updateProgress(40);

  // --- Extended tool suite ----------------------------------------------------
  const [nucleiResult, zapResult, sqlmapResult, nmapResult] = await Promise.allSettled([
    runNuclei(targetUrl),
    runZap(targetUrl),
    runSqlmap(targetUrl),
    runNmap(targetUrl),
  ]);

  await job.updateProgress(80);

  const extended = {
    nuclei: nucleiResult.status === "fulfilled" ? nucleiResult.value : { status: "error", findings: [], note: String(nucleiResult.reason) },
    zap: zapResult.status === "fulfilled" ? zapResult.value : { status: "error", alerts: [], note: String(zapResult.reason) },
    sqlmap: sqlmapResult.status === "fulfilled" ? sqlmapResult.value : { status: "error", findings: [], note: String(sqlmapResult.reason) },
    nmap: nmapResult.status === "fulfilled" ? nmapResult.value : { status: "error", ports: [], note: String(nmapResult.reason) },
  };

  // Merge extended findings into the core finding set before scoring.
  const { findings: coreFindings } = summariseResults(coreResults);

  const allFindings = [...coreFindings];

  // Nuclei
  if (extended.nuclei.status === "completed") {
    for (const f of extended.nuclei.findings) {
      allFindings.push({
        severity: f.severity as "critical" | "high" | "medium" | "low" | "info",
        title: `[Nuclei] ${f.title}`,
        detail: f.detail,
      });
    }
  }

  // ZAP
  if (extended.zap.status === "completed" && "findings" in extended.zap) {
    allFindings.push(...(extended.zap as { findings: typeof allFindings }).findings);
  }

  // sqlmap
  if (extended.sqlmap.status === "completed" && "vulnerable" in extended.sqlmap && extended.sqlmap.vulnerable) {
    for (const f of extended.sqlmap.findings) {
      allFindings.push({
        severity: "critical",
        title: `[sqlmap] SQL Injection — param: ${f.parameter}`,
        detail: `DBMS: ${f.dbms ?? "unknown"}. Parameter "${f.parameter}" is vulnerable to SQL injection.`,
      });
    }
  }

  // nmap
  if (extended.nmap.status === "completed") {
    for (const p of extended.nmap.ports) {
      if ([2375, 2376, 6379, 9200, 27017, 2379].includes(p.port)) {
        allFindings.push({
          severity: "critical",
          title: `[nmap] Dangerous port open: ${p.port}/${p.protocol} (${p.service})`,
          detail: `Service "${p.service}" is publicly reachable on port ${p.port}. This commonly indicates an unprotected database or Docker daemon.`,
        });
      }
    }
  }

  const summary = await generateAiSummary(coreResults, allFindings);
  const score = scoreFromFindings(allFindings);

  await supabaseAdmin.from("scan_results").upsert({
    scan_id: scanId,
    results: { ...coreResults, extended, findings: allFindings },
    summary,
    score,
  });

  await supabaseAdmin.from("scans").update({ status: "completed" }).eq("id", scanId);
  await job.updateProgress(100);

  return { score, summary, findingsCount: allFindings.length };
}
