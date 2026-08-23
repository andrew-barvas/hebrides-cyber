// Shared "finish a scan" logic: run the checks, write results, mark the scan
// completed, fire webhooks and the Slack change-alert. Extracted out of
// src/functions/run-scan/index.ts (the dashboard's synchronous scan path) so
// the queued-worker path (src/scripts/run-queued-scan-jobs.ts) executes the
// exact same sequence rather than a second copy that can drift — the same
// reasoning as src/lib/scanReport.ts's "one contract" comment.
//
// Callers are responsible for everything BEFORE this: creating the `scans`
// row, verifying ownership, and the SSRF check (validateNoSsrf). This
// function assumes all of that already happened.
import type { SupabaseClient } from "@supabase/supabase-js";
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary, type Finding } from "./scanners";
import { buildScanReport, findPreviousFindings, type ScanReport } from "./scanReport";
import { dispatchScanCompletedWebhooks } from "./webhooks";
import { sendSlackAlert } from "./slack";
import { sendTeamsAlert } from "./msTeams";
import { runNuclei } from "../worker/tools/nuclei";
import { runZap } from "../worker/tools/zap";
import { runSqlmap } from "../worker/tools/sqlmap";
import { runXsser } from "../worker/tools/xsser";
import { runCommix } from "../worker/tools/commix";
import { runNmap } from "../worker/tools/nmap";
import { runSubdomainDiscovery } from "./scanners/subdomains";
import { runDeepTls } from "./scanners/deepTls";
import { scanRepositoryForSecrets } from "./scanners/secretScan";
import { scanDependencyManifest } from "./scanners/dependencyManifest";
import { scanDockerBaseImage } from "./scanners/dockerBaseImage";
import { checkAuthenticated, buildAuthenticatedFindings, type AuthCredential } from "./scanners/authenticatedCheck";
import { nucleiRemediation, sqlmapRemediation, xsserRemediation, commixRemediation, nmapDangerousPortRemediation } from "./scanners/remediationText";
import { getComplianceRefs } from "./scanners/compliance";
import { sendCriticalAlertEmail } from "./scanAlerts";
import { autoCloseFixedFindingTickets } from "./ticketAutoClose";
import { logAuditEvent } from "./audit";

export type ScanExecutionResult =
  | { ok: true; score: number; summary: string; report: ScanReport }
  | { ok: false; error: string };

export type ExecuteScanOptions = {
  /**
   * Also runs nmap/nuclei/sqlmap/ZAP and merges their findings in. Off by
   * default — explicit opt-in, not "on wherever the binaries happen to be
   * installed". These tools take 1-3 minutes and need real binaries/a ZAP
   * daemon that only the GitHub Actions queue worker actually has (see
   * .github/workflows/scheduled-scans.yml) — the dashboard's synchronous
   * run-scan Function and the public API must never wait on them, so they
   * never pass this. Each tool already degrades to "not_configured" on its
   * own when its binary/daemon is missing (see src/worker/tools/*.ts), but
   * this flag means that's never load-bearing for correctness — a future
   * environment that happens to have nmap installed still won't trigger it
   * for the dashboard path.
   */
  runExtendedTools?: boolean;
};

// Ports whose presence alone is worth a critical finding, regardless of what
// nmap's service-detection guessed — an unauthenticated database or Docker
// daemon exposed to the internet needs no further probing to be dangerous.
const DANGEROUS_TOOL_PORTS = new Set([2375, 2376, 6379, 9200, 27017, 2379]);

/**
 * Runs the real active-scanning tool suite and shapes its output into
 * Finding[] the same way the rest of the scanner suite does — including
 * checkId, which the original BullMQ-worker sketch (src/worker/runner.ts)
 * never set, so none of these findings could ever participate in the
 * New/Fixed scan-to-scan diff. Ported here rather than left in runner.ts
 * because runner.ts's queue (BullMQ+Redis) was never wired to anything —
 * see docs/PLATFORM-ROADMAP.md.
 */
async function runExtendedTools(
  targetUrl: string,
  githubRepo: string | null,
  authCredential: AuthCredential | null,
  detectedTechnologies: string[]
): Promise<{ extended: Record<string, unknown>; findings: Finding[]; supersedesReconSubdomains: boolean }> {
  const [
    nucleiResult,
    zapResult,
    sqlmapResult,
    xsserResult,
    commixResult,
    nmapResult,
    subdomainsResult,
    deepTlsResult,
    secretScanResult,
    dependencyManifestResult,
    dockerBaseImageResult,
    authCheckResult,
  ] = await Promise.allSettled([
    runNuclei(targetUrl, detectedTechnologies),
    runZap(targetUrl),
    runSqlmap(targetUrl),
    // Same "dedicated tool beyond ZAP's generic active-scan rules" precedent
    // as sqlmap above, applied to XSS and OS command injection respectively.
    runXsser(targetUrl),
    runCommix(targetUrl),
    runNmap(targetUrl),
    runSubdomainDiscovery(targetUrl),
    runDeepTls(targetUrl),
    // All three of these are only attempted when the scan owner has a row in
    // repo_connections — see sql/migrations/009_repo_connections.sql.
    // secretScan.ts/dependencyManifest.ts/dockerBaseImage.ts are pure
    // { githubRepo } functions specifically so this call site is the only
    // place that needs to know where the repo name comes from.
    githubRepo
      ? scanRepositoryForSecrets({ githubRepo })
      : Promise.resolve({ status: "not_configured" as const, repo: "", findings: [] as Finding[], note: "No repository connected." }),
    githubRepo
      ? scanDependencyManifest({ githubRepo })
      : Promise.resolve({ status: "not_applicable" as const, repo: "", findings: [] as Finding[], note: "No repository connected." }),
    githubRepo
      ? scanDockerBaseImage({ githubRepo })
      : Promise.resolve({ status: "not_applicable" as const, repo: "", findings: [] as Finding[], note: "No repository connected." }),
    // Sprint 3, first slice — same "pure function over an explicit input"
    // shape as the GitHub-backed checks above, so this call site is the only
    // place that needs to know where the credential comes from.
    checkAuthenticated(targetUrl, authCredential),
  ]);

  const extended = {
    nuclei: nucleiResult.status === "fulfilled" ? nucleiResult.value : { status: "error", findings: [], note: String(nucleiResult.reason) },
    zap: zapResult.status === "fulfilled" ? zapResult.value : { status: "error", alerts: [], note: String(zapResult.reason) },
    sqlmap: sqlmapResult.status === "fulfilled" ? sqlmapResult.value : { status: "error", vulnerable: false, findings: [], note: String(sqlmapResult.reason) },
    xsser: xsserResult.status === "fulfilled" ? xsserResult.value : { status: "error", vulnerable: false, findings: [], note: String(xsserResult.reason) },
    commix: commixResult.status === "fulfilled" ? commixResult.value : { status: "error", vulnerable: false, findings: [], note: String(commixResult.reason) },
    nmap: nmapResult.status === "fulfilled" ? nmapResult.value : { status: "error", ports: [], note: String(nmapResult.reason) },
    subdomains: subdomainsResult.status === "fulfilled" ? subdomainsResult.value : { status: "error", subdomains: [], findings: [], note: String(subdomainsResult.reason) },
    deepTls: deepTlsResult.status === "fulfilled" ? deepTlsResult.value : { status: "error", host: targetUrl, findings: [], note: String(deepTlsResult.reason) },
    secretScan: secretScanResult.status === "fulfilled" ? secretScanResult.value : { status: "error", repo: githubRepo ?? "", findings: [], note: String(secretScanResult.reason) },
    dependencyManifest: dependencyManifestResult.status === "fulfilled" ? dependencyManifestResult.value : { status: "error", repo: githubRepo ?? "", findings: [], note: String(dependencyManifestResult.reason) },
    dockerBaseImage: dockerBaseImageResult.status === "fulfilled" ? dockerBaseImageResult.value : { status: "error", repo: githubRepo ?? "", findings: [], note: String(dockerBaseImageResult.reason) },
    authCheck: authCheckResult.status === "fulfilled" ? authCheckResult.value : { status: "error" as const, note: String(authCheckResult.reason) },
  };

  const findings: Finding[] = [];

  if (extended.nuclei.status === "completed") {
    for (const f of extended.nuclei.findings) {
      findings.push({
        checkId: `nuclei.finding:${f.templateId || f.title}`,
        severity: (f.severity as Finding["severity"]) || "info",
        title: `[Nuclei] ${f.title}`,
        detail: f.detail,
        remediation: nucleiRemediation(f.templateId),
      });
    }
  }

  // ZAP's own alert.solution is real, evidenced, per-finding remediation
  // from its own knowledge base — runZap() (src/worker/tools/zap.ts) attaches
  // it directly as Finding.remediation, so there's nothing to add here.
  if (extended.zap.status === "completed" && "findings" in extended.zap) {
    findings.push(...extended.zap.findings);
  }

  if (extended.sqlmap.status === "completed" && extended.sqlmap.vulnerable) {
    for (const f of extended.sqlmap.findings) {
      findings.push({
        checkId: `sqlmap.sqli:${f.parameter}`,
        severity: "critical",
        title: `[sqlmap] SQL injection — param: ${f.parameter}`,
        detail: `DBMS: ${f.dbms ?? "unknown"}. Parameter "${f.parameter}" is vulnerable to SQL injection.`,
        remediation: sqlmapRemediation(f.dbms),
      });
    }
  }

  if (extended.xsser.status === "completed" && extended.xsser.vulnerable) {
    for (const f of extended.xsser.findings) {
      findings.push({
        checkId: `xsser.xss:${f.url}`,
        severity: "critical",
        title: `[XSSer] Cross-site scripting confirmed`,
        detail: `A reflected/injectable XSS point was confirmed at ${f.url}.`,
        remediation: xsserRemediation(),
      });
    }
  }

  if (extended.commix.status === "completed" && extended.commix.vulnerable) {
    for (const f of extended.commix.findings) {
      findings.push({
        checkId: `commix.command-injection:${f.parameter}`,
        severity: "critical",
        title: `[commix] OS command injection — param: ${f.parameter}`,
        detail: `Parameter "${f.parameter}" is vulnerable to OS command injection.`,
        remediation: commixRemediation(),
      });
    }
  }

  if (extended.nmap.status === "completed") {
    for (const p of extended.nmap.ports) {
      if (DANGEROUS_TOOL_PORTS.has(p.port)) {
        findings.push({
          checkId: `nmap.dangerous-port:${p.port}`,
          severity: "critical",
          title: `[nmap] Dangerous port open: ${p.port}/${p.protocol} (${p.service})`,
          detail: `Service "${p.service}" is publicly reachable on port ${p.port}. This commonly indicates an unprotected database or Docker daemon.`,
          remediation: nmapDangerousPortRemediation(p.port),
        });
      }
    }
  }

  // subdomains.ts (Subfinder) and deepTls.ts (testssl.sh) already emit
  // fully-formed Finding[] with their own checkId namespaces, same as ZAP.
  if (extended.subdomains.status === "completed") {
    findings.push(...extended.subdomains.findings);
  }
  if (extended.deepTls.status === "completed") {
    findings.push(...extended.deepTls.findings);
  }
  if (extended.secretScan.status === "completed") {
    findings.push(...extended.secretScan.findings);
  }
  if (extended.dependencyManifest.status === "completed") {
    findings.push(...extended.dependencyManifest.findings);
  }
  if (extended.dockerBaseImage.status === "completed") {
    findings.push(...extended.dockerBaseImage.findings);
  }
  findings.push(...buildAuthenticatedFindings(extended.authCheck));

  // recon.ts's base checkDns pass already reports a single "N subdomains
  // found via crt.sh" finding (recon.subdomains-found). When Subfinder also
  // ran and found anything, its per-host findings are strictly more useful
  // (evidence-scored severity, takeover/sensitive-host detection, New/Fixed
  // diffing per host) — the caller drops the recon.ts summary finding in
  // that case so one report never lists both.
  const supersedesReconSubdomains =
    extended.subdomains.status === "completed" && "total" in extended.subdomains && extended.subdomains.total > 0;

  return { extended, findings, supersedesReconSubdomains };
}

export async function executeScan(
  supabaseAdmin: SupabaseClient,
  scanId: string,
  ownerId: string,
  targetUrl: string,
  options: ExecuteScanOptions = {}
): Promise<ScanExecutionResult> {
  // Phase 1: the part that determines success/failure. Anything thrown here
  // means the scan itself didn't complete, so marking the row 'failed' is
  // correct.
  let score: number;
  let summary: string;
  let findings: Finding[];
  let extended: Record<string, unknown> | undefined;

  await logAuditEvent(supabaseAdmin, {
    actorId: ownerId,
    action: "scan.started",
    resourceType: "scan",
    resourceId: scanId,
    metadata: { target_url: targetUrl, extended_tools: Boolean(options.runExtendedTools) },
  });

  try {
    const results = await runAllChecks(targetUrl);
    ({ findings } = summariseResults(results));

    if (options.runExtendedTools) {
      const { data: repoConnection } = await supabaseAdmin
        .from("repo_connections")
        .select("github_repo")
        .eq("owner", ownerId)
        .maybeSingle();

      // target_auth_credentials is keyed by monitored_target_id, not
      // (owner, target_url) directly — a scan only ever gets here via the
      // scheduled path (runExtendedTools is scheduled-scan-only), which
      // always originates from a monitored_targets row, so this join is
      // real, not speculative.
      const { data: monitoredTarget } = await supabaseAdmin
        .from("monitored_targets")
        .select("id")
        .eq("owner", ownerId)
        .eq("target_url", targetUrl)
        .maybeSingle();

      let authCredential: AuthCredential | null = null;
      if (monitoredTarget) {
        const { data: credRow } = await supabaseAdmin
          .from("target_auth_credentials")
          .select("auth_type, cookie_value, basic_username, basic_password")
          .eq("monitored_target_id", monitoredTarget.id)
          .maybeSingle();
        if (credRow?.auth_type === "cookie" && credRow.cookie_value) {
          authCredential = { type: "cookie", cookieValue: credRow.cookie_value };
        } else if (credRow?.auth_type === "basic" && credRow.basic_username && credRow.basic_password) {
          authCredential = { type: "basic", username: credRow.basic_username, password: credRow.basic_password };
        }
      }

      // Feeds nuclei's technology-scoped -tags filter (Sprint 5) — see
      // src/worker/tools/nuclei.ts's header for why this replaced firing
      // nuclei's entire default template set at every target.
      const detectedTechnologies = results.fingerprint.status === "checked" ? results.fingerprint.technologies.map((t) => t.name) : [];

      const toolOutcome = await runExtendedTools(targetUrl, repoConnection?.github_repo ?? null, authCredential, detectedTechnologies);
      extended = toolOutcome.extended;
      if (toolOutcome.supersedesReconSubdomains) {
        findings = findings.filter((f) => f.checkId !== "recon.subdomains-found");
      }
      findings = [...findings, ...toolOutcome.findings];
      // summariseResults() already ran its own compliance-mapping pass over
      // the base-suite findings; extended-tool findings are appended after
      // that returns, so they need the same pass applied here — see
      // src/lib/scanners/compliance.ts's header for why this is a final
      // pass over checkId rather than something each push site sets itself.
      for (const finding of toolOutcome.findings) {
        const refs = getComplianceRefs(finding.checkId);
        if (refs.length > 0) finding.complianceRefs = refs;
      }
    }

    summary = await generateAiSummary(results, findings);
    score = scoreFromFindings(findings);

    const { error: resultsError } = await supabaseAdmin.from("scan_results").insert({
      scan_id: scanId,
      results: extended ? { ...results, extended, findings } : { ...results, findings },
      summary,
      score,
    });
    if (resultsError) throw new Error(resultsError.message);

    await supabaseAdmin.from("scans").update({ status: "completed" }).eq("id", scanId);
    await logAuditEvent(supabaseAdmin, {
      actorId: ownerId,
      action: "scan.completed",
      resourceType: "scan",
      resourceId: scanId,
      metadata: { target_url: targetUrl, score },
    });
  } catch (err) {
    await supabaseAdmin
      .from("scans")
      .update({ status: "failed" })
      .eq("id", scanId)
      .then(
        () => {},
        () => {}
      );
    await logAuditEvent(supabaseAdmin, {
      actorId: ownerId,
      action: "scan.failed",
      resourceType: "scan",
      resourceId: scanId,
      metadata: { target_url: targetUrl, error: (err as Error).message },
    });
    return { ok: false, error: (err as Error).message };
  }

  // Phase 1.5: build the report. The scan already succeeded and is already
  // recorded as 'completed' above, so a failure here (e.g. a transient
  // Supabase error while looking up the previous scan to diff against) must
  // not flip that back to 'failed' — it just means the report comes back
  // without new/fixed-finding comparison, same as a genuine first-ever scan.
  const completedAt = new Date().toISOString();
  const scanRow = { id: scanId, owner: ownerId, target_url: targetUrl, status: "completed", created_at: completedAt };
  const resultRow = { results: { findings }, summary, score, created_at: completedAt };
  let report: ScanReport;
  try {
    const previous = await findPreviousFindings(supabaseAdmin, ownerId, scanId, targetUrl, completedAt);
    report = buildScanReport(scanRow, resultRow, previous);
  } catch (err) {
    console.error(`[scanExecution] could not look up previous scan for diffing (scan ${scanId}):`, (err as Error).message);
    report = buildScanReport(scanRow, resultRow, null);
  }

  // Phase 2: notifications. dispatchScanCompletedWebhooks and the Slack
  // alert both already swallow their own errors internally, but wrapping
  // the whole phase keeps it that way even if that ever changes.
  try {
    await dispatchScanCompletedWebhooks(supabaseAdmin, ownerId, report);
    await sendChangeAlertIfDue(supabaseAdmin, ownerId, report, findings);
    await sendCriticalAlertEmail(supabaseAdmin, ownerId, report);
    // Opt-in and off by default — no-ops entirely unless the owner enabled
    // auto-close on their Jira/Linear integration.
    await autoCloseFixedFindingTickets(supabaseAdmin, ownerId, report);
  } catch (err) {
    console.error(`[scanExecution] post-completion notifications failed for scan ${scanId}:`, (err as Error).message);
  }

  return { ok: true, score, summary, report };
}

/**
 * Slack/Teams "change alert" — fires only when this scan found something new
 * compared to the last one, so nightly monitoring doesn't spam a channel
 * with an identical "all clear" message every night. Gated to Pro/Agency
 * plans, matching what the services page advertises ("Slack alerts on score
 * change (Pro/Agency plan)"). Slack and Teams are independent — a customer
 * with both webhooks configured gets both, and either can be set without
 * the other.
 */
async function sendChangeAlertIfDue(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport,
  findings: { severity: string }[]
): Promise<void> {
  if (!report.new_finding_count) return; // null (no previous scan) or 0 — nothing changed

  const { data: sub } = await supabaseAdmin
    .from("subscriptions")
    .select("plan, status, slack_webhook_url, ms_teams_webhook_url")
    .eq("owner", ownerId)
    .maybeSingle();

  if (!sub || sub.status !== "active") return;
  if (sub.plan !== "pro" && sub.plan !== "agency") return;
  if (!sub.slack_webhook_url && !sub.ms_teams_webhook_url) return;

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  const alertPayload = {
    scanId: report.scan_id,
    targetUrl: report.target_url,
    score: report.score ?? 0,
    findingsCount: findings.length,
    criticalCount,
    highCount,
    newFindingsCount: report.new_finding_count,
    fixedFindingsCount: report.fixed_finding_count ?? 0,
    dashboardUrl: process.env.NEXT_PUBLIC_SITE_URL ?? "https://hebridescyber.com",
  };

  if (sub.slack_webhook_url) {
    await sendSlackAlert(sub.slack_webhook_url, alertPayload).catch((err) =>
      console.error("[scanExecution] slack change alert failed:", (err as Error).message)
    );
  }
  if (sub.ms_teams_webhook_url) {
    await sendTeamsAlert(sub.ms_teams_webhook_url, alertPayload).catch((err) =>
      console.error("[scanExecution] teams change alert failed:", (err as Error).message)
    );
  }
}
