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
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary, enrichFindingsWithCvss, type Finding } from "./scanners";
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
import { scanTrivyImage, scanTrivyConfig } from "./scanners/trivyScan";
import { checkAuthenticated, buildAuthenticatedFindings, type AuthCredential } from "./scanners/authenticatedCheck";
import { runWhatWaf } from "../worker/tools/whatwaf";
import { runWpScanCli } from "../worker/tools/wpscan";
import { runCmsMap } from "../worker/tools/cmsmap";
import { runPhoton } from "../worker/tools/photon";
import { runGospider } from "../worker/tools/gospider";
import { runZapAjaxSpider } from "../worker/tools/zapAjaxSpider";
import { runMetadataLeakCheck } from "../worker/tools/metadataLeak";
import { runKiterunner } from "../worker/tools/kiterunner";
import { runArjun } from "../worker/tools/arjun";
import { runSessionCheck } from "../worker/tools/sessionCheck";
import { nucleiRemediation, sqlmapRemediation, xsserRemediation, commixRemediation, nmapDangerousPortRemediation, WAF_NOT_DETECTED, WPSCAN_CONFIG_BACKUP, WPSCAN_DB_EXPORT, WPSCAN_TIMTHUMB, wpScanThemeVulnerabilityRemediation, cmsmapVulnerabilityRemediation, cmsmapMisconfigRemediation, METADATA_LEAK_EMAIL, METADATA_LEAK_INTERNAL_IP, METADATA_LEAK_PATH, METADATA_LEAK_AUTHOR, METADATA_LEAK_SOFTWARE, HIDDEN_ENDPOINT_DISCOVERED, KITERUNNER_HIDDEN_ENDPOINT, ARJUN_HIDDEN_PARAMETER, NO_RATE_LIMIT, SESSION_FIXATION, IDOR_INDICATOR } from "./scanners/remediationText";
import { getComplianceRefs } from "./scanners/compliance";
import { getFixDifficulty, estimateFixMinutes } from "./scanners/fixDifficulty";
import { resolveToolConfig, type ScanProfile, type ExtendedToolName } from "./scanProfiles";
import { getCmsType } from "./scanners/fingerprint";
import { syncAssetInventory } from "./assetInventory";
import { sendCriticalAlertEmail } from "./scanAlerts";
import { sendScanCompletionEmail } from "./scanCompletionEmail";
import { autoCloseFixedFindingTickets } from "./ticketAutoClose";
import { logAuditEvent } from "./audit";
import { forwardToSiem } from "./siemIntegration";
import { runCloudPostureChecks } from "./scanners/cloudPosture";

export type ScanExecutionResult =
  | { ok: true; score: number; summary: string; report: ScanReport }
  | { ok: false; error: string };

export type ExecuteScanOptions = {
  /**
   * Which of the extended-tool suite's tools run for this scan — replaces
   * the old binary runExtendedTools:boolean flag (all 14 tools or none) with
   * a named profile. "safe" (the default) runs none of them — explicit
   * opt-in, not "on wherever the binaries happen to be installed". These
   * tools take 1-3 minutes each and need real binaries/a ZAP daemon that
   * only the GitHub Actions queue worker actually has (see
   * .github/workflows/scheduled-scans.yml) — the dashboard's synchronous
   * run-scan Function and the public API must never wait on them, so they
   * never pass anything but "safe". Each tool already degrades to
   * "not_configured" on its own when its binary/daemon is missing (see
   * src/worker/tools/*.ts), but this option means that's never load-bearing
   * for correctness — a future environment that happens to have nmap
   * installed still won't trigger it for the dashboard path. See
   * src/lib/scanProfiles.ts for the profile → tool-list mapping.
   */
  profile?: ScanProfile;
  /** Per-scan overrides on top of `profile`'s tool list — see scan_bundles. */
  toolOverrides?: Partial<Record<ExtendedToolName, boolean>>;
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
 * see docs/decisions/ENGINEERING-LOG-2026-08.md.
 */
async function runExtendedTools(
  targetUrl: string,
  githubRepo: string | null,
  authCredential: AuthCredential | null,
  detectedTechnologies: string[],
  toolConfig: Record<ExtendedToolName, boolean>
): Promise<{ extended: Record<string, unknown>; findings: Finding[]; supersedesReconSubdomains: boolean }> {
  // Each entry below is gated on toolConfig.<name> — a disabled tool
  // resolves to exactly the same "not_configured"/"not_applicable" shape
  // its own module already returns when its binary/repo/credential is
  // missing, so the ~150-line findings-derivation block after this
  // Promise.allSettled needs no changes: a profile-disabled tool is
  // indistinguishable from "not available in this environment," which
  // that code already handles correctly by pushing nothing.
  const detectedCmsType = getCmsType(
    detectedTechnologies.map((name) => ({ name, category: "", version: null, confidence: "medium" as const, source: "html" as const }))
  );

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
    trivyImageResult,
    trivyConfigResult,
    authCheckResult,
    whatwafResult,
    wpscanResult,
    cmsmapResult,
    photonResult,
    gospiderResult,
    zapAjaxSpiderResult,
    kiterunnerResult,
    arjunResult,
    sessionCheckResult,
  ] = await Promise.allSettled([
    toolConfig.nuclei
      ? runNuclei(targetUrl, detectedTechnologies)
      : Promise.resolve({ status: "not_configured" as const, findings: [] as Finding[] }),
    toolConfig.zap ? runZap(targetUrl) : Promise.resolve({ status: "not_configured" as const, alerts: [] as never[] }),
    toolConfig.sqlmap
      ? runSqlmap(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, vulnerable: false as const, findings: [] as never[] }),
    // Same "dedicated tool beyond ZAP's generic active-scan rules" precedent
    // as sqlmap above, applied to XSS and OS command injection respectively.
    toolConfig.xsser
      ? runXsser(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, vulnerable: false as const, findings: [] as never[] }),
    toolConfig.commix
      ? runCommix(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, vulnerable: false as const, findings: [] as never[] }),
    toolConfig.nmap
      ? runNmap(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, host: targetUrl, ports: [] as never[] }),
    toolConfig.subdomains
      ? runSubdomainDiscovery(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, subdomains: [] as never[], findings: [] as Finding[] }),
    toolConfig.deepTls
      ? runDeepTls(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, host: targetUrl, findings: [] as Finding[] }),
    // All five of these are only attempted when the scan owner has a row in
    // repo_connections — see sql/migrations/009_repo_connections.sql — AND
    // the resolved profile/bundle enables them. secretScan.ts/
    // dependencyManifest.ts/dockerBaseImage.ts/trivyScan.ts are pure
    // { githubRepo } functions specifically so this call site is the only
    // place that needs to know where the repo name comes from.
    toolConfig.secretScan && githubRepo
      ? scanRepositoryForSecrets({ githubRepo })
      : Promise.resolve({
          status: "not_configured" as const,
          repo: githubRepo ?? "",
          findings: [] as Finding[],
          note: githubRepo ? "Disabled by scan profile." : "No repository connected.",
        }),
    toolConfig.dependencyManifest && githubRepo
      ? scanDependencyManifest({ githubRepo })
      : Promise.resolve({
          status: "not_applicable" as const,
          repo: githubRepo ?? "",
          findings: [] as Finding[],
          note: githubRepo ? "Disabled by scan profile." : "No repository connected.",
        }),
    toolConfig.dockerBaseImage && githubRepo
      ? scanDockerBaseImage({ githubRepo })
      : Promise.resolve({
          status: "not_applicable" as const,
          repo: githubRepo ?? "",
          findings: [] as Finding[],
          note: githubRepo ? "Disabled by scan profile." : "No repository connected.",
        }),
    // Fills the real-installed-package-CVE gap dockerBaseImage.ts's own
    // header comment explicitly declines to fill (text-only tag checks,
    // not a real registry pull + package-database match).
    toolConfig.trivyImage && githubRepo
      ? scanTrivyImage({ githubRepo })
      : Promise.resolve({
          status: "not_applicable" as const,
          repo: githubRepo ?? "",
          findings: [] as Finding[],
          note: githubRepo ? "Disabled by scan profile." : "No repository connected.",
        }),
    // IaC misconfiguration scanning (Terraform/Kubernetes/Dockerfile) — no
    // existing scanner covers this at all.
    toolConfig.trivyConfig && githubRepo
      ? scanTrivyConfig({ githubRepo })
      : Promise.resolve({
          status: "not_applicable" as const,
          repo: githubRepo ?? "",
          findings: [] as Finding[],
          note: githubRepo ? "Disabled by scan profile." : "No repository connected.",
        }),
    // Sprint 3, first slice — same "pure function over an explicit input"
    // shape as the GitHub-backed checks above, so this call site is the only
    // place that needs to know where the credential comes from.
    toolConfig.authCheck
      ? checkAuthenticated(targetUrl, authCredential)
      : Promise.resolve({ status: "not_applicable" as const, note: "Disabled by scan profile." }),
    toolConfig.whatwaf
      ? runWhatWaf(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
    toolConfig.wpscan && detectedCmsType === "wordpress"
      ? runWpScanCli(targetUrl)
      : Promise.resolve({ status: "not_configured" as const, findings: [] as never[] }),
    toolConfig.cmsmap && detectedCmsType
      ? runCmsMap(targetUrl, detectedCmsType)
      : Promise.resolve({ status: "not_applicable" as const, findings: [] as never[], note: detectedCmsType ? "Disabled by scan profile." : "No CMS detected." }),
    toolConfig.photon
      ? runPhoton(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
    toolConfig.gospider
      ? runGospider(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
    toolConfig.zapAjaxSpider
      ? runZapAjaxSpider(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
    toolConfig.kiterunner
      ? runKiterunner(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
    toolConfig.arjun
      ? runArjun(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
    toolConfig.sessionCheck
      ? runSessionCheck(targetUrl)
      : Promise.resolve({ status: "not_configured" as const }),
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
    trivyImage: trivyImageResult.status === "fulfilled" ? trivyImageResult.value : { status: "error", repo: githubRepo ?? "", findings: [], note: String(trivyImageResult.reason) },
    trivyConfig: trivyConfigResult.status === "fulfilled" ? trivyConfigResult.value : { status: "error", repo: githubRepo ?? "", findings: [], note: String(trivyConfigResult.reason) },
    authCheck: authCheckResult.status === "fulfilled" ? authCheckResult.value : { status: "error" as const, note: String(authCheckResult.reason) },
    whatwaf: whatwafResult.status === "fulfilled" ? whatwafResult.value : { status: "error" as const, note: String(whatwafResult.reason) },
    wpscan: wpscanResult.status === "fulfilled" ? wpscanResult.value : { status: "error" as const, findings: [], note: String(wpscanResult.reason) },
    cmsmap: cmsmapResult.status === "fulfilled" ? cmsmapResult.value : { status: "error" as const, findings: [], note: String(cmsmapResult.reason) },
    photon: photonResult.status === "fulfilled" ? photonResult.value : { status: "error" as const, note: String(photonResult.reason) },
    gospider: gospiderResult.status === "fulfilled" ? gospiderResult.value : { status: "error" as const, note: String(gospiderResult.reason) },
    zapAjaxSpider: zapAjaxSpiderResult.status === "fulfilled" ? zapAjaxSpiderResult.value : { status: "error" as const, note: String(zapAjaxSpiderResult.reason) },
    kiterunner: kiterunnerResult.status === "fulfilled" ? kiterunnerResult.value : { status: "error" as const, note: String(kiterunnerResult.reason) },
    arjun: arjunResult.status === "fulfilled" ? arjunResult.value : { status: "error" as const, note: String(arjunResult.reason) },
    sessionCheck: sessionCheckResult.status === "fulfilled" ? sessionCheckResult.value : { status: "error" as const, note: String(sessionCheckResult.reason) },
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
  if (extended.trivyImage.status === "completed") {
    findings.push(...extended.trivyImage.findings);
  }
  if (extended.trivyConfig.status === "completed") {
    findings.push(...extended.trivyConfig.findings);
  }
  findings.push(...buildAuthenticatedFindings(extended.authCheck));

  // WAF detection findings
  if (extended.whatwaf.status === "completed") {
    const waf = extended.whatwaf as { status: "completed"; waf: string | null; vendor: string | null; confidence: number };
    if (waf.waf) {
      findings.push({
        checkId: "whatwaf.waf-detected",
        severity: "info",
        title: `[WhatWaf] WAF detected: ${waf.waf}`,
        detail: `A web application firewall (${waf.waf}${waf.vendor ? `, ${waf.vendor}` : ""}) is protecting this application. Confidence: ${waf.confidence}%.`,
      });
    } else {
      findings.push({
        checkId: "whatwaf.no-waf",
        severity: "medium",
        title: "[WhatWaf] No Web Application Firewall detected",
        detail: "No WAF was detected protecting this application. A WAF provides defence-in-depth against common web attacks.",
        remediation: WAF_NOT_DETECTED,
      });
    }
  }

  // WPScan CLI findings
  if (extended.wpscan.status === "completed" && "findings" in extended.wpscan) {
    const wpscanFindings = (extended.wpscan as { status: "completed"; findings: Array<{ type: string; title: string; detail: string; severity: string; slug?: string; cveIds?: string[]; fixedIn?: string }> }).findings;
    for (const f of wpscanFindings) {
      const slugKey = f.slug ?? f.title.replace(/\s+/g, "-").toLowerCase().slice(0, 40);
      let checkId: string;
      let remediation: string;

      if (f.title.includes("config backup")) {
        checkId = `wpscan.config-backup:${slugKey}`;
        remediation = WPSCAN_CONFIG_BACKUP;
      } else if (f.title.includes("database export")) {
        checkId = `wpscan.db-export:${slugKey}`;
        remediation = WPSCAN_DB_EXPORT;
      } else if (f.title.includes("TimThumb")) {
        checkId = `wpscan.timthumb:${slugKey}`;
        remediation = WPSCAN_TIMTHUMB;
      } else {
        checkId = `wpscan.theme-vulnerability:${slugKey}`;
        remediation = wpScanThemeVulnerabilityRemediation(f.slug ?? "unknown", f.fixedIn ?? null);
      }

      findings.push({
        checkId,
        severity: (f.severity as Finding["severity"]) || "medium",
        title: `[WPScan] ${f.title}`,
        detail: f.detail,
        remediation,
        cveIds: f.cveIds,
      });
    }
  }

  // CMSmap findings
  if (extended.cmsmap.status === "completed" && "findings" in extended.cmsmap) {
    const cmsmapFindings = (extended.cmsmap as { status: "completed"; cmsType: string; findings: Array<{ type: string; title: string; detail: string; severity: string; checkName?: string; cveIds?: string[] }> });
    for (const f of cmsmapFindings.findings) {
      const checkName = f.checkName ?? f.title.replace(/\s+/g, "-").toLowerCase().slice(0, 40);
      const checkId = f.type === "vulnerability"
        ? `cmsmap.vulnerability:${checkName}`
        : `cmsmap.misconfiguration:${checkName}`;

      findings.push({
        checkId,
        severity: (f.severity as Finding["severity"]) || "medium",
        title: f.title,
        detail: f.detail,
        remediation: f.type === "vulnerability"
          ? cmsmapVulnerabilityRemediation(cmsmapFindings.cmsType)
          : cmsmapMisconfigRemediation(cmsmapFindings.cmsType),
        cveIds: f.cveIds,
      });
    }
  }

  // Photon — OSINT URL/email/social harvesting (inventory, not vulnerabilities)
  const photonAssets: Array<{ type: string; value: string }> = [];
  if (extended.photon.status === "completed" && "assets" in extended.photon) {
    const assets = (extended.photon as { status: "completed"; assets: Array<{ type: string; value: string }> }).assets;
    photonAssets.push(...assets);
    const emails = assets.filter((a) => a.type === "email");
    const jsEndpoints = assets.filter((a) => a.type === "js-endpoint");
    if (emails.length > 0) {
      findings.push({
        checkId: `photon.emails-discovered`,
        severity: "info",
        title: `[Photon] ${emails.length} email address${emails.length > 1 ? "es" : ""} discovered`,
        detail: `Emails found on the target: ${emails.slice(0, 5).map((e) => e.value).join(", ")}${emails.length > 5 ? ` (+${emails.length - 5} more)` : ""}`,
      });
    }
    if (jsEndpoints.length > 0) {
      findings.push({
        checkId: `photon.js-endpoints-discovered`,
        severity: "info",
        title: `[Photon] ${jsEndpoints.length} JavaScript endpoint${jsEndpoints.length > 1 ? "s" : ""} extracted`,
        detail: `Endpoints extracted from JS files: ${jsEndpoints.slice(0, 5).map((e) => e.value).join(", ")}${jsEndpoints.length > 5 ? ` (+${jsEndpoints.length - 5} more)` : ""}`,
      });
    }
  }

  // Gospider — fast web crawling and JS endpoint discovery (inventory)
  const gospiderEndpoints: Array<{ type: string; value: string }> = [];
  if (extended.gospider.status === "completed" && "endpoints" in extended.gospider) {
    const endpoints = (extended.gospider as { status: "completed"; endpoints: Array<{ type: string; value: string; source: string }> }).endpoints;
    gospiderEndpoints.push(...endpoints);
    const jsEps = endpoints.filter((e) => e.type === "js-endpoint");
    const s3Refs = endpoints.filter((e) => e.type === "aws-s3");
    if (jsEps.length > 0) {
      findings.push({
        checkId: `gospider.js-endpoints-discovered`,
        severity: "info",
        title: `[Gospider] ${jsEps.length} hidden API endpoint${jsEps.length > 1 ? "s" : ""} found in JavaScript`,
        detail: `Endpoints discovered via JS analysis: ${jsEps.slice(0, 5).map((e) => e.value).join(", ")}${jsEps.length > 5 ? ` (+${jsEps.length - 5} more)` : ""}`,
      });
    }
    if (s3Refs.length > 0) {
      findings.push({
        checkId: `gospider.aws-s3-reference`,
        severity: "low",
        title: `[Gospider] ${s3Refs.length} AWS S3 reference${s3Refs.length > 1 ? "s" : ""} found`,
        detail: `S3 bucket references discovered: ${s3Refs.slice(0, 3).map((e) => e.value).join(", ")}`,
      });
    }
  }

  // ZAP AJAX Spider — JS-aware crawling discovers endpoints the traditional spider misses
  if (extended.zapAjaxSpider.status === "completed" && "urls" in extended.zapAjaxSpider) {
    const urls = (extended.zapAjaxSpider as { status: "completed"; urls: string[] }).urls;
    if (urls.length > 0) {
      findings.push({
        checkId: `zapAjaxSpider.hidden-endpoint`,
        severity: "info",
        title: `[ZAP AJAX Spider] ${urls.length} additional endpoint${urls.length > 1 ? "s" : ""} discovered`,
        detail: `The AJAX spider discovered ${urls.length} URL${urls.length > 1 ? "s" : ""} not found by the traditional spider. These may include client-side-rendered routes and API endpoints.`,
        remediation: HIDDEN_ENDPOINT_DISCOVERED,
      });
    }
  }

  // Metadata leak — checks files discovered by Photon/Gospider for metadata leakage
  const allDiscoveredFileUrls = [
    ...photonAssets.filter((a) => a.type === "url").map((a) => a.value),
    ...gospiderEndpoints.filter((e) => e.type === "url").map((e) => e.value),
  ];
  if (toolConfig.metadataLeak && allDiscoveredFileUrls.length > 0) {
    try {
      const metadataResult = await runMetadataLeakCheck(allDiscoveredFileUrls);
      (extended as Record<string, unknown>).metadataLeak = metadataResult;
      if (metadataResult.status === "completed") {
        const remediationMap: Record<string, string> = {
          email: METADATA_LEAK_EMAIL,
          "internal-ip": METADATA_LEAK_INTERNAL_IP,
          path: METADATA_LEAK_PATH,
          author: METADATA_LEAK_AUTHOR,
          software: METADATA_LEAK_SOFTWARE,
        };
        for (const f of metadataResult.findings) {
          findings.push({
            checkId: `metadataLeak.${f.type}:${f.url}`,
            severity: f.type === "internal-ip" ? "medium" : f.type === "email" ? "low" : "info",
            title: `[Metadata] ${f.type === "email" ? "Email address" : f.type === "internal-ip" ? "Internal IP address" : f.type === "path" ? "Filesystem path" : f.type === "author" ? "Author name" : "Software version"} leaked in document`,
            detail: `Found "${f.value}" in metadata of ${f.url}`,
            remediation: remediationMap[f.type],
          });
        }
      }
    } catch {
      (extended as Record<string, unknown>).metadataLeak = { status: "error", note: "Metadata check failed" };
    }
  } else {
    (extended as Record<string, unknown>).metadataLeak = { status: "not_configured" };
  }

  // Kiterunner — API endpoint brute-force discovery
  if (extended.kiterunner.status === "completed" && "endpoints" in extended.kiterunner) {
    const endpoints = (extended.kiterunner as { status: "completed"; endpoints: Array<{ method: string; path: string; statusCode: number }> }).endpoints;
    if (endpoints.length > 0) {
      findings.push({
        checkId: `kiterunner.hidden-api-endpoint`,
        severity: "medium",
        title: `[Kiterunner] ${endpoints.length} hidden API endpoint${endpoints.length > 1 ? "s" : ""} discovered`,
        detail: `Undocumented API endpoints found via wordlist brute-forcing: ${endpoints.slice(0, 5).map((e) => `${e.method} ${e.path} (${e.statusCode})`).join(", ")}${endpoints.length > 5 ? ` (+${endpoints.length - 5} more)` : ""}`,
        remediation: KITERUNNER_HIDDEN_ENDPOINT,
      });
    }
  }

  // Arjun — HTTP parameter discovery
  if (extended.arjun.status === "completed" && "parameters" in extended.arjun) {
    const params = (extended.arjun as { status: "completed"; parameters: Array<{ url: string; method: string; params: string[] }> }).parameters;
    for (const p of params) {
      if (p.params.length > 0) {
        findings.push({
          checkId: `arjun.hidden-parameter:${p.url}`,
          severity: "low",
          title: `[Arjun] ${p.params.length} hidden parameter${p.params.length > 1 ? "s" : ""} found on ${p.url}`,
          detail: `Hidden ${p.method} parameters discovered: ${p.params.join(", ")}`,
          remediation: ARJUN_HIDDEN_PARAMETER,
        });
      }
    }
  }

  // Session / business logic checks
  if (extended.sessionCheck.status === "completed" && "findings" in extended.sessionCheck) {
    const sessionFindings = (extended.sessionCheck as { status: "completed"; findings: Array<{ type: string; detail: string; url: string }> }).findings;
    const remediationMap: Record<string, string> = {
      "no-rate-limit": NO_RATE_LIMIT,
      "session-fixation": SESSION_FIXATION,
      "idor-indicator": IDOR_INDICATOR,
    };
    for (const f of sessionFindings) {
      findings.push({
        checkId: `sessionCheck.${f.type}:${f.url}`,
        severity: f.type === "idor-indicator" ? "high" : f.type === "session-fixation" ? "high" : "medium",
        title: `[Session] ${f.type === "no-rate-limit" ? "No rate limiting on login endpoint" : f.type === "session-fixation" ? "Possible session fixation" : f.type === "idor-indicator" ? "IDOR indicator detected" : f.type}`,
        detail: f.detail,
        remediation: remediationMap[f.type],
      });
    }
  }

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

  const profile: ScanProfile = options.profile ?? "safe";

  await logAuditEvent(supabaseAdmin, {
    actorId: ownerId,
    action: "scan.started",
    resourceType: "scan",
    resourceId: scanId,
    metadata: { target_url: targetUrl, scan_profile: profile },
  });

  try {
    const results = await runAllChecks(targetUrl);
    ({ findings } = summariseResults(results));

    // "safe" early-exits before any of the repo_connections/monitored_targets/
    // target_auth_credentials lookups below — preserving today's behaviour of
    // skipping those Supabase round-trips entirely for the common case (every
    // on-demand scan), rather than doing them unconditionally and letting
    // per-tool gating alone decide nothing runs.
    if (profile !== "safe") {
      const { data: repoConnection } = await supabaseAdmin
        .from("repo_connections")
        .select("github_repo")
        .eq("owner", ownerId)
        .maybeSingle();

      // target_auth_credentials is keyed by monitored_target_id, not
      // (owner, target_url) directly — a non-"safe" profile only ever
      // reaches here via the scheduled path (run-scan.ts/v1/scans.ts/
      // retest-finding.ts never set scan_profile and always pre-set scan_id,
      // so resolveScanConfig() resolves them to "safe" — see
      // run-queued-scan-jobs.ts), which always originates from a
      // monitored_targets row, so this join is real, not speculative.
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

      const toolConfig = resolveToolConfig(profile, options.toolOverrides);
      const toolOutcome = await runExtendedTools(targetUrl, repoConnection?.github_repo ?? null, authCredential, detectedTechnologies, toolConfig);
      extended = toolOutcome.extended;
      if (toolOutcome.supersedesReconSubdomains) {
        findings = findings.filter((f) => f.checkId !== "recon.subdomains-found");
      }
      findings = [...findings, ...toolOutcome.findings];
      // summariseResults() already ran its own compliance-mapping and
      // fix-difficulty passes over the base-suite findings; extended-tool
      // findings are appended after that returns, so they need the same
      // passes applied here — see src/lib/scanners/compliance.ts's and
      // fixDifficulty.ts's headers for why these are final passes over
      // checkId rather than something each push site sets itself.
      for (const finding of toolOutcome.findings) {
        const refs = getComplianceRefs(finding.checkId);
        if (refs.length > 0) finding.complianceRefs = refs;

        const difficulty = getFixDifficulty(finding.checkId);
        if (difficulty) {
          finding.fixDifficulty = difficulty;
          finding.estimatedFixMinutes = estimateFixMinutes(difficulty);
        }
      }

      // E-32: Cloud posture scanning — runs separately from runExtendedTools
      // because it needs supabaseAdmin + ownerId (not targetUrl).
      if (toolConfig.cloudPosture) {
        try {
          const cpResult = await runCloudPostureChecks(supabaseAdmin, ownerId);
          if (extended) (extended as Record<string, unknown>).cloudPosture = cpResult;
          if (cpResult.status === "checked") {
            for (const finding of cpResult.findings) {
              const refs = getComplianceRefs(finding.checkId);
              if (refs.length > 0) finding.complianceRefs = refs;
              const difficulty = getFixDifficulty(finding.checkId);
              if (difficulty) {
                finding.fixDifficulty = difficulty;
                finding.estimatedFixMinutes = estimateFixMinutes(difficulty);
              }
            }
            findings.push(...cpResult.findings);
          }
        } catch {
          if (extended) (extended as Record<string, unknown>).cloudPosture = { status: "error", note: "Cloud posture check failed" };
        }
      }
    }

    // E-55: enrich CVE-backed findings with CVSS scores from NVD (best-effort)
    try { await enrichFindingsWithCvss(findings); } catch { /* never block scan completion */ }

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

    // Best-effort, post-completion — syncAssetInventory() swallows its own
    // errors internally (see its header), so this can never flip a
    // completed scan back to failed.
    await syncAssetInventory(supabaseAdmin, ownerId, targetUrl, results, extended);
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
    await sendScanCompletionEmail(supabaseAdmin, ownerId, report);
    // Opt-in and off by default — no-ops entirely unless the owner enabled
    // auto-close on their Jira/Linear integration.
    await autoCloseFixedFindingTickets(supabaseAdmin, ownerId, report);
    await forwardToSiem(supabaseAdmin, ownerId, {
      eventType: "scan.completed",
      timestamp: new Date().toISOString(),
      actorId: ownerId,
      resourceType: "scan",
      resourceId: scanId,
      severity: score !== undefined && score < 50 ? "high" : "info",
      metadata: { targetUrl, score, findingsCount: findings.length },
    });
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
 *
 * Admins bypass the plan/subscription-status gate — same `users.is_admin`
 * precedent as freeTier.ts's isFreeTierExhausted() and ownership.ts's
 * isDomainVerified(). This was the one plan-gated path in the scan pipeline
 * that hadn't picked up that convention: an admin account (which may have
 * no subscriptions row at all, since admin access doesn't require a paid
 * plan) would otherwise silently never get a change alert, same as a real
 * Basic customer, unlike every other admin-exempt gate in this codebase.
 */
async function sendChangeAlertIfDue(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport,
  findings: { severity: string }[]
): Promise<void> {
  if (!report.new_finding_count) return; // null (no previous scan) or 0 — nothing changed

  const [{ data: sub }, { data: user }] = await Promise.all([
    supabaseAdmin.from("subscriptions").select("plan, status, slack_webhook_url, ms_teams_webhook_url").eq("owner", ownerId).maybeSingle(),
    supabaseAdmin.from("users").select("is_admin").eq("id", ownerId).maybeSingle(),
  ]);

  if (!sub) return; // nothing to send to, admin or not
  const isAdmin = Boolean(user?.is_admin);
  if (!isAdmin) {
    if (sub.status !== "active") return;
    if (sub.plan !== "pro" && sub.plan !== "agency") return;
  }
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
    dashboardUrl: process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk",
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
