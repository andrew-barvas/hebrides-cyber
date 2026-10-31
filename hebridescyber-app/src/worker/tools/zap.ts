// OWASP ZAP active scanning integration.
//
// Runs a full spider + active scan against the target and collects alerts.
// In passive-only mode (the `exposure` profile, isNonIntrusiveProfile) it
// spiders, waits for the passive scan queue to drain and reads the passive
// alerts; it never calls the active scanner, so it sends no attack payloads.
// Requires a running ZAP daemon (started by the "Start ZAP daemon" step in
// .github/workflows/scheduled-scans.yml — there is no docker-compose.yml).
// When ZAP_API_URL is not set, returns gracefully.

import type { Finding } from "../../lib/scanners/index";

const ZAP_SPIDER_POLL_MS = 5_000;
const ZAP_SPIDER_TIMEOUT_MS = 120_000;
const ZAP_ASCAN_POLL_MS = 5_000;
const ZAP_ASCAN_TIMEOUT_MS = 300_000;
const ZAP_PSCAN_POLL_MS = 2_000;
const ZAP_PSCAN_TIMEOUT_MS = 120_000;

export type ZapAlert = {
  risk: string;
  name: string;
  description: string;
  url: string;
  /** The parameter ZAP attacked, when the alert has one. */
  param?: string;
  solution: string;
  reference: string;
};

export type ZapResult =
  | { status: "completed"; alerts: ZapAlert[]; findings: Finding[] }
  | { status: "not_configured"; alerts: []; note?: string }
  | { status: "error"; alerts: []; note: string };

function zapRiskToSeverity(risk: string): Finding["severity"] {
  switch (risk.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "informational":
    case "info":
      return "info";
    default:
      return "info";
  }
}

async function zapGet<T>(
  base: string,
  path: string,
  apiKey: string
): Promise<T> {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(
    `${base}${path}${sep}apikey=${encodeURIComponent(apiKey)}`,
    { signal: AbortSignal.timeout(15_000) }
  );
  if (!res.ok) {
    throw new Error(`ZAP responded ${res.status} for ${path}`);
  }
  return res.json() as Promise<T>;
}

async function zapPost<T>(
  base: string,
  path: string,
  body: Record<string, string>,
  apiKey: string
): Promise<T> {
  const params = new URLSearchParams({ ...body, apikey: apiKey });
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    throw new Error(`ZAP responded ${res.status} for ${path}`);
  }
  return res.json() as Promise<T>;
}

async function pollUntilDone(
  base: string,
  statusPath: string,
  apiKey: string,
  intervalMs: number,
  timeoutMs: number
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const resp = await zapGet<{ status: string }>(base, statusPath, apiKey);
    if (parseInt(resp.status, 10) >= 100) return;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("ZAP scan timed out");
}

// The passive scanner works through a queue of recorded messages; its alerts
// are only complete once that queue is empty.
async function pollPassiveQueue(base: string, apiKey: string): Promise<void> {
  const deadline = Date.now() + ZAP_PSCAN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const resp = await zapGet<{ recordsToScan: string }>(base, "/JSON/pscan/view/recordsToScan/", apiKey);
    if (parseInt(resp.recordsToScan, 10) === 0) return;
    await new Promise((r) => setTimeout(r, ZAP_PSCAN_POLL_MS));
  }
  throw new Error("ZAP passive scan timed out");
}

export type ZapOptions = {
  /** Spider and passive rules only: no active scan, no test payloads. */
  passiveOnly?: boolean;
};

export async function runZap(targetUrl: string, options: ZapOptions = {}): Promise<ZapResult> {
  const zapApiUrl = process.env.ZAP_API_URL;
  const zapApiKey = process.env.ZAP_API_KEY;

  if (!zapApiUrl) {
    return { status: "not_configured", alerts: [] };
  }

  if (!zapApiKey) {
    return { status: "not_configured", alerts: [], note: "ZAP_API_KEY is not set — skipping ZAP scan" };
  }

  try {
    // --- Spider scan --------------------------------------------------------
    const spiderResp = await zapPost<{ scan: string }>(
      zapApiUrl,
      "/JSON/spider/action/scan/",
      { url: targetUrl },
      zapApiKey
    );
    const spiderScanId = spiderResp.scan;

    await pollUntilDone(
      zapApiUrl,
      `/JSON/spider/view/status/?scanId=${encodeURIComponent(spiderScanId)}`,
      zapApiKey,
      ZAP_SPIDER_POLL_MS,
      ZAP_SPIDER_TIMEOUT_MS
    );

    if (options.passiveOnly) {
      // --- Passive scan only ------------------------------------------------
      await pollPassiveQueue(zapApiUrl, zapApiKey);
    } else {
      // --- Active scan ------------------------------------------------------
      const ascanResp = await zapPost<{ scan: string }>(
        zapApiUrl,
        "/JSON/ascan/action/scan/",
        { url: targetUrl },
        zapApiKey
      );
      const ascanScanId = ascanResp.scan;

      await pollUntilDone(
        zapApiUrl,
        `/JSON/ascan/view/status/?scanId=${encodeURIComponent(ascanScanId)}`,
        zapApiKey,
        ZAP_ASCAN_POLL_MS,
        ZAP_ASCAN_TIMEOUT_MS
      );
    }

    // --- Collect alerts -----------------------------------------------------
    const alertsResp = await zapGet<{ alerts: ZapAlert[] }>(
      zapApiUrl,
      `/JSON/core/view/alerts/?baseurl=${encodeURIComponent(targetUrl)}`,
      zapApiKey
    );

    const alerts: ZapAlert[] = alertsResp.alerts ?? [];

    // alert.solution is ZAP's own real, evidenced fix guidance for this
    // specific alert type — used directly as remediation rather than
    // duplicated as static text, unlike nuclei/sqlmap/nmap (see
    // remediationText.ts's header comment on the extended tool suite).
    const findings: Finding[] = alerts.map((alert) => ({
      checkId: `zap.alert:${alert.name}`,
      severity: zapRiskToSeverity(alert.risk),
      title: `[ZAP] ${alert.name}`,
      detail: alert.description ?? alert.solution ?? "No additional detail.",
      remediation: alert.solution || undefined,
      // Lets proofOfExploit.ts re-check a reflected-XSS alert with one harmless probe.
      ...(alert.url && alert.param ? { metadata: { url: alert.url, parameter: alert.param } } : {}),
    }));

    return { status: "completed", alerts, findings };
  } catch (err) {
    return {
      status: "error",
      alerts: [],
      note: `ZAP scan failed: ${(err as Error).message}`,
    };
  }
}
