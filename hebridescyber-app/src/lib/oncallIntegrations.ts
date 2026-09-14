// E-54: PagerDuty / Opsgenie alert integration — extends the ticket_
// integrations pattern to on-call alerting. Creates incidents for critical
// findings and resolves them when findings are marked fixed.
//
// Same credential-save-and-validate pattern as ticketIntegrations.ts:
// validate before saving, one row per owner+provider in ticket_integrations.

const REQUEST_TIMEOUT_MS = 10_000;

export type AlertResult =
  | { ok: true; alertId: string; url: string }
  | { ok: false; error: string };

export type AlertState = "triggered" | "resolved" | "missing" | "unknown";

// ---- PagerDuty Events API v2 -----------------------------------------------

export async function validatePagerDutyKey(routingKey: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: "trigger",
        payload: {
          summary: "Hebrides Cyber — integration test (safe to resolve)",
          source: "hebridescyber.co.uk",
          severity: "info",
        },
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) {
      const body = await res.text();
      return { ok: false, error: `PagerDuty returned ${res.status}: ${body.slice(0, 200)}` };
    }
    const body = (await res.json()) as { dedup_key?: string };
    if (body.dedup_key) {
      // Immediately resolve the test incident
      await fetch("https://events.pagerduty.com/v2/enqueue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          routing_key: routingKey,
          event_action: "resolve",
          dedup_key: body.dedup_key,
        }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      }).catch(() => {});
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export async function createPagerDutyIncident(
  routingKey: string,
  opts: { dedupKey: string; summary: string; severity: string; sourceUrl: string; detailsUrl: string }
): Promise<AlertResult> {
  try {
    const pdSeverity = opts.severity === "critical" ? "critical" : opts.severity === "high" ? "error" : "warning";
    const res = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: "trigger",
        dedup_key: opts.dedupKey,
        payload: {
          summary: opts.summary,
          source: opts.sourceUrl,
          severity: pdSeverity,
          custom_details: { dashboard: opts.detailsUrl },
        },
        links: [{ href: opts.detailsUrl, text: "View in Hebrides Cyber" }],
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `PagerDuty ${res.status}` };
    const body = (await res.json()) as { dedup_key?: string };
    return { ok: true, alertId: body.dedup_key ?? opts.dedupKey, url: "https://app.pagerduty.com" };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export async function resolvePagerDutyIncident(routingKey: string, dedupKey: string): Promise<boolean> {
  try {
    const res = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: "resolve",
        dedup_key: dedupKey,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ---- Opsgenie Alert API ----------------------------------------------------

export async function validateOpsgenieKey(apiKey: string, region: "us" | "eu" = "us"): Promise<{ ok: boolean; error?: string }> {
  const baseUrl = region === "eu" ? "https://api.eu.opsgenie.com" : "https://api.opsgenie.com";
  try {
    const res = await fetch(`${baseUrl}/v2/heartbeats`, {
      headers: { Authorization: `GenieKey ${apiKey}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, error: "Invalid or expired Opsgenie API key" };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export async function createOpsgenieAlert(
  apiKey: string,
  region: "us" | "eu",
  opts: { alias: string; message: string; description: string; priority: string; sourceUrl: string }
): Promise<AlertResult> {
  const baseUrl = region === "eu" ? "https://api.eu.opsgenie.com" : "https://api.opsgenie.com";
  const ogPriority = opts.priority === "critical" ? "P1" : opts.priority === "high" ? "P2" : "P3";
  try {
    const res = await fetch(`${baseUrl}/v2/alerts`, {
      method: "POST",
      headers: { Authorization: `GenieKey ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        message: opts.message,
        alias: opts.alias,
        description: opts.description,
        priority: ogPriority,
        source: "Hebrides Cyber",
        tags: ["security", "scan-finding"],
        details: { dashboard_url: opts.sourceUrl },
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `Opsgenie ${res.status}` };
    const body = (await res.json()) as { requestId?: string };
    return { ok: true, alertId: opts.alias, url: `${baseUrl.replace("api.", "app.")}/alert/detail/${opts.alias}` };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export async function resolveOpsgenieAlert(apiKey: string, region: "us" | "eu", alias: string): Promise<boolean> {
  const baseUrl = region === "eu" ? "https://api.eu.opsgenie.com" : "https://api.opsgenie.com";
  try {
    const res = await fetch(`${baseUrl}/v2/alerts/${encodeURIComponent(alias)}/close?identifierType=alias`, {
      method: "POST",
      headers: { Authorization: `GenieKey ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ source: "Hebrides Cyber", note: "Finding verified as fixed" }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}
