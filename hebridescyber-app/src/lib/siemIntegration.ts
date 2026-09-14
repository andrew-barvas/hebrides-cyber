// SIEM integration — forward audit events and scan findings to external
// SIEM/log aggregation systems. Supports webhook (JSON/CEF/LEEF) delivery.
//
// Called from scanExecution.ts after scan completion and from audit.ts
// for security-relevant events. Best-effort — never blocks the action
// it's forwarding.

import type { SupabaseClient } from "@supabase/supabase-js";

const REQUEST_TIMEOUT_MS = 10_000;

export type SiemEventType = "scan.completed" | "scan.failed" | "finding.new" | "finding.fixed" |
  "user.login" | "user.logout" | "api_key.created" | "api_key.revoked" |
  "team.member_added" | "team.member_removed" | "settings.changed";

export type SiemPayload = {
  eventType: SiemEventType | string;
  timestamp: string;
  actorId?: string | null;
  actorEmail?: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  severity?: string;
  metadata?: Record<string, unknown>;
};

type SiemConfig = {
  id: string;
  type: "webhook" | "syslog";
  endpoint: string;
  auth_header: string | null;
  format: "json" | "cef" | "leef";
  event_types: string[];
};

function formatCef(payload: SiemPayload): string {
  const severity = payload.severity === "critical" ? 10 : payload.severity === "high" ? 7 :
    payload.severity === "medium" ? 4 : 1;
  const ext = [
    payload.actorId ? `suid=${payload.actorId}` : "",
    payload.actorEmail ? `suser=${payload.actorEmail}` : "",
    payload.resourceId ? `cs1=${payload.resourceId}` : "",
    `msg=${payload.eventType}`,
  ].filter(Boolean).join(" ");
  return `CEF:0|HebridesСyber|Scanner|1.0|${payload.eventType}|${payload.eventType}|${severity}|${ext}`;
}

function formatLeef(payload: SiemPayload): string {
  const fields = [
    `devTime=${payload.timestamp}`,
    payload.actorId ? `usrName=${payload.actorId}` : "",
    payload.actorEmail ? `identSrc=${payload.actorEmail}` : "",
    payload.resourceId ? `objectName=${payload.resourceId}` : "",
    payload.severity ? `sev=${payload.severity}` : "",
  ].filter(Boolean).join("\t");
  return `LEEF:2.0|HebridesСyber|Scanner|1.0|${payload.eventType}|${fields}`;
}

async function sendWebhook(config: SiemConfig, payload: SiemPayload): Promise<{ ok: boolean; error?: string }> {
  let body: string;
  let contentType: string;

  switch (config.format) {
    case "cef":
      body = formatCef(payload);
      contentType = "text/plain";
      break;
    case "leef":
      body = formatLeef(payload);
      contentType = "text/plain";
      break;
    default:
      body = JSON.stringify(payload);
      contentType = "application/json";
  }

  const headers: Record<string, string> = { "Content-Type": contentType };
  if (config.auth_header) headers["Authorization"] = config.auth_header;

  try {
    const res = await fetch(config.endpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

/**
 * Forward an event to all enabled SIEM integrations for the given owner.
 * Best-effort: logs errors but never throws.
 */
export async function forwardToSiem(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  payload: SiemPayload,
): Promise<void> {
  try {
    const { data: integrations } = await supabaseAdmin
      .from("siem_integrations")
      .select("id, type, endpoint, auth_header, format, event_types")
      .eq("owner", ownerId)
      .eq("enabled", true);

    if (!integrations || integrations.length === 0) return;

    for (const config of integrations as SiemConfig[]) {
      if (!config.event_types.includes(payload.eventType)) continue;

      if (config.type === "webhook") {
        const result = await sendWebhook(config, payload);
        if (!result.ok) {
          console.error(`[siem] webhook ${config.id} failed: ${result.error}`);
          await supabaseAdmin
            .from("siem_integrations")
            .update({ last_error: result.error, updated_at: new Date().toISOString() })
            .eq("id", config.id);
        } else {
          await supabaseAdmin
            .from("siem_integrations")
            .update({ last_sent: new Date().toISOString(), last_error: null, updated_at: new Date().toISOString() })
            .eq("id", config.id);
        }
      }
      // syslog type: future — needs UDP/TCP socket, not fetch
    }
  } catch (err) {
    console.error("[siem] forwardToSiem threw:", (err as Error).message);
  }
}

/**
 * Validate a SIEM webhook endpoint by sending a test event.
 */
export async function validateSiemWebhook(
  endpoint: string,
  authHeader: string | null,
  format: "json" | "cef" | "leef",
): Promise<{ ok: boolean; error?: string }> {
  const testPayload: SiemPayload = {
    eventType: "test.connection",
    timestamp: new Date().toISOString(),
    metadata: { source: "hebridescyber", test: true },
  };
  return sendWebhook(
    { id: "test", type: "webhook", endpoint, auth_header: authHeader, format, event_types: [] },
    testPayload,
  );
}
