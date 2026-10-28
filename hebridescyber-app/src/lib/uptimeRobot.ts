// UptimeRobot API v3 client for the "bring your own account" uptime offering.
//
// Each customer connects THEIR OWN UptimeRobot account; we create and read
// monitors there and show the result in the dashboard. That is deliberate:
// UptimeRobot's terms bar repackaging or white-labelling its monitoring as
// someone else's service and bar extra accounts to dodge the per-account
// monitor cap, so a single shared Hebrides account is not an option without a
// separate commercial agreement (docs/ARCHITECTURE-NOTES.md, "Uptime monitoring").
//
// Written against UptimeRobot's published OpenAPI spec
// (https://cdn.uptimerobot.com/api/openapi.yaml, read 2026-10-23):
//   base URL     https://api.uptimerobot.com/v3, `Authorization: Bearer <token>`
//   GET /user/me                                  account details
//   GET /monitors?limit&cursor                    { data: Monitor[], nextLink }
//   POST /monitors { type:"HTTP", friendlyName, url, interval (s), timeout (s) }
//   Monitor.status filter values: PAUSED STARTED UP LOOKS_DOWN DOWN
//   Free plan: 10 requests/minute, 429 with Retry-After.
// NOT yet confirmed against a real account: that a dashboard API key is
// accepted as the bearer token, and the exact MonitorDto.status strings. Both
// are covered below by treating anything unexpected as "unknown"/"auth" rather
// than guessing, and the owner check in the rollout plan exercises them.
//
// Never throws; every call has a timeout; a failed or malformed response is an
// error result, never an empty "all monitors up".
import type { ProviderResult, UptimeMonitor, UptimeProvider, UptimeStatus } from "./uptimeProvider";

export const UPTIMEROBOT_API_BASE = "https://api.uptimerobot.com/v3";
const REQUEST_TIMEOUT_MS = 10_000;
/** Free plans can only check every 5 minutes; the API rejects anything shorter. */
export const UPTIMEROBOT_DEFAULT_INTERVAL_SECONDS = 300;
const MONITOR_TIMEOUT_SECONDS = 30;
const PAGE_SIZE = 200;
/** Pages to follow per list call: 3 x 200 monitors is far above any plan's cap, and each page costs one of 10 requests/minute. */
const MAX_PAGES = 3;

/** Map UptimeRobot's status strings; anything unrecognised is "unknown", never "up". */
export function mapUptimeRobotStatus(raw: unknown): UptimeStatus {
  switch (typeof raw === "string" ? raw.trim().toUpperCase() : "") {
    case "UP":
      return "up";
    case "DOWN":
      return "down";
    case "LOOKS_DOWN":
      return "seems_down";
    case "PAUSED":
      return "paused";
    default:
      // Includes STARTED (just created, no check result yet) and anything new.
      return "unknown";
  }
}

/** Turn a raw MonitorDto into ours, or null when it has no usable id. */
export function parseUptimeRobotMonitor(raw: unknown): UptimeMonitor | null {
  if (!raw || typeof raw !== "object") return null;
  const m = raw as Record<string, unknown>;
  const id = typeof m.id === "number" || typeof m.id === "string" ? String(m.id) : "";
  if (!id) return null;
  return {
    externalId: id,
    name: typeof m.friendlyName === "string" ? m.friendlyName : "",
    url: typeof m.url === "string" ? m.url : null,
    status: mapUptimeRobotStatus(m.status),
    stateDurationSeconds: typeof m.currentStateDuration === "number" && m.currentStateDuration >= 0 ? Math.floor(m.currentStateDuration) : null,
  };
}

type Fail = Extract<ProviderResult<never>, { ok: false }>;

function failFromStatus(status: number, res: Response): Fail {
  if (status === 401 || status === 403) return { ok: false, kind: "auth", error: "UptimeRobot rejected this API key." };
  if (status === 429) {
    const retry = Number(res.headers.get("retry-after"));
    return { ok: false, kind: "rate_limited", error: "UptimeRobot rate limit reached; try again shortly.", retryAfterSeconds: Number.isFinite(retry) && retry > 0 ? retry : 60 };
  }
  if (status >= 400 && status < 500) return { ok: false, kind: "invalid", error: `UptimeRobot refused the request (${status}).` };
  return { ok: false, kind: "unavailable", error: `UptimeRobot returned ${status}.` };
}

async function call(apiKey: string, path: string, init: { method?: "GET" | "POST"; body?: unknown } = {}): Promise<ProviderResult<{ json: unknown }>> {
  try {
    const res = await fetch(path.startsWith("http") ? path : `${UPTIMEROBOT_API_BASE}${path}`, {
      method: init.method ?? "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json",
        ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return failFromStatus(res.status, res);
    try {
      return { ok: true, value: { json: await res.json() } };
    } catch {
      return { ok: false, kind: "unavailable", error: "UptimeRobot returned a response that is not JSON." };
    }
  } catch (err) {
    return { ok: false, kind: "unavailable", error: `Could not reach UptimeRobot: ${(err as Error).message}` };
  }
}

/** Only ever send the key to UptimeRobot's own API host (a `nextLink` is untrusted input). */
export function isUptimeRobotApiUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && u.host === new URL(UPTIMEROBOT_API_BASE).host;
  } catch {
    return false;
  }
}

export function uptimeRobotProvider(apiKey: string): UptimeProvider {
  return {
    id: "uptimerobot",

    async validate() {
      const r = await call(apiKey, "/user/me");
      return r.ok ? { ok: true, value: true } : r;
    },

    async listMonitors() {
      const monitors: UptimeMonitor[] = [];
      let next: string | null = `/monitors?limit=${PAGE_SIZE}`;
      for (let page = 0; next && page < MAX_PAGES; page++) {
        const r = await call(apiKey, next);
        if (!r.ok) return r;
        const body = r.value.json as { data?: unknown; nextLink?: unknown } | null;
        if (!body || !Array.isArray(body.data)) {
          return { ok: false, kind: "unavailable", error: "UptimeRobot returned an unexpected monitor list." };
        }
        for (const raw of body.data) {
          const parsed = parseUptimeRobotMonitor(raw);
          if (parsed) monitors.push(parsed);
        }
        const link: unknown = body.nextLink;
        if (typeof link === "string" && link) {
          if (link.startsWith("http")) {
            if (!isUptimeRobotApiUrl(link)) return { ok: false, kind: "unavailable", error: "UptimeRobot pagination pointed somewhere unexpected; stopped." };
            next = link;
          } else {
            next = link.startsWith("/") ? link : `/monitors?limit=${PAGE_SIZE}&cursor=${encodeURIComponent(link)}`;
          }
        } else {
          next = null;
        }
      }
      return { ok: true, value: monitors };
    },

    async createMonitor({ url, name }) {
      const r = await call(apiKey, "/monitors", {
        method: "POST",
        body: { type: "HTTP", friendlyName: name.slice(0, 120), url, interval: UPTIMEROBOT_DEFAULT_INTERVAL_SECONDS, timeout: MONITOR_TIMEOUT_SECONDS },
      });
      if (!r.ok) return r;
      const monitor = parseUptimeRobotMonitor(r.value.json);
      if (!monitor) return { ok: false, kind: "unavailable", error: "UptimeRobot created a monitor but returned no id." };
      return { ok: true, value: monitor };
    },
  };
}
