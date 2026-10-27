// What the dashboard needs from an uptime monitor, independent of who runs it.
// Phase 1 has one implementation (uptimeRobot.ts, the customer's own
// UptimeRobot account); a native Hebrides checker can implement the same
// interface later without touching the UI or the sync script.
//
// Statuses are deliberately conservative. "unknown" is what we report when the
// provider didn't say, said something we don't recognise, or couldn't be
// reached: never "up". An alert is only ever raised on a clear "down", and a
// failed lookup never changes a stored status (CLAUDE.md rule 7).

export type UptimeStatus = "up" | "down" | "seems_down" | "paused" | "unknown";

export type UptimeMonitor = {
  /** The provider's own id for the monitor, as a string. */
  externalId: string;
  name: string;
  url: string | null;
  status: UptimeStatus;
  /** How long the monitor has been in its current status, when the provider says. */
  stateDurationSeconds: number | null;
};

export type ProviderErrorKind = "auth" | "rate_limited" | "unavailable" | "invalid";

export type ProviderResult<T> =
  | { ok: true; value: T }
  | { ok: false; kind: ProviderErrorKind; error: string; retryAfterSeconds?: number };

export interface UptimeProvider {
  readonly id: "uptimerobot";
  /** Cheap authenticated call proving the stored key works. */
  validate(): Promise<ProviderResult<true>>;
  listMonitors(): Promise<ProviderResult<UptimeMonitor[]>>;
  createMonitor(input: { url: string; name: string }): Promise<ProviderResult<UptimeMonitor>>;
}

/** Compare monitor URLs the way a person would: case-insensitive host, no trailing slash, no fragment. */
export function normaliseMonitorUrl(raw: string): string | null {
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    u.hash = "";
    const path = u.pathname.replace(/\/+$/, "");
    return `${u.protocol}//${u.host.toLowerCase()}${path}${u.search}`;
  } catch {
    return null;
  }
}
