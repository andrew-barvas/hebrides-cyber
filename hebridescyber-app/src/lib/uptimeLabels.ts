// Plain-language labels for an uptime monitor's status, shared by the
// Integrations card (UptimeMonitoringConfig) and the monitored-sites list
// (MonitoredTargets) so the two never describe the same monitor differently.
import type { UptimeStatus } from "./uptimeProvider";

export type UptimeLabel = { text: string; className: string };

const STATUS_LABEL: Record<UptimeStatus, UptimeLabel> = {
  up: { text: "Up", className: "text-neon" },
  down: { text: "Down", className: "text-danger" },
  seems_down: { text: "Seems down", className: "text-warning" },
  paused: { text: "Paused", className: "text-cybermuted" },
  unknown: { text: "Waiting for first check", className: "text-cybermuted" },
};

// A stale status must not read as current: say we can't see it instead.
const MISSING_LABEL: UptimeLabel = { text: "Not found in UptimeRobot", className: "text-warning" };

/** `missing`: the last sync did not find the monitor, so `status` is stale and is not shown. */
export function uptimeStatusLabel(status: UptimeStatus | null | undefined, missing = false): UptimeLabel {
  if (missing) return MISSING_LABEL;
  return STATUS_LABEL[status ?? "unknown"] ?? STATUS_LABEL.unknown;
}
