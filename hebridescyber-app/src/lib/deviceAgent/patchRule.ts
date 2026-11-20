// The Cyber Essentials 14-day patch rule, evaluated for one device.
//
// The requirement (NCSC Cyber Essentials, "Security update management"):
// software must be licensed and supported, and updates the vendor rates
// critical or high risk, or that fix vulnerabilities with a CVSS v3 score of
// 7 or more, must be installed within 14 days of release. Unsupported
// software must be removed (or segregated out of scope).
//
// Pure: everything it needs is passed in, so the 14-day arithmetic, the
// "unknown is not clean" rule and each source's evidence are unit-tested
// without a database.
//
// EVIDENCE RULES
// - A device only "passes" when the update source was read
//   (pending_updates_checked) and, if a CVE match ran, it completed. Anything
//   less is "unknown", never "passes" (CLAUDE.md rule 7).
// - "fails" needs evidence of an overdue item; that wins over "unknown"
//   because it is true whatever the missing source would have said.
// - A pending update with no vendor release date is aged from the day this
//   device first reported it. That understates its age (it may have been
//   released earlier) and the dashboard says so.
import type { DeviceInventory, InventoryPendingUpdate } from "./inventorySchema";
import type { DeviceMatch } from "./matching";

export const PATCH_WINDOW_DAYS = 14;
/** A device that hasn't reported for this long is shown as stale. */
export const STALE_AFTER_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

export type PatchStatus = "passes" | "at_risk" | "fails" | "unknown";

export type PatchItem = {
  kind: "pending_update" | "cve" | "unsupported_os";
  /** Stable key: update id, CVE id + software, or "os". */
  key: string;
  title: string;
  /** Software or update the item is about. */
  subject: string;
  severity: string | null;
  /** YYYY-MM-DD the 14 days run from. */
  since: string | null;
  /** How `since` was established. */
  sinceBasis: "vendor_release" | "first_reported" | "cve_published" | "end_of_life" | null;
  /** YYYY-MM-DD the 14-day window closes (since + 14). */
  dueBy: string | null;
  overdue: boolean;
  detail: string | null;
};

export type PatchEvaluation = {
  status: PatchStatus;
  summary: string;
  overdue: PatchItem[];
  dueSoon: PatchItem[];
  /** Why the result isn't complete, when it isn't. */
  gaps: string[];
  /** The pending_first_seen map to store back on the device. */
  pendingFirstSeen: Record<string, string>;
  evaluatedAt: string;
  counts: { software: number; pendingUpdates: number; securityUpdates: number; cves: number };
};

const ymd = (d: Date) => d.toISOString().slice(0, 10);
const addDays = (iso: string, days: number) => ymd(new Date(Date.parse(`${iso}T00:00:00Z`) + days * DAY_MS));

/** Does this pending update fall under the 14-day rule? */
export function isInScopeUpdate(u: Pick<InventoryPendingUpdate, "security" | "severity">): boolean {
  return u.security || u.severity === "critical" || u.severity === "important";
}

/**
 * Carries forward the first-reported date of each pending update still
 * pending, adds today for new ones, and drops ones no longer pending.
 */
export function nextPendingFirstSeen(previous: Record<string, string>, pending: InventoryPendingUpdate[], now: Date): Record<string, string> {
  const today = ymd(now);
  const next: Record<string, string> = {};
  for (const u of pending) {
    const key = `${u.source}:${u.id}`;
    const prior = previous[key];
    next[key] = typeof prior === "string" && /^\d{4}-\d{2}-\d{2}$/.test(prior) && prior <= today ? prior : today;
  }
  return next;
}

function windowItem(base: Omit<PatchItem, "dueBy" | "overdue">, now: Date): PatchItem {
  if (!base.since) return { ...base, dueBy: null, overdue: false };
  const dueBy = addDays(base.since, PATCH_WINDOW_DAYS);
  return { ...base, dueBy, overdue: dueBy < ymd(now) };
}

export type EvaluateInput = {
  inventory: DeviceInventory;
  previousFirstSeen: Record<string, string>;
  /** Latest CVE / end-of-life match, or null when none has run yet. */
  match: DeviceMatch | null;
  now: Date;
};

export function evaluatePatchRule({ inventory, previousFirstSeen, match, now }: EvaluateInput): PatchEvaluation {
  const pendingFirstSeen = nextPendingFirstSeen(previousFirstSeen, inventory.pending_updates, now);
  const items: PatchItem[] = [];
  const gaps: string[] = [];

  // 1. Pending updates the vendor classes as security / critical / important.
  const security = inventory.pending_updates.filter(isInScopeUpdate);
  for (const u of security) {
    const released = u.released_at || null;
    const firstSeen = pendingFirstSeen[`${u.source}:${u.id}`] ?? null;
    const since = released ?? firstSeen;
    items.push(
      windowItem(
        {
          kind: "pending_update",
          key: `${u.source}:${u.id}`,
          title: u.title || u.id,
          subject: u.id,
          severity: u.severity || (u.security ? "security" : null),
          since,
          sinceBasis: released ? "vendor_release" : "first_reported",
          detail: u.version ? `Update available: ${u.version}` : null,
        },
        now
      )
    );
  }
  if (!inventory.pending_updates_checked) {
    gaps.push("The device couldn't read its update source, so pending updates are unknown.");
  }
  if (!inventory.software_checked) {
    gaps.push("The device couldn't list its installed software.");
  }
  if (inventory.truncated) {
    gaps.push("The device has more software or updates than one report holds; some were left out.");
  }

  // 2. CVE matches and end of life, once the matching job has run.
  if (!match) {
    gaps.push("CVE and end-of-life matching hasn't run on this report yet.");
  } else {
    gaps.push(...match.notes);
    for (const c of match.cves) {
      // In scope: CVSS >= 7 (or a vendor high/critical rating), with a fix
      // that exists. With no fix there is nothing to install within 14 days.
      const high = (c.cvssScore ?? 0) >= 7 || c.severity === "high" || c.severity === "critical";
      if (!high || c.fixAvailable !== true) continue;
      const since = c.publishedAt ? c.publishedAt.slice(0, 10) : null;
      items.push(
        windowItem(
          {
            kind: "cve",
            key: `${c.id}:${c.software}`,
            title: `${c.id} in ${c.software} ${c.version}`,
            subject: c.software,
            severity: c.cvssScore !== null ? `CVSS ${c.cvssScore.toFixed(1)}` : c.severity,
            since,
            sinceBasis: since ? "cve_published" : null,
            detail: c.fixedVersion ? `Fixed in ${c.fixedVersion}` : c.summary,
          },
          now
        )
      );
    }
    if (match.osEol?.state === "unsupported") {
      items.push({
        kind: "unsupported_os",
        key: "os",
        title: `${inventory.os.name || inventory.os.family} ${match.osEol.cycle} is no longer supported`,
        subject: inventory.os.name || inventory.os.family,
        severity: "unsupported",
        since: match.osEol.eolDate,
        sinceBasis: match.osEol.eolDate ? "end_of_life" : null,
        dueBy: match.osEol.eolDate,
        overdue: true,
        detail: "Cyber Essentials requires supported software: upgrade the operating system or take the device out of scope.",
      });
    }
  }

  const overdue = items.filter((i) => i.overdue);
  const dueSoon = items.filter((i) => !i.overdue);
  const complete = inventory.pending_updates_checked && inventory.software_checked && match !== null && match.status === "checked";

  let status: PatchStatus;
  if (overdue.length > 0) status = "fails";
  else if (!inventory.pending_updates_checked) status = "unknown";
  else if (dueSoon.length > 0) status = "at_risk";
  else if (complete) status = "passes";
  else status = "unknown";

  return {
    status,
    summary: summarise(status, overdue.length, dueSoon),
    overdue,
    dueSoon,
    gaps,
    pendingFirstSeen,
    evaluatedAt: now.toISOString(),
    counts: {
      software: inventory.software.length,
      pendingUpdates: inventory.pending_updates.length,
      securityUpdates: security.length,
      cves: match?.cves.length ?? 0,
    },
  };
}

function summarise(status: PatchStatus, overdueCount: number, dueSoon: PatchItem[]): string {
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  switch (status) {
    case "fails":
      return `Misses the 14-day rule: ${plural(overdueCount, "item")} overdue.`;
    case "at_risk": {
      const next = dueSoon.map((i) => i.dueBy).filter((d): d is string => !!d).sort()[0];
      return `${plural(dueSoon.length, "security update")} to install${next ? ` by ${next}` : ""}.`;
    }
    case "passes":
      return "Meets the 14-day rule on this report.";
    default:
      return "Not enough evidence to say: see what's missing.";
  }
}

/**
 * The status to show for a device, given when it last reported. A device
 * that stopped reporting has no current evidence either way.
 */
export function displayStatus(stored: string, lastSeenAt: string | null, now: Date): PatchStatus | "never_reported" | "stale" {
  if (!lastSeenAt) return "never_reported";
  if (now.getTime() - Date.parse(lastSeenAt) > STALE_AFTER_DAYS * DAY_MS) return "stale";
  return (["passes", "at_risk", "fails", "unknown"] as const).find((s) => s === stored) ?? "unknown";
}
