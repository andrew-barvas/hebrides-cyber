// Pure helpers for agency client workspaces: grouping sites under clients and
// rolling their latest results up into one line per client. Kept free of
// React and Supabase so the grouping rules are unit-testable.

/** The switcher's selection: every client, the sites with no client, or one client. */
export type ClientScope = "all" | "unassigned" | (string & {});

export const SCOPE_ALL: ClientScope = "all";
export const SCOPE_UNASSIGNED: ClientScope = "unassigned";

export type ClientSummary = { id: string; name: string };

export type SiteRow = {
  targetId: string;
  targetUrl: string;
  clientId: string | null;
  latestScore: number | null;
  lastScannedAt: string | null;
  /** Open (non-info) findings on the latest scan; null when never scanned. */
  openFindingsCount: number | null;
  /** Open critical findings on the latest scan; null when never scanned. */
  openCriticalCount?: number | null;
};

export type ClientGroup<T extends SiteRow = SiteRow> = {
  /** null = the "Unassigned" group. */
  clientId: string | null;
  name: string;
  sites: T[];
  /** Mean of the sites' latest scores, rounded; null when none has been scanned. */
  rollupScore: number | null;
  openFindings: number;
  openCriticals: number;
  lastScannedAt: string | null;
};

export const UNASSIGNED_NAME = "Unassigned";

/** Accepts only the scope strings the switcher can produce; anything else falls back to "all". */
export function parseScope(raw: string | null | undefined, clients: ClientSummary[]): ClientScope {
  if (!raw || raw === SCOPE_ALL) return SCOPE_ALL;
  if (raw === SCOPE_UNASSIGNED) return SCOPE_UNASSIGNED;
  return clients.some((c) => c.id === raw) ? raw : SCOPE_ALL;
}

/** Does a row with this client_id belong in the selected scope? */
export function inScope(clientId: string | null | undefined, scope: ClientScope): boolean {
  if (scope === SCOPE_ALL) return true;
  if (scope === SCOPE_UNASSIGNED) return !clientId;
  return clientId === scope;
}

export function filterByScope<T extends { clientId: string | null }>(rows: T[], scope: ClientScope): T[] {
  return rows.filter((r) => inScope(r.clientId, scope));
}

/** Mean of the non-null scores, rounded to a whole number; null if there are none. */
export function rollupScore(scores: (number | null)[]): number | null {
  const real = scores.filter((s): s is number => typeof s === "number");
  if (real.length === 0) return null;
  return Math.round(real.reduce((a, b) => a + b, 0) / real.length);
}

function latestOf(dates: (string | null)[]): string | null {
  let best: string | null = null;
  for (const d of dates) {
    if (d && (best === null || new Date(d).getTime() > new Date(best).getTime())) best = d;
  }
  return best;
}

function summarise<T extends SiteRow>(clientId: string | null, name: string, sites: T[]): ClientGroup<T> {
  return {
    clientId,
    name,
    sites,
    rollupScore: rollupScore(sites.map((s) => s.latestScore)),
    openFindings: sites.reduce((n, s) => n + (s.openFindingsCount ?? 0), 0),
    openCriticals: sites.reduce((n, s) => n + (s.openCriticalCount ?? 0), 0),
    lastScannedAt: latestOf(sites.map((s) => s.lastScannedAt)),
  };
}

/**
 * One group per client (including clients with no sites yet), ordered worst
 * roll-up first with unscanned clients last, then "Unassigned" at the end when
 * any site has no client. A site pointing at a client that no longer exists
 * counts as unassigned.
 */
export function groupByClient<T extends SiteRow>(sites: T[], clients: ClientSummary[]): ClientGroup<T>[] {
  const known = new Set(clients.map((c) => c.id));
  const byClient = new Map<string, T[]>();
  const loose: T[] = [];
  for (const s of sites) {
    if (s.clientId && known.has(s.clientId)) {
      const list = byClient.get(s.clientId) ?? [];
      list.push(s);
      byClient.set(s.clientId, list);
    } else {
      loose.push(s);
    }
  }
  const groups = clients.map((c) => summarise(c.id, c.name, byClient.get(c.id) ?? []));
  groups.sort((a, b) => {
    if (a.rollupScore === null && b.rollupScore === null) return a.name.localeCompare(b.name);
    if (a.rollupScore === null) return 1;
    if (b.rollupScore === null) return -1;
    return a.rollupScore - b.rollupScore || a.name.localeCompare(b.name);
  });
  if (loose.length > 0) groups.push(summarise(null, UNASSIGNED_NAME, loose));
  return groups;
}

/** Display name for a client id (or "Unassigned"). */
export function clientName(clientId: string | null | undefined, clients: ClientSummary[]): string {
  if (!clientId) return UNASSIGNED_NAME;
  return clients.find((c) => c.id === clientId)?.name ?? UNASSIGNED_NAME;
}

/** Group arbitrary rows (scans, findings) by their site hostname for a "group by site" view. */
export function groupBySite<T>(rows: T[], hostOf: (row: T) => string | null): { host: string; rows: T[] }[] {
  const map = new Map<string, T[]>();
  for (const r of rows) {
    const host = hostOf(r) ?? "unknown";
    const list = map.get(host) ?? [];
    list.push(r);
    map.set(host, list);
  }
  return [...map.entries()].map(([host, list]) => ({ host, rows: list })).sort((a, b) => a.host.localeCompare(b.host));
}

export const CLIENT_STORAGE_KEY = "hc-client-scope";
