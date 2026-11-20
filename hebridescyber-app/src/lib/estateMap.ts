// The estate map (next-10 task 8): every host we know about for an account,
// grouped by domain, with what each one is doing — whether it answers on the
// web (and what it shows), its certificate's expiry, which services are
// exposed, and its open issues. The "whole footprint on one page" view of an
// exposure review.
//
// Built only from data already stored: asset_inventory (hosts seen by
// scans), the latest scans' httpx records (live hosts) and TLS results, and
// the open findings. Absent data is shown as unknown, never as "fine".
import type { SupabaseClient } from "@supabase/supabase-js";
import { loadFindingsView, type FindingRow } from "./findingsView";
import { registrableDomain } from "./scanners/registrableDomain";
import type { HttpProbeRecord } from "./scanners/hostProbe";

const SCAN_LOOKBACK = 200;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITIES)[number];

export type EstateHost = {
  host: string;
  kind: "domain" | "subdomain" | "unknown";
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  /** From the newest httpx record; null when no probe has seen it. */
  web: { statusCode: number; title: string | null; webserver: string | null; url: string } | null;
  /** From the newest scan of this host itself; null when it hasn't been scanned directly. */
  certificate: { expiresAt: string; daysLeft: number | null; issuer: string } | null;
  /** Exposed services from open findings, e.g. "3389", "22". */
  exposedPorts: string[];
  openFindings: Record<Severity, number>;
  /** The newest completed scan of this host, for linking to its report. */
  scanId: string | null;
};

export type EstateMap = {
  domains: Array<{ domain: string; hosts: EstateHost[] }>;
  totals: { hosts: number; live: number; certificatesExpiringSoon: number; withCriticalOrHigh: number };
};

type InventoryRow = { hostname: string; kind: string; first_seen_at: string | null; last_seen_at: string | null };
type TlsLike = { status?: string; certificateExpiresAt?: string; daysUntilExpiry?: number | null; issuer?: string } | null;
export type ScanSnapshot = { id: string; target_url: string; created_at: string; httpx: HttpProbeRecord[] | null; tls: TlsLike };

const hostOf = (url: string): string | null => {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
};

const emptyCounts = (): Record<Severity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
export const EXPIRING_DAYS = 30;

/** Pure. `scans` newest first. */
export function buildEstateMap(inventory: readonly InventoryRow[], scans: readonly ScanSnapshot[], rows: readonly FindingRow[]): EstateMap {
  const hosts = new Map<string, EstateHost>();
  const ensure = (host: string, kind: EstateHost["kind"] = "unknown"): EstateHost => {
    let h = hosts.get(host);
    if (!h) {
      h = { host, kind, firstSeenAt: null, lastSeenAt: null, web: null, certificate: null, exposedPorts: [], openFindings: emptyCounts(), scanId: null };
      hosts.set(host, h);
    }
    return h;
  };

  for (const r of inventory) {
    const h = ensure(r.hostname.toLowerCase(), r.kind === "domain" || r.kind === "subdomain" ? r.kind : "unknown");
    h.firstSeenAt = r.first_seen_at;
    h.lastSeenAt = r.last_seen_at;
  }

  const webSeen = new Set<string>();
  for (const scan of scans) {
    const target = hostOf(scan.target_url);
    if (target) {
      const h = ensure(target);
      if (!h.scanId) {
        h.scanId = scan.id;
        if (scan.tls?.status === "checked" && scan.tls.certificateExpiresAt) {
          h.certificate = { expiresAt: scan.tls.certificateExpiresAt, daysLeft: scan.tls.daysUntilExpiry ?? null, issuer: scan.tls.issuer ?? "" };
        }
      }
    }
    for (const rec of scan.httpx ?? []) {
      const host = (rec.host || hostOf(rec.url) || "").toLowerCase();
      if (!host || webSeen.has(host)) continue;
      webSeen.add(host);
      ensure(host).web = { statusCode: rec.statusCode, title: rec.title, webserver: rec.webserver, url: rec.url };
    }
  }

  for (const r of rows) {
    if (r.triage?.state === "false_positive") continue;
    const h = ensure(r.host.toLowerCase());
    if (SEVERITIES.includes(r.severity as Severity)) h.openFindings[r.severity as Severity]++;
    const port = r.checkId.match(/^network-exposure\.open-port:(\d+)/)?.[1];
    if (port && !h.exposedPorts.includes(port)) h.exposedPorts.push(port);
  }

  const byDomain = new Map<string, EstateHost[]>();
  for (const h of hosts.values()) {
    h.exposedPorts.sort((a, b) => Number(a) - Number(b));
    const domain = registrableDomain(h.host) ?? h.host;
    byDomain.set(domain, [...(byDomain.get(domain) ?? []), h]);
  }
  const domains = [...byDomain]
    .map(([domain, list]) => ({ domain, hosts: list.sort((a, b) => (a.host === domain ? -1 : b.host === domain ? 1 : a.host.localeCompare(b.host))) }))
    .sort((a, b) => a.domain.localeCompare(b.domain));
  const all = [...hosts.values()];
  return {
    domains,
    totals: {
      hosts: all.length,
      live: all.filter((h) => h.web && h.web.statusCode < 500).length,
      certificatesExpiringSoon: all.filter((h) => h.certificate?.daysLeft !== null && h.certificate?.daysLeft !== undefined && h.certificate.daysLeft <= EXPIRING_DAYS).length,
      withCriticalOrHigh: all.filter((h) => h.openFindings.critical + h.openFindings.high > 0).length,
    },
  };
}

export async function loadEstateMap(supabaseAdmin: SupabaseClient, ownerId: string): Promise<{ ok: true; map: EstateMap } | { ok: false; error: string }> {
  const [inventory, scans, view] = await Promise.all([
    supabaseAdmin.from("asset_inventory").select("hostname, kind, first_seen_at, last_seen_at").eq("owner", ownerId),
    supabaseAdmin
      .from("scans")
      .select("id, target_url, created_at, scan_results(httpx:results->extended->httpx->results, tls:results->tls)")
      .eq("owner", ownerId)
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(SCAN_LOOKBACK),
    loadFindingsView(supabaseAdmin, ownerId),
  ]);
  if (inventory.error) return { ok: false, error: inventory.error.message };
  if (scans.error) return { ok: false, error: scans.error.message };
  if (!view.ok) return { ok: false, error: view.error };
  const snapshots: ScanSnapshot[] = ((scans.data ?? []) as Array<{ id: string; target_url: string; created_at: string; scan_results: unknown }>).map((s) => {
    const r = (Array.isArray(s.scan_results) ? s.scan_results[0] : s.scan_results) as { httpx?: unknown; tls?: unknown } | null;
    return { id: s.id, target_url: s.target_url, created_at: s.created_at, httpx: Array.isArray(r?.httpx) ? (r?.httpx as HttpProbeRecord[]) : null, tls: (r?.tls as TlsLike) ?? null };
  });
  return { ok: true, map: buildEstateMap((inventory.data ?? []) as InventoryRow[], snapshots, view.data.rows) };
}
