// External Attack Surface Management — post-scan discovery step.
// Continuously discovers subdomains/assets beyond what per-scan recon finds,
// building the asset_inventory table into a comprehensive attack surface map.
// Rows it inserts are "pending" (notified_at null) and are reported by
// attackSurfaceMonitor.ts: by the next scan's sendAttackSurfaceAlerts, or
// sooner by the standalone sweep's sendSweepHostnameAlerts (easmPipeline.ts),
// which uses the certificate evidence this module now returns.
//
// Two things here are easy to get wrong and both were once:
//   - Rows must carry the URL of the site being monitored (`targetUrl`), not
//     just the bare domain. A scan's alert reads pending rows by exact
//     target_url, so rows stored as https://<domain> never matched a site
//     monitored as https://www.<domain> and sat pending forever.
//   - A crt.sh failure is not "no hostnames". It is reported as `ctRead:
//     false` so a caller can tell "nothing new" from "could not look" (the
//     repo-wide evidence rule: a failed lookup is never an empty result).
//
// Runs in scanExecution.ts's executeScan, right after syncAssetInventory, on
// every scan — but via crt.sh (Certificate Transparency) and HTTP probing
// ONLY by default. DNS brute-force of common prefixes is a second,
// opt-in mode (bruteForce: true): it is active discovery against hosts that
// may not exist yet, so it is gated the same way as the Tier A `offensive`
// profile's other active-discovery tool (contentDiscovery.ts/ffuf) — callers
// must only pass bruteForce: true once that gate has already cleared.

import type { SupabaseClient } from "@supabase/supabase-js";
import { fetchCrtSh } from "./scanners/recon";

export type DiscoveredAsset = {
  hostname: string;
  source: "crt.sh" | "dns-brute" | "existing";
  httpStatus: number | null;
  httpTitle: string | null;
  tlsExpiry: string | null;
  firstSeen: string;
  lastSeen: string;
};

export type EasmResult = {
  domain: string;
  assetsDiscovered: number;
  newAssets: number;
  assets: DiscoveredAsset[];
  /**
   * Each hostname's earliest certificate date in crt.sh (raw, zone-less UTC as
   * crt.sh reports it). This is the evidence that a hostname is new; see
   * attackSurfaceMonitor.ts.
   */
  firstCertificates: Map<string, string>;
  /**
   * crt.sh was read successfully. False means the lookup failed, so an empty
   * `firstCertificates` says nothing about what exists. Callers that alert
   * must not treat it as "no new hostnames".
   */
  ctRead: boolean;
};

const COMMON_PREFIXES = [
  "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
  "smtp", "secure", "vpn", "admin", "api", "dev", "staging", "test",
  "portal", "app", "cdn", "shop", "store", "m", "docs", "status",
  "git", "ci", "jenkins", "grafana", "monitor",
];

const DNS_TIMEOUT = 5_000;
const HTTP_PROBE_TIMEOUT = 5_000;
const MAX_ASSETS_PER_DOMAIN = 200;

type CrtShResult = {
  hosts: string[];
  /** Each hostname's earliest certificate date, as crt.sh reports it. */
  firstCertificates: Map<string, string>;
  /** False when crt.sh could not be read; `hosts` is then empty because we could not look, not because there is nothing. */
  ok: boolean;
};

/**
 * Hostnames under `domain` from Certificate Transparency, each with its
 * earliest certificate date. Shares recon.ts's fetch, so crt.sh's brief
 * 502/503s are retried once. A failed lookup (network error, non-200, or a
 * reply that is not a certificate list, which crt.sh sometimes sends as a 200
 * HTML page) is `ok: false`, never an empty success.
 */
async function discoverViaCrtSh(domain: string): Promise<CrtShResult> {
  const failed: CrtShResult = { hosts: [], firstCertificates: new Map(), ok: false };
  try {
    // "%" is crt.sh's wildcard and must be percent-encoded itself.
    const res = await fetchCrtSh(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`);
    if (!res.ok) return failed;
    const body: unknown = await res.json();
    if (!Array.isArray(body)) return failed;

    const first = new Map<string, string>();
    const latest = new Map<string, string>();
    for (const entry of body as Array<{ name_value?: unknown; not_before?: unknown }>) {
      if (typeof entry?.name_value !== "string") continue;
      const notBefore = typeof entry.not_before === "string" ? entry.not_before : "";
      for (const name of entry.name_value.split("\n")) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, "");
        if (!(clean.endsWith(`.${domain}`) || clean === domain)) continue;
        const earliest = first.get(clean);
        if (notBefore && (!earliest || notBefore < earliest)) first.set(clean, notBefore);
        const newest = latest.get(clean);
        if (newest === undefined || notBefore > newest) latest.set(clean, notBefore);
      }
    }

    // Past the cap keep the most recently certified: a new hostname is by
    // definition one of those, so it can never be the one that is cut.
    const hosts = [...latest.keys()]
      .sort((a, b) => (latest.get(b) ?? "").localeCompare(latest.get(a) ?? "") || a.localeCompare(b))
      .slice(0, MAX_ASSETS_PER_DOMAIN);
    return { hosts, firstCertificates: first, ok: true };
  } catch {
    return failed;
  }
}

async function discoverViaDnsBrute(domain: string): Promise<string[]> {
  const found: string[] = [];
  for (const prefix of COMMON_PREFIXES) {
    const hostname = `${prefix}.${domain}`;
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
        { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(DNS_TIMEOUT) }
      );
      if (!res.ok) continue;
      const body = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
      if (body.Answer?.some((a) => a.type === 1)) {
        found.push(hostname);
      }
    } catch {
      // timeout or network error — skip this prefix
    }
  }
  return found;
}

async function probeHttp(hostname: string): Promise<{ status: number | null; title: string | null; tlsExpiry: string | null }> {
  try {
    const res = await fetch(`https://${hostname}`, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(HTTP_PROBE_TIMEOUT),
    });
    return { status: res.status, title: null, tlsExpiry: null };
  } catch {
    try {
      const res = await fetch(`http://${hostname}`, {
        method: "HEAD",
        redirect: "follow",
        signal: AbortSignal.timeout(HTTP_PROBE_TIMEOUT),
      });
      return { status: res.status, title: null, tlsExpiry: null };
    } catch {
      return { status: null, title: null, tlsExpiry: null };
    }
  }
}

/** New hosts probed per call — crt.sh alone can return close to
 *  MAX_ASSETS_PER_DOMAIN entries, and this runs inside a scan's own
 *  completion flow, so probing is capped and parallel rather than one
 *  sequential await per host (which could otherwise take minutes). */
const MAX_NEW_HOSTS_PROBED = 30;

export async function runEasmDiscovery(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  domain: string,
  options: {
    bruteForce?: boolean;
    /**
     * The monitored site these hostnames belong to (e.g. https://www.example.com).
     * Stored on each new row, because a scan's alert reads pending rows by this
     * exact URL. Defaults to https://<domain> for callers that only know the
     * domain, but those rows will only ever match a site monitored as the bare
     * domain, so every real caller passes it.
     */
    targetUrl?: string;
  } = {},
): Promise<EasmResult> {
  try {
    const now = new Date().toISOString();

    const { data: existing } = await supabaseAdmin
      .from("asset_inventory")
      .select("hostname")
      .eq("owner", ownerId)
      .like("hostname", `%${domain}`);

    const existingHosts = new Set((existing ?? []).map((r) => r.hostname as string));

    const [crt, bruteHosts] = await Promise.all([
      discoverViaCrtSh(domain),
      options.bruteForce ? discoverViaDnsBrute(domain) : Promise.resolve([] as string[]),
    ]);
    if (!crt.ok) console.warn(`[easmDiscovery] crt.sh could not be read for ${domain}; no certificate evidence this run`);

    const allHosts = new Map<string, "crt.sh" | "dns-brute" | "existing">();
    for (const h of existingHosts) allHosts.set(h, "existing");
    for (const h of crt.hosts) if (!allHosts.has(h)) allHosts.set(h, "crt.sh");
    for (const h of bruteHosts) if (!allHosts.has(h)) allHosts.set(h, "dns-brute");

    const newHostnames = [...allHosts.keys()].filter((h) => !existingHosts.has(h)).slice(0, MAX_NEW_HOSTS_PROBED);
    const probes = new Map(
      await Promise.all(newHostnames.map(async (h) => [h, await probeHttp(h)] as const))
    );

    const assets: DiscoveredAsset[] = [];
    let newCount = 0;

    for (const [hostname, source] of allHosts) {
      const isNew = !existingHosts.has(hostname);
      if (isNew) newCount++;

      const probe = probes.get(hostname) ?? { status: null, title: null, tlsExpiry: null };

      assets.push({
        hostname,
        source,
        httpStatus: probe.status,
        httpTitle: probe.title,
        tlsExpiry: probe.tlsExpiry,
        firstSeen: now,
        lastSeen: now,
      });

      if (isNew && probes.has(hostname)) {
        await supabaseAdmin.from("asset_inventory").upsert(
          {
            owner: ownerId,
            target_url: options.targetUrl ?? `https://${domain}`,
            hostname,
            kind: hostname === domain ? "domain" : "subdomain",
            cms_type: null,
            cloud_hints: [],
            last_seen_at: now,
          },
          { onConflict: "owner,hostname" }
        );
      }
    }

    return {
      domain,
      assetsDiscovered: assets.length,
      newAssets: newCount,
      assets,
      firstCertificates: crt.firstCertificates,
      ctRead: crt.ok,
    };
  } catch (err) {
    console.error(`[easmDiscovery] discovery failed for ${domain}:`, (err as Error).message);
    return { domain, assetsDiscovered: 0, newAssets: 0, assets: [], firstCertificates: new Map(), ctRead: false };
  }
}
