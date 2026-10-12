// External Attack Surface Management — post-scan discovery step.
// Continuously discovers subdomains/assets beyond what per-scan recon finds,
// building the asset_inventory table into a comprehensive attack surface map.
// Rows it inserts are picked up for free by attackSurfaceMonitor.ts's
// existing "new hostname" alert (it just reads asset_inventory rows with
// notified_at still null) — no separate alert wiring needed here.
//
// Runs in scanExecution.ts's executeScan, right after syncAssetInventory, on
// every scan — but via crt.sh (Certificate Transparency) and HTTP probing
// ONLY by default. DNS brute-force of common prefixes is a second,
// opt-in mode (bruteForce: true): it is active discovery against hosts that
// may not exist yet, so it is gated the same way as the Tier A `offensive`
// profile's other active-discovery tool (contentDiscovery.ts/ffuf) — callers
// must only pass bruteForce: true once that gate has already cleared.

import type { SupabaseClient } from "@supabase/supabase-js";

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
};

const COMMON_PREFIXES = [
  "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
  "smtp", "secure", "vpn", "admin", "api", "dev", "staging", "test",
  "portal", "app", "cdn", "shop", "store", "m", "docs", "status",
  "git", "ci", "jenkins", "grafana", "monitor",
];

const CRT_SH_TIMEOUT = 10_000;
const DNS_TIMEOUT = 5_000;
const HTTP_PROBE_TIMEOUT = 5_000;
const MAX_ASSETS_PER_DOMAIN = 200;

async function discoverViaCrtSh(domain: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(CRT_SH_TIMEOUT) }
    );
    if (!res.ok) return [];
    const entries = (await res.json()) as Array<{ name_value: string }>;
    const hosts = new Set<string>();
    for (const entry of entries) {
      for (const name of entry.name_value.split("\n")) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, "");
        if (clean.endsWith(`.${domain}`) || clean === domain) {
          hosts.add(clean);
        }
      }
    }
    return [...hosts].slice(0, MAX_ASSETS_PER_DOMAIN);
  } catch {
    return [];
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
  options: { bruteForce?: boolean } = {},
): Promise<EasmResult> {
  try {
    const now = new Date().toISOString();

    const { data: existing } = await supabaseAdmin
      .from("asset_inventory")
      .select("hostname")
      .eq("owner", ownerId)
      .like("hostname", `%${domain}`);

    const existingHosts = new Set((existing ?? []).map((r) => r.hostname as string));

    const [crtHosts, bruteHosts] = await Promise.all([
      discoverViaCrtSh(domain),
      options.bruteForce ? discoverViaDnsBrute(domain) : Promise.resolve([] as string[]),
    ]);

    const allHosts = new Map<string, "crt.sh" | "dns-brute" | "existing">();
    for (const h of existingHosts) allHosts.set(h, "existing");
    for (const h of crtHosts) if (!allHosts.has(h)) allHosts.set(h, "crt.sh");
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
            target_url: `https://${domain}`,
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
    };
  } catch (err) {
    console.error(`[easmDiscovery] discovery failed for ${domain}:`, (err as Error).message);
    return { domain, assetsDiscovered: 0, newAssets: 0, assets: [] };
  }
}
