// External Attack Surface Management — scheduled discovery pipeline.
// Continuously discovers subdomains/assets beyond what per-scan recon finds,
// building the asset_inventory table into a comprehensive attack surface map.
//
// Runs as a post-scan enrichment step in scanExecution.ts Phase 2, and can
// also be triggered on demand. Uses crt.sh (Certificate Transparency),
// DNS brute-force of common prefixes, and HTTP probing of discovered hosts.

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

export async function runEasmDiscovery(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  domain: string,
): Promise<EasmResult> {
  const now = new Date().toISOString();

  const { data: existing } = await supabaseAdmin
    .from("asset_inventory")
    .select("hostname")
    .eq("owner", ownerId)
    .like("hostname", `%${domain}`);

  const existingHosts = new Set((existing ?? []).map((r) => r.hostname as string));

  const [crtHosts, bruteHosts] = await Promise.all([
    discoverViaCrtSh(domain),
    discoverViaDnsBrute(domain),
  ]);

  const allHosts = new Map<string, "crt.sh" | "dns-brute" | "existing">();
  for (const h of existingHosts) allHosts.set(h, "existing");
  for (const h of crtHosts) if (!allHosts.has(h)) allHosts.set(h, "crt.sh");
  for (const h of bruteHosts) if (!allHosts.has(h)) allHosts.set(h, "dns-brute");

  const assets: DiscoveredAsset[] = [];
  let newCount = 0;

  for (const [hostname, source] of allHosts) {
    const isNew = !existingHosts.has(hostname);
    if (isNew) newCount++;

    const probe = isNew ? await probeHttp(hostname) : { status: null, title: null, tlsExpiry: null };

    assets.push({
      hostname,
      source,
      httpStatus: probe.status,
      httpTitle: probe.title,
      tlsExpiry: probe.tlsExpiry,
      firstSeen: isNew ? now : now,
      lastSeen: now,
    });

    if (isNew) {
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
}
