// Passive reconnaissance: Shodan InternetDB (free, no key) + crt.sh subdomain
// enumeration via Certificate Transparency logs. No credentials required.
import { registrableDomain } from "./registrableDomain";

export type ReconResult =
  | {
      status: "checked";
      ip: string | null;
      shodan: ShodanData | null;
      subdomains: SubdomainEntry[];
    }
  | { status: "error"; note: string };

export type ShodanData = {
  cves: string[];
  ports: number[];
  tags: string[];
  cpes: string[];
  hostnames: string[];
};

export type SubdomainEntry = {
  name: string;
  issuer: string;
  notBefore: string;
};

// ── IP resolution ─────────────────────────────────────────────────────────────

async function resolveIp(hostname: string): Promise<string | null> {
  try {
    // Use Cloudflare's DNS-over-HTTPS (JSON API) — available from Node.js
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(6_000),
      }
    );
    if (!res.ok) return null;
    const body = (await res.json()) as { Answer?: { type: number; data: string }[] };
    const a = body.Answer?.find((r) => r.type === 1);
    return a?.data ?? null;
  } catch {
    return null;
  }
}

// ── Shodan InternetDB ─────────────────────────────────────────────────────────

async function queryShodan(ip: string): Promise<ShodanData | null> {
  try {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, {
      signal: AbortSignal.timeout(8_000),
    });
    // 404 = no data for this IP
    if (res.status === 404) return null;
    if (!res.ok) return null;
    const body = (await res.json()) as {
      cves?: string[];
      ports?: number[];
      tags?: string[];
      cpes?: string[];
      hostnames?: string[];
    };
    return {
      cves: body.cves ?? [],
      ports: body.ports ?? [],
      tags: body.tags ?? [],
      cpes: body.cpes ?? [],
      hostnames: body.hostnames ?? [],
    };
  } catch {
    return null;
  }
}

// ── crt.sh subdomain enumeration ─────────────────────────────────────────────

async function queryCrtSh(domain: string): Promise<SubdomainEntry[]> {
  try {
    // "%" is crt.sh's wildcard and must be percent-encoded itself.
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(12_000),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return [];

    const body = (await res.json()) as Array<{
      name_value: string;
      issuer_name?: string;
      not_before?: string;
    }>;

    const seen = new Set<string>();
    const entries: SubdomainEntry[] = [];

    for (const cert of body) {
      // name_value may contain multiple newline-separated names (SANs)
      const names = cert.name_value.split(/\n/).map((n) => n.trim().toLowerCase());
      for (const name of names) {
        if (!name) continue;
        // A wildcard covers its base; list the base once. Compare the domain
        // *after* stripping "*." — a "*.example.com" certificate used to list
        // the apex itself as one of its own subdomains.
        const display = name.startsWith("*.") ? name.slice(2) : name;
        if (display === domain || seen.has(display)) continue;
        seen.add(display);
        entries.push({
          name: display,
          issuer: cert.issuer_name ?? "",
          notBefore: cert.not_before ?? "",
        });
      }
    }

    // Sort by name, limit to 50 most interesting
    return entries.sort((a, b) => a.name.localeCompare(b.name)).slice(0, 50);
  } catch {
    return [];
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function checkRecon(targetUrl: string): Promise<ReconResult> {
  try {
    const hostname = new URL(targetUrl).hostname;
    // Enumerate the whole registered domain: scanning shop.example.co.uk
    // used to search only *.shop.example.co.uk and miss every sibling host —
    // the candidates takeover.ts checks for dangling DNS.
    const domain = registrableDomain(hostname) ?? hostname.replace(/^www\./, "");

    const [ip, subdomains] = await Promise.all([
      resolveIp(hostname),
      queryCrtSh(domain),
    ]);

    const shodan = ip ? await queryShodan(ip) : null;

    return { status: "checked", ip, shodan, subdomains };
  } catch (err) {
    return { status: "error", note: `Recon check failed: ${(err as Error).message}` };
  }
}
