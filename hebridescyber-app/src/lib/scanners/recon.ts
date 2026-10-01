// Passive reconnaissance: Shodan InternetDB (free, no key) + crt.sh subdomain
// enumeration via Certificate Transparency logs. No credentials required.
import { registrableDomain } from "./registrableDomain";

export type ReconResult =
  | {
      status: "checked";
      ip: string | null;
      shodan: ShodanData | null;
      subdomains: SubdomainEntry[];
      /** crt.sh couldn't be read, so `subdomains` being empty means "unknown",
       *  not "none". Checks that work from the list must not treat it as
       *  complete. Optional: older stored results lack it. */
      ctLookupFailed?: boolean;
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

/** crt.sh often answers 502/503 for a moment; one quick retry fixes most. */
const CRTSH_RETRY_DELAY_MS = 1_500;

async function fetchCrtSh(url: string): Promise<Response> {
  const attempt = () => fetch(url, { signal: AbortSignal.timeout(12_000), headers: { Accept: "application/json" } });
  const res = await attempt();
  if (res.status < 500) return res;
  await new Promise((r) => setTimeout(r, CRTSH_RETRY_DELAY_MS));
  return attempt();
}

async function queryCrtSh(domain: string): Promise<SubdomainEntry[] | null> {
  try {
    // "%" is crt.sh's wildcard and must be percent-encoded itself.
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const res = await fetchCrtSh(url);
    if (!res.ok) return null;

    const body = (await res.json()) as Array<{
      name_value: string;
      issuer_name?: string;
      not_before?: string;
    }>;

    const byName = new Map<string, SubdomainEntry>();

    for (const cert of body) {
      // name_value may contain multiple newline-separated names (SANs)
      const names = cert.name_value.split(/\n/).map((n) => n.trim().toLowerCase());
      for (const name of names) {
        if (!name) continue;
        // A wildcard covers its base; list the base once. Compare the domain
        // *after* stripping "*." — a "*.example.com" certificate used to list
        // the apex itself as one of its own subdomains.
        const display = name.startsWith("*.") ? name.slice(2) : name;
        if (display === domain) continue;
        // Keep each name's most recent certificate: a host still being
        // issued certificates is most likely still in use.
        const existing = byName.get(display);
        if (existing && (existing.notBefore >= (cert.not_before ?? ""))) continue;
        byName.set(display, { name: display, issuer: cert.issuer_name ?? "", notBefore: cert.not_before ?? "" });
      }
    }

    // The 50 most recently certified (the ones likeliest to be live), listed
    // alphabetically.
    return [...byName.values()]
      .sort((a, b) => b.notBefore.localeCompare(a.notBefore))
      .slice(0, 50)
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    return null;
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

    return subdomains
      ? { status: "checked", ip, shodan, subdomains }
      : { status: "checked", ip, shodan, subdomains: [], ctLookupFailed: true };
  } catch (err) {
    return { status: "error", note: `Recon check failed: ${(err as Error).message}` };
  }
}
