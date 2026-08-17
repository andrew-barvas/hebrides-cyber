// Real domain-ownership verification: DNS TXT record or a file under
// /.well-known/. No third-party API or credentials required — just Node's
// built-in DNS resolver and fetch. This is the real implementation the
// rest of the codebase's TODOs have been pointing at.
//
// Used by src/functions/verify-ownership/index.ts (the HTTP-triggered
// function that drives this) and referenced by src/functions/run-scan.

import { resolveTxt, resolve4, resolve6 } from "node:dns/promises";
import type { SupabaseClient } from "@supabase/supabase-js";

// ---- SSRF protection -------------------------------------------------------
// Resolves the target hostname and blocks private/loopback ranges before any
// scan or verification request is issued. Prevents attackers from using the
// scanner as a proxy to reach internal infrastructure.

function parseIpv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => ((acc << 8) | parseInt(oct, 10)) >>> 0, 0) >>> 0;
}

const BLOCKED_IPV4_CIDRS: Array<{ network: number; mask: number }> = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "169.254.0.0/16", // link-local — includes AWS/Azure/GCP metadata service
  "100.64.0.0/10",  // shared address space (RFC 6598)
  "0.0.0.0/8",
  "240.0.0.0/4",    // reserved
].map((cidr) => {
  const [net, bits] = cidr.split("/");
  const prefixLen = parseInt(bits, 10);
  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return { network: parseIpv4ToInt(net) & mask, mask };
});

function isBlockedIpv4(ip: string): boolean {
  const n = parseIpv4ToInt(ip);
  return BLOCKED_IPV4_CIDRS.some(({ network, mask }) => (n & mask) === network);
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  // ::1 loopback, fc00::/7 unique-local, fe80::/10 link-local, :: unspecified
  return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe8") || lower === "::";
}

/**
 * Validates a URL is safe to make outbound requests to.
 * Throws a descriptive error if the target resolves to a private/reserved
 * IP — callers should surface this as a 400, not a 500.
 */
export async function validateNoSsrf(targetUrl: string): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new Error("Invalid URL format");
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Only http:// and https:// targets are permitted");
  }

  const hostname = parsed.hostname;

  // Reject bare IPs without DNS resolution — common SSRF shortcut.
  if (/^[\d.]+$/.test(hostname)) {
    if (isBlockedIpv4(hostname)) throw new Error(`Target IP ${hostname} is in a restricted private range`);
  }
  if (hostname.includes(":") || hostname.startsWith("[")) {
    const bare = hostname.replace(/^\[|\]$/g, "");
    if (isBlockedIpv6(bare)) throw new Error(`Target IPv6 ${hostname} is in a restricted range`);
  }

  // Resolve the hostname and block private IPs reachable via DNS rebinding.
  const [v4Results, v6Results] = await Promise.allSettled([resolve4(hostname), resolve6(hostname)]);
  const allIps = [
    ...(v4Results.status === "fulfilled" ? v4Results.value : []),
    ...(v6Results.status === "fulfilled" ? v6Results.value : []),
  ];

  if (allIps.length === 0) throw new Error(`Could not resolve hostname: ${hostname}`);

  for (const ip of allIps) {
    if (ip.includes(":")) {
      if (isBlockedIpv6(ip)) throw new Error(`${hostname} resolves to restricted IPv6 address ${ip}`);
    } else {
      if (isBlockedIpv4(ip)) throw new Error(`${hostname} resolves to restricted IP address ${ip}`);
    }
  }

  return parsed.origin;
}

export const VERIFICATION_PREFIX = "hebridescyber-verify";
export const WELL_KNOWN_PATH = "/.well-known/hebridescyber-verify.txt";

/** Extracts a bare hostname from a URL string, e.g. "https://x.com/a" -> "x.com". */
export function hostnameFromUrl(targetUrl: string): string {
  return new URL(targetUrl).hostname;
}

/**
 * Whether `ownerId` has a completed, real (DNS/file) verification on file for
 * `targetUrl`'s hostname — the persisted `verifications.verified_at` flag,
 * not a fresh live re-check. Shared by run-scan's isOwnershipVerified (which
 * also has a dev-only proof-token fallback this doesn't need), the public API
 * (src/pages/api/v1/scans.ts), and the scheduled-scan queue's enqueue/worker
 * scripts, which have no interactive token exchange to fall back to and must
 * only ever enqueue/run scans against a domain the owner has actually proven
 * they control.
 *
 * Admins bypass this entirely — same reasoning and same `users.is_admin`
 * flag as isFreeTierExhausted (src/lib/freeTier.ts): they need to test
 * scans against arbitrary targets without going through the DNS/file
 * verification dance every time.
 */
export async function isDomainVerified(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string
): Promise<boolean> {
  const { data: user } = await supabaseAdmin.from("users").select("is_admin").eq("id", ownerId).maybeSingle();
  if (user?.is_admin) return true;

  let domain: string;
  try {
    domain = hostnameFromUrl(targetUrl);
  } catch {
    return false;
  }

  const { data } = await supabaseAdmin
    .from("verifications")
    .select("verified_at")
    .eq("owner", ownerId)
    .eq("domain", domain)
    .maybeSingle();

  return Boolean(data?.verified_at);
}

/**
 * Checks whether `domain` has a DNS TXT record of the form
 * `hebridescyber-verify=<token>`.
 *
 * TODO: DNS propagation can take minutes to hours after the user adds the
 * record — the dashboard should say so and let them retry rather than
 * implying a single failed check means it'll never work.
 */
export async function checkDnsTxt(domain: string, token: string): Promise<boolean> {
  try {
    const records = await resolveTxt(domain);
    const expected = `${VERIFICATION_PREFIX}=${token}`;
    // resolveTxt returns string[][] — each TXT record can be split into
    // multiple strings by DNS itself, so join before comparing.
    return records.some((chunks) => chunks.join("") === expected);
  } catch (err) {
    // NXDOMAIN, no TXT records, timeout, etc. — all just mean "not verified yet".
    return false;
  }
}

/**
 * Checks whether https://<domain>/.well-known/hebridescyber-verify.txt
 * exists and its (trimmed) body matches `token` exactly.
 */
export async function checkFileVerification(domain: string, token: string): Promise<boolean> {
  try {
    const res = await fetch(`https://${domain}${WELL_KNOWN_PATH}`, {
      redirect: "manual", // don't follow redirects — avoids SSRF via open redirects
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return false;
    const body = await res.text();
    return body.trim() === token;
  } catch (err) {
    return false;
  }
}

/** Runs both checks and returns which method (if any) succeeded. */
export async function verifyDomain(
  domain: string,
  token: string
): Promise<{ verified: boolean; method: "dns" | "file" | null }> {
  if (await checkDnsTxt(domain, token)) return { verified: true, method: "dns" };
  if (await checkFileVerification(domain, token)) return { verified: true, method: "file" };
  return { verified: false, method: null };
}
