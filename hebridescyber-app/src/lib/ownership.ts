// Real domain-ownership verification: DNS TXT record or a file under
// /.well-known/. No third-party API or credentials required — just Node's
// built-in DNS resolver and fetch. This is the real implementation the
// rest of the codebase's TODOs have been pointing at.
//
// Used by src/functions/verify-ownership/index.ts (the HTTP-triggered
// function that drives this) and referenced by src/functions/run-scan.

import { resolveTxt } from "node:dns/promises";

export const VERIFICATION_PREFIX = "hebridescyber-verify";
export const WELL_KNOWN_PATH = "/.well-known/hebridescyber-verify.txt";

/** Extracts a bare hostname from a URL string, e.g. "https://x.com/a" -> "x.com". */
export function hostnameFromUrl(targetUrl: string): string {
  return new URL(targetUrl).hostname;
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
 *
 * TODO: add a timeout (AbortController) tuned for slow customer hosting,
 * and consider following one redirect max to avoid SSRF via open redirects.
 */
export async function checkFileVerification(domain: string, token: string): Promise<boolean> {
  try {
    const res = await fetch(`https://${domain}${WELL_KNOWN_PATH}`, {
      redirect: "manual", // don't blindly follow redirects — see TODO above
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
