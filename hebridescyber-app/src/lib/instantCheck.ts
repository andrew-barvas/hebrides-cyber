// The no-signup "instant check" on the public site: TLS, security headers and
// DNS/email authentication for any site, with no ownership proof. That is only
// acceptable because it sends what any browser or mail server would: one GET
// per redirect hop, a TLS handshake and DNS lookups. Nothing here probes paths,
// ports or inputs; those stay behind domain verification.
//
// Because the caller is anonymous and the target is arbitrary, redirects are
// followed by hand with every hop checked for internal addresses (the verified
// scan path lets fetch follow them, which is fine when the owner chose the
// target). A hostname that changes its DNS answer between our check and the
// fetch is a known gap shared with the rest of the scanner.
import { validateNoSsrf } from "@/lib/ownership";
import { buildHeaderAnalysis, type HeadersResult } from "@/lib/scanners/headers";
import { checkTls } from "@/lib/scanners/tls";
import { checkDns } from "@/lib/scanners/dns";
import { scoreFromFindings, summariseResults, type Finding, type ScanResults } from "@/lib/scanners";

export const MAX_REDIRECTS = 4;
export const FINDINGS_SHOWN = 5;

// Only these checks run, so only their findings are reported.
const REPORTED_PREFIXES = ["tls.", "dns.", "headers."];

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export class InstantCheckError extends Error {}

/** "example.com", "https://example.com/a?b" or "http://example.com:80" -> an origin, or an error the visitor can act on. */
export function normaliseTarget(input: string): string {
  const raw = input.trim();
  if (!raw || raw.length > 253) throw new InstantCheckError("Enter a website address, for example example.com.");
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    throw new InstantCheckError("That doesn't look like a website address.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new InstantCheckError("Only http and https addresses can be checked.");
  if (url.username || url.password) throw new InstantCheckError("Remove the username and password from the address.");
  if (url.port && url.port !== "80" && url.port !== "443") throw new InstantCheckError("Only the standard web ports (80 and 443) can be checked.");
  if (!url.hostname.includes(".")) throw new InstantCheckError("Enter a full domain name, for example example.com.");
  return url.origin;
}

/** GET with redirects followed by hand, re-validating each hop. Returns the final response and origin. */
export async function fetchFollowingSafely(
  startOrigin: string,
  fetchImpl: typeof fetch = fetch,
  validate: (url: string) => Promise<string> = validateNoSsrf
): Promise<{ res: Response; origin: string }> {
  let current = startOrigin;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const origin = await validate(current);
    const res = await fetchImpl(current, { redirect: "manual", signal: AbortSignal.timeout(8_000), headers: { "user-agent": "HebridesCyberInstantCheck/1.0 (+https://www.hebridescyber.co.uk/check)" } });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
    if (!location) return { res, origin };
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      throw new InstantCheckError("The site redirects to an address that isn't valid.");
    }
    if (next.protocol !== "https:" && next.protocol !== "http:") throw new InstantCheckError("The site redirects somewhere that can't be checked.");
    current = next.href;
  }
  throw new InstantCheckError("The site redirects too many times to check.");
}

export type InstantCheckResult = {
  target: string;
  score: number;
  counts: Record<(typeof SEVERITY_ORDER)[number], number>;
  total: number;
  /** The most serious findings, without remediation steps (those are the account's job). */
  findings: { severity: string; title: string; detail: string }[];
  hidden: number;
  checkedAt: string;
};

const notRun = { status: "error" } as never;

export async function runInstantCheck(
  input: string,
  deps: { fetchImpl?: typeof fetch; validate?: (url: string) => Promise<string> } = {}
): Promise<InstantCheckResult> {
  const start = normaliseTarget(input);
  let fetched: { res: Response; origin: string };
  try {
    fetched = await fetchFollowingSafely(start, deps.fetchImpl, deps.validate);
  } catch (err) {
    if (err instanceof InstantCheckError) throw err;
    // validateNoSsrf messages name internal ranges and resolver errors; the visitor only needs to know we can't check it.
    throw new InstantCheckError("We couldn't reach that site. Check the address, or the site may block automated requests.");
  }
  const { res, origin } = fetched;

  const [tls, dns] = await Promise.all([checkTls(origin), checkDns(origin)]);
  const headers: HeadersResult = { status: "checked", ...buildHeaderAnalysis(res) };

  const results = {
    target_url: origin,
    checked_at: new Date().toISOString(),
    tls,
    headers,
    dns,
    exposure: notRun, directoryListing: notRun, cloudMisconfig: notRun, fingerprint: notRun, ports: notRun,
    playwright: notRun, recon: notRun, webapp: notRun, safeBrowsing: notRun, waybackDiscovery: notRun,
    hibp: notRun, wpVulnDb: notRun, softwareCveDb: notRun, businessLogic: notRun, apiSpec: notRun, zap: notRun,
  } as unknown as ScanResults;

  const findings: Finding[] = summariseResults(results).findings.filter((f) => REPORTED_PREFIXES.some((p) => (f.checkId ?? "").startsWith(p)));
  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity as never) - SEVERITY_ORDER.indexOf(b.severity as never));

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity as keyof typeof counts]++;
  const actionable = findings.filter((f) => f.severity !== "info");

  return {
    target: origin,
    score: scoreFromFindings(findings),
    counts,
    total: actionable.length,
    findings: actionable.slice(0, FINDINGS_SHOWN).map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })),
    hidden: Math.max(0, actionable.length - FINDINGS_SHOWN),
    checkedAt: results.checked_at,
  };
}
