// HaveIBeenPwned (HIBP) domain breach search — checks whether email
// addresses on the target domain have appeared in known third-party data
// breaches.
//
// IMPORTANT — this is NOT a stateless "pass a domain, get results" lookup
// like checkSafeBrowsing() or the Shodan/crt.sh calls in ./recon.ts. HIBP's
// domain search endpoint (`GET /api/v3/breacheddomain/{domain}`) requires
// the domain to be separately verified *with HIBP itself* — via their own
// dashboard (haveibeenpwned.com/Dashboard → Business → Domain Search) using
// a DNS TXT record, an HTML meta tag, an uploaded file, or an email link to
// admin@/webmaster@/postmaster@ on that domain — before it will return any
// data for it. An unverified domain gets HTTP 403 back, regardless of how
// valid the API key is.
//
// This is a SEPARATE, unrelated verification system from this app's own
// src/lib/ownership.ts (DNS TXT / .well-known file proving control *to this
// app*). Passing our own ownership check does NOT satisfy HIBP's — the two
// have no relationship to each other. Concretely, for this app's
// multi-tenant model (scanning arbitrary customer domains on demand), HIBP's
// per-domain verification would need to be completed separately, by whoever
// holds the HIBP subscription, for every single customer domain, before this
// check can return real data for it. That is a manual, out-of-band, per-
// domain step driven entirely by HIBP's own dashboard/API — this module
// cannot automate it, and no code change here can close that gap. Until a
// product workflow for that exists, expect `not_verified` back for most
// domains even with a paid key configured — this module still calls the
// real endpoint and reports that state honestly rather than pretending it's
// equivalent to "checked, no breaches."
//
// Subscription: the free HIBP tier has no domain search API access at all.
// Paid tiers start at Core 1 (~$4.39/mo at time of writing) and scale up
// based on the number of breached addresses found on the domain, not
// flat-rate — see https://haveibeenpwned.com/Subscription. Get a key at
// https://haveibeenpwned.com/API/Key.
//
// Once a real breach match comes back, per-breach detail (date, data
// classes, description) is enriched via HIBP's public, unauthenticated
// `GET /api/v3/breach/{name}` endpoint — no extra key or cost for that call.
//
// Same not_configured-when-unset degrade pattern as checkZap() in
// ./index.ts and ./safeBrowsing.ts: missing HIBP_API_KEY never throws and
// never blocks the rest of the scan.

const HIBP_API_BASE = "https://haveibeenpwned.com/api/v3";

// Every outbound request in this codebase carries AbortSignal.timeout() so a
// hung third party can't hang a scan (docs/SCANNER-CONVENTIONS.md).
const REQUEST_TIMEOUT_MS = 8_000;

// HIBP has required a User-Agent header on every API request since June
// 2018 — omitting it returns HTTP 403, indistinguishable at the status-code
// level from an unverified domain. Always sending one here means a 403 this
// module sees is (barring a HIBP-side bug) genuinely the domain-verification
// case, not a missing-header mistake.
const USER_AGENT = "HebridesCyberScanner/1.0 (+https://hebridescyber.co.uk)";

export type HibpBreach = {
  /** Stable HIBP breach identifier (e.g. "Adobe") — use this, not title, for diffing/keys. */
  name: string;
  title: string;
  breachDate: string | null;
  dataClasses: string[];
  description: string;
  /** HIBP's own flag for a breach that's more sensitive than usual (e.g. an adult-content site) — worth wording the finding carefully around, not less honestly. */
  isSensitive: boolean;
  isVerified: boolean;
  /** How many aliases (email local-parts) on this domain appeared in this specific breach. */
  affectedAliasCount: number;
};

export type HibpResult =
  | { status: "checked"; domain: string; breaches: HibpBreach[]; affectedAliasCount: number }
  | { status: "not_configured"; note: string }
  /**
   * HIBP responded but this domain has not completed HIBP's own separate
   * domain-verification flow (see file header) — distinct from a generic
   * error so callers/UI can explain *why* rather than reporting a check
   * failure.
   */
  | { status: "not_verified"; domain: string; note: string }
  | { status: "error"; note: string };

// Raw shape of GET /breacheddomain/{domain}: maps each breached email's
// local-part (alias) to the list of breach names it appeared in.
type BreachedDomainResponse = Record<string, string[]>;

// Raw shape (subset) of GET /breach/{name} — see
// https://haveibeenpwned.com/API/v3#SingleBreach. Unauthenticated, public.
type HibpBreachApiResponse = {
  Name: string;
  Title?: string;
  BreachDate?: string;
  DataClasses?: string[];
  Description?: string;
  IsSensitive?: boolean;
  IsVerified?: boolean;
};

/**
 * Pure parsing step: alias->breachNames map into unique breach name ->
 * affected alias count. Split out so it can be exercised directly against a
 * constructed response shape without a live API key or network access.
 */
export function summariseBreachedDomainResponse(body: BreachedDomainResponse): Map<string, number> {
  const counts = new Map<string, number>();
  for (const names of Object.values(body)) {
    for (const name of names) {
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
  }
  return counts;
}

/**
 * Pure parsing step: raw /breach/{name} response into our HibpBreach shape.
 * affectedAliasCount is threaded through from summariseBreachedDomainResponse
 * rather than present on this endpoint's own response.
 */
export function parseBreachDetail(body: HibpBreachApiResponse, affectedAliasCount: number): HibpBreach {
  return {
    name: body.Name,
    title: body.Title ?? body.Name,
    breachDate: body.BreachDate ?? null,
    dataClasses: body.DataClasses ?? [],
    // HIBP's Description field is HTML (contains <a> tags) — strip markup,
    // this scanner's Finding.detail is rendered as plain text elsewhere.
    description: (body.Description ?? "").replace(/<[^>]*>/g, ""),
    isSensitive: body.IsSensitive ?? false,
    isVerified: body.IsVerified ?? true,
    affectedAliasCount,
  };
}

/**
 * Best-effort enrichment for one breach name. Returns null on any failure —
 * callers fall back to a name-only record rather than fabricating detail or
 * failing the whole check over one slow/unavailable lookup.
 */
async function fetchBreachDetail(name: string): Promise<HibpBreachApiResponse | null> {
  try {
    const res = await fetch(`${HIBP_API_BASE}/breach/${encodeURIComponent(name)}`, {
      headers: { "User-Agent": USER_AGENT },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    return (await res.json()) as HibpBreachApiResponse;
  } catch {
    return null;
  }
}

/**
 * Heuristic severity for a single breach finding, based on what data classes
 * HIBP actually reported — not a blanket severity for "appeared in a
 * breach." Exported so the index.ts call site can use it directly rather
 * than re-deriving the same logic.
 */
export function hibpBreachSeverity(breach: HibpBreach): "critical" | "high" | "medium" | "low" | "info" {
  const classes = breach.dataClasses.map((c) => c.toLowerCase());
  if (classes.some((c) => c.includes("password"))) return "high";
  const sensitiveFinancialOrId = ["credit card", "bank account", "social security", "passport", "national id", "financ"];
  if (classes.some((c) => sensitiveFinancialOrId.some((s) => c.includes(s)))) return "high";
  if (breach.dataClasses.length > 0) return "medium";
  return "low";
}

export async function checkHibp(targetUrl: string): Promise<HibpResult> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) {
    return {
      status: "not_configured",
      note: "HIBP_API_KEY is not set — skipping breach exposure check",
    };
  }

  let domain: string;
  try {
    domain = new URL(targetUrl).hostname.replace(/^www\./, "");
  } catch {
    return { status: "error", note: `Invalid target URL: ${targetUrl}` };
  }

  try {
    const res = await fetch(`${HIBP_API_BASE}/breacheddomain/${encodeURIComponent(domain)}`, {
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": USER_AGENT,
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (res.status === 403) {
      return {
        status: "not_verified",
        domain,
        note:
          `HIBP returned 403 for ${domain} — almost always because this domain hasn't completed ` +
          `HIBP's own domain-verification flow (haveibeenpwned.com/Dashboard), which is separate from ` +
          `this app's ownership verification. Verify the domain directly with HIBP before this check ` +
          `can return data for it.`,
      };
    }
    if (res.status === 401) {
      return {
        status: "error",
        note: "HIBP rejected the API key (401) — confirm HIBP_API_KEY is current and the subscription is active",
      };
    }
    if (res.status === 429) {
      return { status: "error", note: "HIBP rate-limited this request (429) — back off and retry later" };
    }
    if (res.status === 404) {
      // No breach data on file for this domain's aliases.
      return { status: "checked", domain, breaches: [], affectedAliasCount: 0 };
    }
    if (!res.ok) {
      return { status: "error", note: `HIBP domain search returned HTTP ${res.status}` };
    }

    const body = (await res.json()) as BreachedDomainResponse;
    const breachCounts = summariseBreachedDomainResponse(body);
    const affectedAliasCount = Object.keys(body).length;

    if (breachCounts.size === 0) {
      return { status: "checked", domain, breaches: [], affectedAliasCount };
    }

    const breaches = await Promise.all(
      [...breachCounts.entries()].map(async ([name, aliasCount]) => {
        const detail = await fetchBreachDetail(name);
        return detail
          ? parseBreachDetail(detail, aliasCount)
          : // Enrichment failed — report the breach name/count honestly with no fabricated detail
            // rather than dropping the finding entirely.
            ({
              name,
              title: name,
              breachDate: null,
              dataClasses: [],
              description: "",
              isSensitive: false,
              isVerified: true,
              affectedAliasCount: aliasCount,
            } as HibpBreach);
      })
    );

    breaches.sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""));

    return { status: "checked", domain, breaches, affectedAliasCount };
  } catch (err) {
    return { status: "error", note: `HIBP breach check failed: ${(err as Error).message}` };
  }
}
