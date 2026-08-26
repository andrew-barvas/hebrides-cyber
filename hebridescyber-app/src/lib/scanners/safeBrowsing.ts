// Google Safe Browsing v4 (threatMatches.find) — checks whether the target
// URL is currently flagged for malware, phishing ("social engineering"), or
// unwanted software. Every other scanner in this module infers risk
// indirectly (a missing header, a weak cipher); this one is Google directly
// telling us the URL is on a live threat list, so a positive match is
// high-confidence evidence rather than a heuristic — see the "critical,
// unqualified" severity choice in the finding this produces.
//
// Requires GOOGLE_SAFE_BROWSING_API_KEY (see .env.example for how to obtain
// one — Google Cloud Console, enable "Safe Browsing API", create a
// restricted API key). Degrades to a "not_configured" stub when unset, the
// same pattern checkZap() in ./index.ts and the GITHUB_PAT-gated checks in
// ./dependencyManifest.ts use for an optional credential.
//
// API reference: https://developers.google.com/safe-browsing/v4/lookup-api

const SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

// Every outbound request in this codebase carries AbortSignal.timeout() so a
// hung third party can't hang a scan (docs/SCANNER-CONVENTIONS.md).
const REQUEST_TIMEOUT_MS = 8_000;

export type SafeBrowsingThreatType = "MALWARE" | "SOCIAL_ENGINEERING" | "UNWANTED_SOFTWARE";

export type SafeBrowsingMatch = {
  threatType: string;
  platformType: string;
  threatEntryType: string;
};

export type SafeBrowsingResult =
  | { status: "checked"; flagged: boolean; matches: SafeBrowsingMatch[]; threatTypes: string[] }
  | { status: "not_configured"; note: string }
  | { status: "error"; note: string };

// Raw shape of a successful threatMatches.find response body. An unflagged
// URL returns `{}` (no `matches` key at all, HTTP 200) — that is the normal
// "clean" response, not an error or an empty-but-present array.
type ThreatMatchesResponse = {
  matches?: Array<{
    threatType?: string;
    platformType?: string;
    threatEntryType?: string;
    threat?: { url?: string };
    cacheDuration?: string;
  }>;
};

/**
 * Pure parsing step, split out from checkSafeBrowsing() so it can be
 * exercised directly against a recorded/constructed API response shape
 * without a live API key or network access.
 */
export function parseThreatMatchesResponse(
  body: ThreatMatchesResponse
): { flagged: boolean; matches: SafeBrowsingMatch[]; threatTypes: string[] } {
  const matches: SafeBrowsingMatch[] = (body.matches ?? []).map((m) => ({
    threatType: m.threatType ?? "UNKNOWN",
    platformType: m.platformType ?? "UNKNOWN",
    threatEntryType: m.threatEntryType ?? "URL",
  }));
  const threatTypes = [...new Set(matches.map((m) => m.threatType))];
  return { flagged: matches.length > 0, matches, threatTypes };
}

export async function checkSafeBrowsing(targetUrl: string): Promise<SafeBrowsingResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return {
      status: "not_configured",
      note: "GOOGLE_SAFE_BROWSING_API_KEY is not set — skipping malware/phishing blocklist check",
    };
  }

  try {
    const res = await fetch(`${SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      body: JSON.stringify({
        client: {
          clientId: "hebridescyber",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"] as SafeBrowsingThreatType[],
          platformTypes: ["WINDOWS", "ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: targetUrl }],
        },
      }),
    });

    if (!res.ok) {
      return { status: "error", note: `Safe Browsing API returned HTTP ${res.status}` };
    }

    const body = (await res.json()) as ThreatMatchesResponse;
    const { flagged, matches, threatTypes } = parseThreatMatchesResponse(body);
    return { status: "checked", flagged, matches, threatTypes };
  } catch (err) {
    return { status: "error", note: `Safe Browsing check failed: ${(err as Error).message}` };
  }
}
