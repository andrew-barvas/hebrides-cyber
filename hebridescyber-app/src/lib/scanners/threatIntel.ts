// Threat-intelligence enrichment for CVE-backed findings: is the CVE in
// CISA's Known Exploited Vulnerabilities (KEV) catalog, and what is its FIRST
// EPSS score (probability of exploitation activity in the next 30 days).
//
// CVSS (cvssEnrich.ts) rates how severe a flaw could be; it says nothing
// about whether anyone is exploiting it, which is what decides what to fix
// first. KEV is the authoritative "being exploited now" list (US federal
// agencies must fix KEV entries within weeks under BOD 22-01) and EPSS is
// the standard likelihood model. The NCSC's EASM buyer's guide asks exactly
// this of a product: how are findings ranked by likelihood?
//
// Applied as a final pass, like CVSS. Severity is deliberately NOT changed —
// severity is the finding's evidence; this is prioritisation context shown
// beside it. Both sources are free and keyless. Any failure leaves the
// finding without `threatIntel` (absent = unknown, never "not exploited").
import type { Finding } from "./index";

export const KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EPSS_API_URL = "https://api.first.org/data/v1/epss";

const KEV_TIMEOUT_MS = 15_000;
const EPSS_TIMEOUT_MS = 8_000;
/** EPSS accepts a comma-separated list; keep URLs well under 2k chars. */
const EPSS_BATCH = 50;
/** The feed changes at most daily; one worker run never needs it twice. */
const KEV_CACHE_MS = 6 * 60 * 60 * 1000;

type KevEntry = { cveID: string; knownRansomwareCampaignUse?: string };
export type KevIndex = Map<string, { ransomware: boolean }>;
export type EpssIndex = Map<string, { epss: number; percentile: number }>;

let kevCache: { at: number; index: KevIndex } | null = null;

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

export function parseKev(body: unknown): KevIndex {
  const index: KevIndex = new Map();
  const list = (body as { vulnerabilities?: KevEntry[] } | null)?.vulnerabilities;
  if (!Array.isArray(list)) return index;
  for (const entry of list) {
    if (typeof entry?.cveID !== "string" || !CVE_RE.test(entry.cveID)) continue;
    index.set(entry.cveID.toUpperCase(), { ransomware: entry.knownRansomwareCampaignUse === "Known" });
  }
  return index;
}

export function parseEpss(body: unknown): EpssIndex {
  const index: EpssIndex = new Map();
  const rows = (body as { data?: Array<{ cve?: string; epss?: string; percentile?: string }> } | null)?.data;
  if (!Array.isArray(rows)) return index;
  for (const row of rows) {
    const epss = Number(row?.epss);
    const percentile = Number(row?.percentile);
    if (typeof row?.cve !== "string" || !Number.isFinite(epss) || !Number.isFinite(percentile)) continue;
    index.set(row.cve.toUpperCase(), { epss, percentile });
  }
  return index;
}

async function loadKev(now: number): Promise<KevIndex | null> {
  if (kevCache && now - kevCache.at < KEV_CACHE_MS) return kevCache.index;
  try {
    const res = await fetch(KEV_FEED_URL, { signal: AbortSignal.timeout(KEV_TIMEOUT_MS) });
    if (!res.ok) return null;
    const index = parseKev(await res.json());
    // An empty parse means the feed changed shape, not "nothing is exploited".
    if (index.size === 0) return null;
    kevCache = { at: now, index };
    return index;
  } catch {
    return null;
  }
}

async function loadEpss(cveIds: string[]): Promise<EpssIndex | null> {
  const index: EpssIndex = new Map();
  try {
    for (let i = 0; i < cveIds.length; i += EPSS_BATCH) {
      const batch = cveIds.slice(i, i + EPSS_BATCH);
      const res = await fetch(`${EPSS_API_URL}?cve=${batch.map(encodeURIComponent).join(",")}`, {
        signal: AbortSignal.timeout(EPSS_TIMEOUT_MS),
      });
      if (!res.ok) return index.size > 0 ? index : null;
      for (const [cve, score] of parseEpss(await res.json())) index.set(cve, score);
    }
    return index;
  } catch {
    return index.size > 0 ? index : null;
  }
}

/**
 * Pure: attach threat intel to each CVE-backed finding from already-loaded
 * indexes. A null index means that source was unavailable — its fields are
 * left out rather than guessed. With neither source, nothing is attached.
 */
export function applyThreatIntel(findings: Finding[], kev: KevIndex | null, epss: EpssIndex | null): void {
  if (!kev && !epss) return;
  for (const finding of findings) {
    const cves = (finding.cveIds ?? []).map((c) => c.toUpperCase()).filter((c) => CVE_RE.test(c));
    if (cves.length === 0) continue;

    const intel: NonNullable<Finding["threatIntel"]> = { knownExploited: false };
    if (kev) {
      const listed = cves.filter((c) => kev.has(c));
      intel.knownExploited = listed.length > 0;
      if (listed.length > 0) {
        intel.kevCveIds = listed;
        if (listed.some((c) => kev.get(c)!.ransomware)) intel.ransomware = true;
      }
    }
    if (epss) {
      let best: { epss: number; percentile: number } | undefined;
      for (const c of cves) {
        const score = epss.get(c);
        if (score && (!best || score.epss > best.epss)) best = score;
      }
      if (best) {
        intel.epss = best.epss;
        intel.epssPercentile = best.percentile;
      }
    }
    // KEV unavailable and no EPSS score either: we learned nothing.
    if (!kev && intel.epss === undefined) continue;
    finding.threatIntel = intel;
  }
}

export async function enrichFindingsWithThreatIntel(findings: Finding[], now: number = Date.now()): Promise<void> {
  const cves = [
    ...new Set(
      findings.flatMap((f) => f.cveIds ?? []).map((c) => c.toUpperCase()).filter((c) => CVE_RE.test(c))
    ),
  ];
  if (cves.length === 0) return;
  const [kev, epss] = await Promise.all([loadKev(now), loadEpss(cves)]);
  applyThreatIntel(findings, kev, epss);
}

/** Test hook: forget the cached KEV feed. */
export function resetThreatIntelCache(): void {
  kevCache = null;
}
