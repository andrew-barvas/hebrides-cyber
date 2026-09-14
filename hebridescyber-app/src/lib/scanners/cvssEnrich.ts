// E-55: CVSS score enrichment for CVE-backed findings. Fetches CVSS v3.1
// base scores from the NVD API for findings that carry cveIds. Applied as
// a final pass over findings (same pattern as compliance.ts), not at push
// time, so older scans without this field still deserialise correctly.
//
// Rate-limited by NVD's public API (10 req/min without a key, 50 with).
// We batch all unique CVE IDs and look up once per CVE, caching results.

const NVD_TIMEOUT_MS = 8_000;
const cache = new Map<string, { score: number; vector: string } | null>();

type NvdCveItem = {
  cve?: {
    metrics?: {
      cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; vectorString?: string } }>;
      cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; vectorString?: string } }>;
    };
  };
};

async function fetchCvss(cveId: string): Promise<{ score: number; vector: string } | null> {
  const cached = cache.get(cveId);
  if (cached !== undefined) return cached;

  try {
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      { signal: AbortSignal.timeout(NVD_TIMEOUT_MS) }
    );
    if (!res.ok) { cache.set(cveId, null); return null; }

    const body = (await res.json()) as { vulnerabilities?: NvdCveItem[] };
    const item = body.vulnerabilities?.[0];
    const m31 = item?.cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
    const m30 = item?.cve?.metrics?.cvssMetricV30?.[0]?.cvssData;
    const data = m31 ?? m30;
    if (!data?.baseScore || !data?.vectorString) { cache.set(cveId, null); return null; }

    const result = { score: data.baseScore, vector: data.vectorString };
    cache.set(cveId, result);
    return result;
  } catch {
    cache.set(cveId, null);
    return null;
  }
}

import type { Finding } from "./index";

export async function enrichFindingsWithCvss(findings: Finding[]): Promise<void> {
  const withCves = findings.filter((f) => f.cveIds && f.cveIds.length > 0 && !f.cvssScore);
  if (withCves.length === 0) return;

  const uniqueCves = [...new Set(withCves.flatMap((f) => f.cveIds!))];

  // Lookup sequentially to respect NVD rate limits
  for (const cveId of uniqueCves.slice(0, 20)) {
    await fetchCvss(cveId);
  }

  for (const finding of withCves) {
    for (const cveId of finding.cveIds!) {
      const result = cache.get(cveId);
      if (result) {
        finding.cvssScore = result.score;
        finding.cvssVector = result.vector;
        break;
      }
    }
  }
}
