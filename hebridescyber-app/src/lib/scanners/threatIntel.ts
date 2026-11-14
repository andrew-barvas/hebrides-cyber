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
/**
 * Exploit-DB's public index (about 10 MB, one row per entry, CVE ids in
 * `codes`). Only this CSV is read: no exploit file is downloaded or run. A
 * listing means "public exploit code exists", which ranks a fix higher beside
 * KEV and EPSS. Severity is never changed.
 */
export const EXPLOITDB_INDEX_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
const EXPLOITDB_TIMEOUT_MS = 30_000;
const EXPLOITDB_CACHE_MS = 24 * 60 * 60 * 1000;
/** Ids kept per CVE; the count beyond this adds nothing for prioritising. */
const EXPLOITDB_IDS_PER_CVE = 5;
export type ExploitDbIndex = Map<string, string[]>;
let exploitDbCache: { at: number; index: ExploitDbIndex } | null = null;

/**
 * PoC-in-GitHub (nomi-sec, CC0): one JSON file per CVE that has public
 * proof-of-concept code on GitHub. Only the repository's file list is read,
 * in one GitHub API call (about 12,000 paths, under 3 MB); no file and no
 * exploit code is downloaded. Cached 24 hours, like the Exploit-DB index.
 */
export const POC_IN_GITHUB_TREE_URL = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1";
const POC_TIMEOUT_MS = 30_000;
export type PocIndex = Set<string>;
let pocCache: { at: number; index: PocIndex } | null = null;

const KEV_TIMEOUT_MS = 15_000;
const EPSS_TIMEOUT_MS = 8_000;
/** EPSS accepts a comma-separated list; keep URLs well under 2k chars. */
const EPSS_BATCH = 50;
/** The feed changes at most daily; one worker run never needs it twice. */
const KEV_CACHE_MS = 6 * 60 * 60 * 1000;

type KevEntry = {
  cveID: string;
  knownRansomwareCampaignUse?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
};
/**
 * `ransomware` is all the finding pass needs. The descriptive fields are kept
 * for src/lib/emergingThreats.ts, which alerts on catalog additions by date —
 * absent when the feed omits them, never filled with a placeholder.
 */
export type KevRecord = {
  ransomware: boolean;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  /** YYYY-MM-DD, the day CISA added the CVE to the catalog. */
  dateAdded?: string;
};
export type KevIndex = Map<string, KevRecord>;
export type EpssIndex = Map<string, { epss: number; percentile: number }>;

let kevCache: { at: number; index: KevIndex } | null = null;

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const KEV_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const text = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

export function parseKev(body: unknown): KevIndex {
  const index: KevIndex = new Map();
  const list = (body as { vulnerabilities?: KevEntry[] } | null)?.vulnerabilities;
  if (!Array.isArray(list)) return index;
  for (const entry of list) {
    if (typeof entry?.cveID !== "string" || !CVE_RE.test(entry.cveID)) continue;
    const dateAdded = text(entry.dateAdded);
    index.set(entry.cveID.toUpperCase(), {
      ransomware: entry.knownRansomwareCampaignUse === "Known",
      vendorProject: text(entry.vendorProject),
      product: text(entry.product),
      vulnerabilityName: text(entry.vulnerabilityName),
      dateAdded: dateAdded && KEV_DATE_RE.test(dateAdded) ? dateAdded : undefined,
    });
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

/**
 * The whole KEV catalog, cached for KEV_CACHE_MS per process. Null when the
 * feed couldn't be read or parsed — callers must treat that as "unknown",
 * never as "nothing is exploited".
 */
export async function loadKev(now: number = Date.now()): Promise<KevIndex | null> {
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

/**
 * Pure: CVE id -> Exploit-DB ids from the index CSV. Reads only the header to
 * find the `id` and `codes` columns, and splits rows with a quote-aware
 * scanner (descriptions contain commas and quotes).
 */
export function parseExploitDbIndex(csv: string): ExploitDbIndex {
  const index: ExploitDbIndex = new Map();
  const rows = csvRows(csv);
  const header = rows.next().value;
  if (!header) return index;
  const idCol = header.indexOf("id");
  const codesCol = header.indexOf("codes");
  if (idCol < 0 || codesCol < 0) return index;
  for (const row of rows) {
    const id = row[idCol];
    if (!id || !/^\d+$/.test(id)) continue;
    for (const code of (row[codesCol] ?? "").split(";")) {
      const cve = code.trim().toUpperCase();
      if (!CVE_RE.test(cve)) continue;
      const ids = index.get(cve) ?? [];
      if (ids.length < EXPLOITDB_IDS_PER_CVE && !ids.includes(id)) ids.push(id);
      index.set(cve, ids);
    }
  }
  return index;
}

function* csvRows(text: string): Generator<string[]> {
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      yield row;
      row = [];
      field = "";
    } else field += ch;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    yield row;
  }
}

/** Pure: CVE ids from the tree listing. Null when the listing was truncated or empty (not "no PoCs"). */
export function parsePocTree(body: unknown): PocIndex | null {
  const b = body as { truncated?: boolean; tree?: Array<{ path?: string; type?: string }> } | null;
  if (!b || b.truncated !== false || !Array.isArray(b.tree)) return null;
  const index: PocIndex = new Set();
  for (const t of b.tree) {
    const m = t.type === "blob" && typeof t.path === "string" ? /^\d{4}\/(CVE-\d{4}-\d{4,})\.json$/i.exec(t.path) : null;
    if (m) index.add(m[1].toUpperCase());
  }
  return index.size > 0 ? index : null;
}

export async function loadPocIndex(now: number = Date.now()): Promise<PocIndex | null> {
  if (pocCache && now - pocCache.at < EXPLOITDB_CACHE_MS) return pocCache.index;
  try {
    const res = await fetch(POC_IN_GITHUB_TREE_URL, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "HebridesCyberBot/1.0" },
      signal: AbortSignal.timeout(POC_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const index = parsePocTree(await res.json());
    if (index) pocCache = { at: now, index };
    return index;
  } catch {
    return null;
  }
}

export async function loadExploitDb(now: number = Date.now()): Promise<ExploitDbIndex | null> {
  if (exploitDbCache && now - exploitDbCache.at < EXPLOITDB_CACHE_MS) return exploitDbCache.index;
  try {
    const res = await fetch(EXPLOITDB_INDEX_URL, { signal: AbortSignal.timeout(EXPLOITDB_TIMEOUT_MS) });
    if (!res.ok) return null;
    const index = parseExploitDbIndex(await res.text());
    // An empty parse means the file changed shape, not "no public exploits".
    if (index.size === 0) return null;
    exploitDbCache = { at: now, index };
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
export function applyThreatIntel(
  findings: Finding[],
  kev: KevIndex | null,
  epss: EpssIndex | null,
  exploitDb: ExploitDbIndex | null = null,
  poc: PocIndex | null = null
): void {
  if (!kev && !epss && !exploitDb && !poc) return;
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
    // Each source's field is set only when that source loaded: absent means not checked.
    if (exploitDb || poc) {
      intel.publicExploit = {
        ...(exploitDb ? { exploitDbIds: [...new Set(cves.flatMap((c) => exploitDb.get(c) ?? []))] } : {}),
        ...(poc ? { githubPoc: cves.some((c) => poc.has(c)) } : {}),
      };
    }
    // No source answered for this finding: we learned nothing.
    if (!kev && intel.epss === undefined && !exploitDb && !poc) continue;
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
  const [kev, epss, exploitDb, poc] = await Promise.all([loadKev(now), loadEpss(cves), loadExploitDb(now), loadPocIndex(now)]);
  applyThreatIntel(findings, kev, epss, exploitDb, poc);
}

/** Test hook: forget the cached KEV feed. */
export function resetThreatIntelCache(): void {
  kevCache = null;
  exploitDbCache = null;
  pocCache = null;
}
