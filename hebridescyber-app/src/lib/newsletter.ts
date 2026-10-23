// Builds the daily cyber security blog post. Grounded primarily in REAL
// external events — the CISA Known Exploited Vulnerabilities catalog, recent
// high-severity CVEs from NVD, and real breach/incident coverage from
// established security news RSS feeds — with the product's own aggregate
// scan stats as a secondary, supporting section, not the main structure.
// Runs daily now (see .github/workflows/daily-blog.yml), not weekly — this
// file used to be "weekly stats first, KEV as a bonus section"; it's now
// "real recent events first, our own stats as a closer."
//
// Same finding-severity vocabulary used throughout src/lib/scanners/ drives
// the stats section; the AI prompt (if Azure OpenAI is configured) is
// grounded in the same real, fetched data — never asked to invent an
// incident. Falls back to a deterministic templated post (still built from
// the real fetched data, just without AI prose) if Azure OpenAI isn't
// configured — a post should never fail to publish just because a model
// call did. Every external fetch (CISA, NVD, RSS feeds) follows the same
// contract: any failure degrades to an empty result, never a thrown error,
// so one dead source can't block publishing.
import type { SupabaseClient } from "@supabase/supabase-js";
import { DETECTABLE_TECHNOLOGIES } from "./scanners/fingerprint";
import { escapeHtml } from "./email";

export type NewsletterPost = {
  slug: string;
  title: string;
  excerpt: string;
  body: string;
};

type AggregateStats = {
  totalScans: number;
  findingsBySeverity: Record<string, number>;
  topFindingTitles: Array<{ title: string; count: number }>;
};

// ---------------------------------------------------------------------------
// CISA Known Exploited Vulnerabilities
// ---------------------------------------------------------------------------

/** One entry from CISA's Known Exploited Vulnerabilities catalog. */
export type KevEntry = {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  dateAdded: string;
  dueDate: string | null;
};

/** A KEV entry paired with the fingerprint.ts technology name it matches, if any. */
export type KevMatch = {
  entry: KevEntry;
  matchedTech: string | null;
};

const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/**
 * Fetches CISA's Known Exploited Vulnerabilities catalog and returns entries
 * added to the catalog within the last `daysBack` days. Free, no-auth,
 * structured JSON, updated as CISA confirms real-world exploitation of
 * specific CVEs.
 *
 * Never throws — matches this file's never-fails-to-publish contract. Any
 * network error, non-OK response, or malformed payload degrades to an
 * empty array rather than blocking generation.
 */
export async function fetchRecentKevEntries(daysBack = 7): Promise<KevEntry[]> {
  try {
    const res = await fetch(CISA_KEV_URL, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return [];

    const json = (await res.json()) as {
      vulnerabilities?: Array<{
        cveID?: string;
        vendorProject?: string;
        product?: string;
        vulnerabilityName?: string;
        shortDescription?: string;
        dateAdded?: string;
        dueDate?: string;
      }>;
    };

    const cutoff = Date.now() - daysBack * 24 * 60 * 60 * 1000;

    return (json.vulnerabilities ?? [])
      .filter((v) => {
        if (!v.dateAdded) return false;
        const added = Date.parse(v.dateAdded);
        return !Number.isNaN(added) && added >= cutoff;
      })
      .map((v) => ({
        cveId: v.cveID ?? "Unknown CVE",
        vendorProject: v.vendorProject ?? "Unknown vendor",
        product: v.product ?? "Unknown product",
        vulnerabilityName: v.vulnerabilityName ?? "Unnamed vulnerability",
        shortDescription: v.shortDescription ?? "",
        dateAdded: v.dateAdded ?? "",
        dueDate: v.dueDate || null,
      }));
  } catch {
    return [];
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// A handful of fingerprint.ts technology names are ambiguous by themselves —
// "Apache" detects the Apache HTTP Server (httpd) specifically via the
// Server response header, but the Apache Software Foundation also ships
// many unrelated products (Tomcat, Struts, Kafka, ActiveMQ, ...) that share
// the "Apache" name in KEV's vendorProject field without being httpd at
// all. Confirmed live against the real KEV feed: a "CVE-... Apache Tomcat"
// entry naively substring-matched "Apache" and would have falsely implied
// this product's Apache detection covers Tomcat vulnerabilities. Excluding
// these known non-httpd ASF projects avoids that overclaim.
const APACHE_NON_HTTPD_PROJECTS = [
  "tomcat",
  "struts",
  "kafka",
  "activemq",
  "camel",
  "solr",
  "spark",
  "hadoop",
  "cassandra",
  "airflow",
  "nifi",
  "ignite",
  "zookeeper",
  "cxf",
  "log4j",
  "shiro",
  "ofbiz",
];

/**
 * Cross-references KEV entries' vendor/product fields against the flat list
 * of technologies src/lib/scanners/fingerprint.ts can actually detect. A
 * match means we can honestly say "we detect this" in the post; no match
 * means the entry can still be mentioned for general awareness but must not
 * imply product coverage that doesn't exist.
 */
export function correlateKevWithFingerprint(entries: KevEntry[]): KevMatch[] {
  return entries.map((entry) => {
    const haystack = `${entry.vendorProject} ${entry.product}`;
    const productLower = entry.product.toLowerCase();

    const matchedTech =
      DETECTABLE_TECHNOLOGIES.find((name) => {
        if (!new RegExp(`\\b${escapeRegExp(name)}\\b`, "i").test(haystack)) return false;
        // "Apache" is ambiguous — only count it when the product isn't one
        // of the well-known non-httpd Apache Software Foundation projects
        // our fingerprint check has no way of distinguishing from httpd.
        if (name === "Apache" && APACHE_NON_HTTPD_PROJECTS.some((p) => productLower.includes(p))) {
          return false;
        }
        return true;
      }) ?? null;

    return { entry, matchedTech };
  });
}

// ---------------------------------------------------------------------------
// NVD recent high-severity CVEs
// ---------------------------------------------------------------------------

export type NvdCve = {
  cveId: string;
  description: string;
  cvssScore: number | null;
  severity: string | null;
  published: string;
};

/**
 * Fetches recently *published* CVEs from NIST's National Vulnerability
 * Database, filtered to high/critical severity (CVSS >= 7.0) — NVD publishes
 * hundreds of CVEs a day and most are low-severity or affect software no
 * reader here runs, so this exists to cut that down to what's actually worth
 * a small business's attention. Free, no API key required at this call
 * volume (NVD's public rate limit is 5 requests/30s without a key — a daily
 * cron making one request is well inside that).
 *
 * Never throws, same degrade-to-empty contract as the rest of this file.
 */
type NvdMetrics = {
  cvssMetricV40?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
  cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
  cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
  cvssMetricV2?: Array<{ cvssData?: { baseScore?: number } }>;
};

/**
 * Highest CVSS base score NVD lists for a CVE, across v4.0, v3.1, v3.0 and v2.
 * v4.0 has to be read: a CVE scored only under v4 used to look unscored and was
 * dropped, and the PHP2Shell flaws (October 2026) carry a v4.0 9.2 alongside
 * their v3.1 9.8. Taking the highest across all of them errs towards surfacing.
 */
export function extractCvssScore(metrics: NvdMetrics | undefined): { score: number | null; severity: string | null } {
  const candidates: Array<{ score: number; severity: string | null }> = [];
  for (const list of [metrics?.cvssMetricV40, metrics?.cvssMetricV31, metrics?.cvssMetricV30, metrics?.cvssMetricV2]) {
    for (const m of list ?? []) {
      const score = m.cvssData?.baseScore;
      if (typeof score === "number") candidates.push({ score, severity: (m.cvssData as { baseSeverity?: string }).baseSeverity ?? null });
    }
  }
  if (candidates.length === 0) return { score: null, severity: null };
  const best = candidates.reduce((a, b) => (b.score > a.score ? b : a));
  return { score: best.score, severity: best.severity ?? severityFromScore(best.score) };
}

type NvdResponse = {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      published?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      metrics?: NvdMetrics;
    };
  }>;
};

/** Parse an NVD 2.0 response into scored CVEs at or above `minScore`. */
export function parseNvdCves(json: NvdResponse, minScore = 7.0, includeUnscored = false): NvdCve[] {
  return (json.vulnerabilities ?? [])
    .map((v) => {
      const cve = v.cve;
      const { score, severity } = extractCvssScore(cve?.metrics);
      return {
        cveId: cve?.id ?? "",
        description: (cve?.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "",
        cvssScore: score,
        severity,
        published: cve?.published ?? "",
      };
    })
    .filter((c) => c.cveId && (c.cvssScore === null ? includeUnscored : c.cvssScore >= minScore));
}

/**
 * Software a small business's website or office network is likely to run. A
 * CVE naming one of these is worth more to this audience than an unrelated
 * product with the same score: ten CVSS-10 entries in obscure products had
 * pushed the PHP2Shell flaws (9.8) out of a six-item list.
 */
const SMB_STACK_TERMS =
  /\b(php|wordpress|woocommerce|joomla|drupal|magento|shopify|apache|nginx|openssl|openssh|mysql|mariadb|postgres(?:ql)?|node\.js|next\.js|laravel|wp-|microsoft exchange|office 365|windows|fortinet|fortigate|citrix|sonicwall|palo alto|cisco|vpn|router|firewall|chrome|firefox|log4j|spring)\b/i;

/** Sort key for a CVE: its score, plus a boost when it names common small-business software. */
export function cveRankScore(c: NvdCve): number {
  return (c.cvssScore ?? 0) + (SMB_STACK_TERMS.test(c.description) ? 2.5 : 0);
}

/** De-duplicate by CVE id (keeping the highest score), most relevant first, capped. */
export function mergeNvdCves(lists: NvdCve[][], cap = 6): NvdCve[] {
  const byId = new Map<string, NvdCve>();
  for (const c of lists.flat()) {
    const existing = byId.get(c.cveId);
    if (!existing || (c.cvssScore ?? 0) > (existing.cvssScore ?? 0)) byId.set(c.cveId, c);
  }
  return [...byId.values()].sort((a, b) => cveRankScore(b) - cveRankScore(a)).slice(0, cap);
}

// NVD publishes hundreds of CVEs a day (495 in one 24 hours in October 2026) and
// returns them unsorted, 200 to a page. Reading the first page and sorting it
// meant a critical CVE was missed whenever it fell past the first 200 (PHP2Shell,
// CVE-2026-109618, was). NVD can filter by severity server-side, so ask for the
// severe ones directly. NVD allows one CVSS version filter per request, hence
// one request per entry here; without an API key the limit is 5 requests per
// 30 seconds, so they are spaced out.
const NVD_QUERIES: Array<{ param: string; label: string }> = [
  { param: "cvssV3Severity=CRITICAL", label: "v3 critical" },
  { param: "cvssV4Severity=CRITICAL", label: "v4 critical" },
  { param: "cvssV3Severity=HIGH", label: "v3 high" },
];
// NVD_PAUSE_MS overrides the spacing (tests set 0); with an NVD API key it could be shortened.
const nvdPauseMs = (): number => Number(process.env.NVD_PAUSE_MS ?? 6_500);

export async function fetchRecentHighSeverityCves(daysBack = 2, options: { pauseMs?: number } = {}): Promise<NvdCve[]> {
  const pauseMs = options.pauseMs ?? nvdPauseMs();
  const end = new Date();
  const start = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);
  const lists: NvdCve[][] = [];

  for (let i = 0; i < NVD_QUERIES.length; i++) {
    if (i > 0 && pauseMs > 0) await new Promise((r) => setTimeout(r, pauseMs));
    try {
      const url =
        `https://services.nvd.nist.gov/rest/json/cves/2.0` +
        `?pubStartDate=${encodeURIComponent(start.toISOString())}` +
        `&pubEndDate=${encodeURIComponent(end.toISOString())}` +
        `&${NVD_QUERIES[i].param}&resultsPerPage=100`;
      const res = await fetch(url, {
        signal: AbortSignal.timeout(15_000),
        headers: { "User-Agent": "HebridesCyberBot/1.0 (+https://hebridescyber.co.uk)" },
      });
      // One failed query costs that slice only; the others still count.
      if (!res.ok) continue;
      lists.push(parseNvdCves((await res.json()) as NvdResponse));
    } catch {
      continue;
    }
  }
  return mergeNvdCves(lists);
}

/** CVE ids named in the titles and summaries of news items, upper-cased, de-duplicated, in first-seen order. */
export function citedCveIds(news: NewsArticle[]): string[] {
  const ids: string[] = [];
  for (const n of news) {
    for (const id of `${n.title} ${n.summary}`.match(/CVE-\d{4}-\d{4,}/gi) ?? []) {
      const upper = id.toUpperCase();
      if (!ids.includes(upper)) ids.push(upper);
    }
  }
  return ids;
}

/**
 * Look up specific CVEs by id. Used for CVEs the news is already talking about:
 * ranking CVEs by score alone filled the list with unrelated CVSS 10.0 entries
 * and left out the widely reported PHP2Shell flaws (9.8), so a CVE a reputable
 * outlet names is added regardless of its score or whether NVD has scored it.
 * Never throws; a failed lookup is just absent.
 */
export async function fetchCvesByIds(ids: string[], options: { pauseMs?: number } = {}): Promise<NvdCve[]> {
  const pauseMs = options.pauseMs ?? nvdPauseMs();
  const out: NvdCve[] = [];
  for (let i = 0; i < ids.length; i++) {
    if (pauseMs > 0) await new Promise((r) => setTimeout(r, pauseMs));
    try {
      const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(ids[i])}`, {
        signal: AbortSignal.timeout(15_000),
        headers: { "User-Agent": "HebridesCyberBot/1.0 (+https://hebridescyber.co.uk)" },
      });
      if (!res.ok) continue;
      out.push(...parseNvdCves((await res.json()) as NvdResponse, 0, true));
    } catch {
      continue;
    }
  }
  return out;
}

/** The score-ranked list, with CVEs the news cites placed first and the whole list capped. */
export function withCitedCves(ranked: NvdCve[], cited: NvdCve[], cap = 8): NvdCve[] {
  const citedIds = new Set(cited.map((c) => c.cveId));
  return [...cited, ...ranked.filter((c) => !citedIds.has(c.cveId))].slice(0, cap);
}

async function attachCitedCves(nvdCves: NvdCve[], news: NewsArticle[]): Promise<NvdCve[]> {
  const known = new Set(nvdCves.map((c) => c.cveId));
  const cited = citedCveIds(news).slice(0, 4);
  // Already in the list: keep, but move to the front as "cited".
  const alreadyHave = nvdCves.filter((c) => cited.includes(c.cveId));
  const missing = cited.filter((id) => !known.has(id)).slice(0, 3);
  const fetched = missing.length > 0 ? await fetchCvesByIds(missing) : [];
  return withCitedCves(nvdCves, [...fetched, ...alreadyHave]);
}

function severityFromScore(score: number): string {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

// ---------------------------------------------------------------------------
// Real breach/incident news via RSS
// ---------------------------------------------------------------------------

export type NewsArticle = {
  title: string;
  link: string;
  source: string;
  publishedAt: string;
  summary: string;
  /** "status" for a cloud provider's own incident feed; absent or "news" for articles. */
  kind?: "news" | "status";
};

// Deliberately not a huge list — a handful of established, high-signal
// security news sources rather than a broad scrape. Each publishes a
// standard RSS 2.0 feed with no auth required.
const SECURITY_NEWS_FEEDS: Array<{ name: string; url: string }> = [
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
  { name: "SecurityWeek", url: "https://www.securityweek.com/feed/" },
  { name: "Help Net Security", url: "https://www.helpnetsecurity.com/feed/" },
  { name: "The Register (security)", url: "https://www.theregister.com/security/headlines.atom" },
];

// Official cloud status feeds. A multi-hour Google Cloud outage that took down UK
// banks and public services (20 October 2026) was missed entirely because the
// pipeline only read vulnerability and breach news. These are the providers'
// own incident feeds, so the post can cite the primary source.
const CLOUD_STATUS_FEEDS: Array<{ name: string; url: string }> = [
  { name: "Google Cloud status", url: "https://status.cloud.google.com/en/feed.atom" },
  { name: "Azure status", url: "https://azure.status.microsoft/en-gb/status/feed/" },
  { name: "AWS status", url: "https://status.aws.amazon.com/rss/all.rss" },
];

function extractTag(block: string, tag: string): string | null {
  const match = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i").exec(block);
  return match ? match[1].trim() : null;
}

function stripCdata(s: string): string {
  return s.replace(/^<!\[CDATA\[/, "").replace(/\]\]>$/, "").trim();
}

function stripHtmlTags(s: string): string {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&nbsp;/g, " ");
}

/**
 * Minimal, dependency-free feed item extractor for RSS 2.0 (`<item>`) and Atom
 * (`<entry>`) — regex-based rather than pulling in an XML parsing library,
 * matching this codebase's established preference (see action/index.js's
 * header comment for the same reasoning applied to the packaged GitHub
 * Action). Good enough for the small, stable set of well-formed feeds this
 * queries; a malformed or unexpected item is simply skipped rather than
 * throwing. Atom was added for Google Cloud's status feed.
 */
export function parseFeedItems(xml: string, sourceName: string, daysBack: number, kind: "news" | "status" = "news"): NewsArticle[] {
  const items: NewsArticle[] = [];
  const cutoff = Date.now() - daysBack * 24 * 60 * 60 * 1000;
  const itemRegex = /<(item|entry)(?:\s[^>]*)?>([\s\S]*?)<\/\1>/g;

  let match: RegExpExecArray | null;
  while (items.length < 20 && (match = itemRegex.exec(xml)) !== null) {
    const isAtom = match[1] === "entry";
    const block = match[2];
    const rawTitle = extractTag(block, "title");
    const rawDate = isAtom ? (extractTag(block, "updated") ?? extractTag(block, "published")) : extractTag(block, "pubDate");
    const rawBody = isAtom ? (extractTag(block, "summary") ?? extractTag(block, "content")) : extractTag(block, "description");
    const rawLink = isAtom ? (/<link\b[^>]*\bhref="([^"]+)"/i.exec(block)?.[1] ?? null) : extractTag(block, "link");

    if (!rawTitle || !rawDate) continue;

    const published = Date.parse(rawDate);
    if (Number.isNaN(published) || published < cutoff) continue;

    items.push({
      title: decodeXmlEntities(stripCdata(rawTitle)),
      link: rawLink ? decodeXmlEntities(stripCdata(rawLink)) : "",
      source: sourceName,
      publishedAt: new Date(published).toISOString(),
      summary: rawBody ? decodeXmlEntities(stripHtmlTags(stripCdata(rawBody))).slice(0, 300) : "",
      kind,
    });
  }

  return items;
}

async function fetchOneFeed(name: string, url: string, daysBack: number, kind: "news" | "status"): Promise<NewsArticle[]> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(10_000),
      headers: { "User-Agent": "HebridesCyberBot/1.0 (+https://hebridescyber.co.uk)" },
    });
    if (!res.ok) return [];
    const xml = await res.text();
    return parseFeedItems(xml, name, daysBack, kind);
  } catch {
    return [];
  }
}

const SEVERE_TERMS = /\b(zero-day|0-day|actively exploited|exploited in the wild|remote code execution|rce|unauthenticated|critical|emergency|ransomware|supply[- ]chain|data breach|breach|leaked)\b/i;
const OUTAGE_TERMS = /\b(outage|disruption|degraded|unavailable|multiple services|service health)\b/i;
/** Status-feed entries that mean nothing happened (AWS publishes these routinely). */
const ROUTINE_STATUS = /operating normally|no issues|informational message/i;

/**
 * How much a story deserves a place in a capped list. The old behaviour was
 * newest-first, so a major story from yesterday lost its slot to eight minor
 * items from today. CVE ids, exploitation/RCE language and real outages now
 * count for more than recency; recency is only a tie-breaker and a small boost.
 * Returns a negative score for routine status noise so it is dropped.
 */
export function scoreNewsArticle(a: NewsArticle, now: number = Date.now()): number {
  const text = `${a.title} ${a.summary}`;
  if (a.kind === "status" && ROUTINE_STATUS.test(text)) return -1;
  let score = 0;
  const cves = new Set(text.match(/CVE-\d{4}-\d{4,}/gi) ?? []);
  score += Math.min(cves.size, 3) * 3;
  if (SEVERE_TERMS.test(text)) score += 3;
  if (a.kind === "status") score += 5 + (OUTAGE_TERMS.test(text) ? 2 : 0);
  else if (OUTAGE_TERMS.test(text)) score += 2;
  const ageHours = (now - Date.parse(a.publishedAt)) / 3_600_000;
  if (ageHours < 24) score += 2;
  else if (ageHours < 48) score += 1;
  return score;
}

/** Highest-scoring first (ties newest first), de-duplicated by normalised title, routine status noise dropped, capped. */
export function rankNews(articles: NewsArticle[], cap: number, now: number = Date.now()): NewsArticle[] {
  const scored = articles
    .map((a) => ({ a, score: scoreNewsArticle(a, now) }))
    .filter((x) => x.score >= 0)
    .sort((x, y) => y.score - x.score || Date.parse(y.a.publishedAt) - Date.parse(x.a.publishedAt));

  const seen = new Set<string>();
  const ranked: NewsArticle[] = [];
  for (const { a } of scored) {
    const key = a.title.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (seen.has(key)) continue;
    seen.add(key);
    ranked.push(a);
  }
  return ranked.slice(0, cap);
}

/**
 * Fetches recent items across all configured security-news and cloud-status
 * feeds, then keeps the ones that matter most (rankNews) rather than just the
 * newest. One dead feed never blocks the others — Promise.allSettled.
 */
export async function fetchRecentSecurityNews(daysBack = 3, cap = 10): Promise<NewsArticle[]> {
  const results = await Promise.allSettled([
    ...SECURITY_NEWS_FEEDS.map((f) => fetchOneFeed(f.name, f.url, daysBack, "news")),
    // Status feeds: at most three entries each, so a chatty feed can't flood the list.
    ...CLOUD_STATUS_FEEDS.map((f) => fetchOneFeed(f.name, f.url, daysBack, "status").then((items) => items.slice(0, 3))),
  ]);
  const articles = results.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
  return rankNews(articles, cap);
}

// ---------------------------------------------------------------------------
// Own product stats — supporting section, not the main structure
// ---------------------------------------------------------------------------

/** Pulls the past 7 days of scan_results and tallies findings by severity/title. */
async function collectRecentScanStats(supabaseAdmin: SupabaseClient): Promise<AggregateStats> {
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const { data: rows } = await supabaseAdmin
    .from("scan_results")
    .select("results, created_at")
    .gte("created_at", since);

  const findingsBySeverity: Record<string, number> = {};
  const titleCounts = new Map<string, number>();

  for (const row of rows ?? []) {
    const findings = (row.results as { findings?: Array<{ severity: string; title: string }> })?.findings ?? [];
    for (const f of findings) {
      findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] ?? 0) + 1;
      titleCounts.set(f.title, (titleCounts.get(f.title) ?? 0) + 1);
    }
  }

  const topFindingTitles = [...titleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([title, count]) => ({ title, count }));

  return { totalScans: rows?.length ?? 0, findingsBySeverity, topFindingTitles };
}

// ---------------------------------------------------------------------------
// Post generation
// ---------------------------------------------------------------------------

/**
 * Daily cyber security blog (.github/workflows/daily-blog.yml) — today's/
 * last couple of days' real events: news, freshly-published high-severity
 * CVEs, and any new KEV entries. Distinct from the weekly newsletter below,
 * not a replacement for it — narrower lookback window, day-by-day framing.
 */
export async function generateDailyBlogPost(supabaseAdmin: SupabaseClient): Promise<NewsletterPost> {
  const [stats, kevEntries, rankedCves, news] = await Promise.all([
    collectRecentScanStats(supabaseAdmin),
    fetchRecentKevEntries(7), // KEV entries are sparse day-to-day; keep a wider net so a real one isn't missed
    // Two days, not one: the run time drifts, and a one-day window left gaps a CVE could fall through.
    fetchRecentHighSeverityCves(2),
    fetchRecentSecurityNews(3, 10),
  ]);
  const nvdCves = await attachCitedCves(rankedCves, news);
  const kevMatches = correlateKevWithFingerprint(kevEntries);

  const dateLabel = new Date().toISOString().slice(0, 10);
  const slug = `cyber-brief-${dateLabel}`;

  const hasRealEventContent = kevMatches.length > 0 || nvdCves.length > 0 || news.length > 0;
  const body = await draftBody(stats, kevMatches, nvdCves, news, "daily");
  const title = hasRealEventContent
    ? `Cyber Security Brief — ${dateLabel}`
    : `Small Business Security Check-In — ${dateLabel}`;

  const leadStory = news[0]?.title ?? kevMatches[0]?.entry.vulnerabilityName ?? nvdCves[0]?.cveId;
  const excerpt = leadStory
    ? `Today's brief: ${leadStory}${news.length + kevMatches.length + nvdCves.length > 1 ? ", plus more from the last few days." : "."}`
    : `A quiet day for major security news — here's how our own customers' sites are doing instead.`;

  return { slug, title, excerpt, body };
}

/**
 * Weekly newsletter (.github/workflows/weekly-newsletter.yml) — a broader
 * roundup of the past 7 days' real events plus a fuller look at our own
 * customers' aggregate scan stats. Separate from the daily blog above: same
 * underlying real-event sourcing (KEV/NVD/news), wider lookback window,
 * weekly framing, its own slug so the two never collide even when published
 * on the same day.
 */
export async function generateWeeklyNewsletterPost(supabaseAdmin: SupabaseClient): Promise<NewsletterPost> {
  const [stats, kevEntries, rankedCves, news] = await Promise.all([
    collectRecentScanStats(supabaseAdmin),
    fetchRecentKevEntries(7),
    fetchRecentHighSeverityCves(7),
    fetchRecentSecurityNews(7, 12),
  ]);
  const nvdCves = await attachCitedCves(rankedCves, news);
  const kevMatches = correlateKevWithFingerprint(kevEntries);

  const weekLabel = new Date().toISOString().slice(0, 10);
  const slug = `week-of-${weekLabel}`;

  const body = await draftBody(stats, kevMatches, nvdCves, news, "weekly");
  const title = `This Week in Small Business Security — ${weekLabel}`;
  const leadStory = news[0]?.title ?? kevMatches[0]?.entry.vulnerabilityName ?? nvdCves[0]?.cveId;
  const excerpt = leadStory
    ? `This week: ${leadStory}, plus ${stats.totalScans} sites scanned and what we found.`
    : `${stats.totalScans} sites scanned this week — here's what stood out.`;

  return { slug, title, excerpt, body };
}

async function draftBody(
  stats: AggregateStats,
  kevMatches: KevMatch[],
  nvdCves: NvdCve[],
  news: NewsArticle[],
  cadence: "daily" | "weekly"
): Promise<string> {
  const fallback = buildDeterministicPost(stats, kevMatches, nvdCves, news, cadence);

  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  if (!endpoint || !apiKey || !deployment) return fallback;

  const lookbackLabel = cadence === "daily" ? "the last couple of days" : "the past week";

  const newsContext =
    news.length > 0
      ? `\n\nReal security news from ${lookbackLabel} (source, title, summary — cite the source by name for anything you use, never invent an article that isn't in this list):\n` +
        news.map((a) => `- [${a.source}] "${a.title}" — ${a.summary || "(no summary available)"} (${a.link})`).join("\n")
      : "";

  const nvdContext =
    nvdCves.length > 0
      ? `\n\nRecent high/critical-severity CVEs newly published on NVD (${cadence === "daily" ? "last 24h" : "past 7 days"}):\n` +
        nvdCves
          .map((c) => `- ${c.cveId} (CVSS ${c.cvssScore}, ${c.severity}) — ${c.description || "no description available"}`)
          .join("\n")
      : "";

  const kevContext =
    kevMatches.length > 0
      ? `\n\nRecent entries from CISA's Known Exploited Vulnerabilities (KEV) catalog (added in the last 7 days):\n` +
        kevMatches
          .map(({ entry, matchedTech }) =>
            `- ${entry.cveId} — "${entry.vulnerabilityName}" affecting ${entry.vendorProject} ${entry.product}. ` +
            `Added to KEV on ${entry.dateAdded}${entry.dueDate ? ` (CISA remediation due date: ${entry.dueDate})` : ""}. ` +
            `Description: ${entry.shortDescription || "n/a"}. ` +
            (matchedTech
              ? `We DO detect ${matchedTech} in our scans, so this is a fair "check your version" mention.`
              : `We do NOT detect this product — mention only for general awareness, never imply we check for it.`)
          )
          .join("\n")
      : "";

  try {
    const res = await fetch(
      `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "api-key": apiKey },
        signal: AbortSignal.timeout(25000),
        body: JSON.stringify({
          messages: [
            {
              role: "system",
              content:
                `You are an experienced cyber security blogger writing a ${cadence === "daily" ? "daily brief" : "weekly roundup"} for ` +
                "small business owners in Scotland, published by Hebrides Cyber. Write like a knowledgeable " +
                "security journalist, not a corporate newsletter — direct, specific, a little conversational, " +
                `but always accurate. Plain English, minimal jargon (explain any term a non-technical reader ` +
                `wouldn't know), ${cadence === "daily" ? "4-7" : "6-9"} short paragraphs in Markdown with a ` +
                "couple of headings.\n\n" +
                "HARD RULE: only report events, CVEs, and article titles/facts that appear in the data you are " +
                "given below. Never invent an incident, a company name, a date, or a detail that isn't in the " +
                "provided sources — this is real news journalism, not creative writing. When you reference a " +
                "news article, name the outlet it came from. When you reference a CVE, cite its ID. If nothing " +
                "provided is genuinely newsworthy or relevant to a small business audience, say so plainly and " +
                "write about the scan stats instead — do not pad with a forced or exaggerated framing of a minor " +
                "item.\n\n" +
                "For the KEV entries specifically: only claim 'we detect this' when the entry explicitly says so.",
            },
            {
              role: "user",
              content:
                `Sources for ${cadence === "daily" ? "today's brief" : "this week's roundup"}:` +
                newsContext +
                nvdContext +
                kevContext +
                `\n\nOur own product's scan stats from the past 7 days (${cadence === "daily" ? "use as a short closing section, not the main content" : "a fuller section is appropriate here since this is the weekly roundup"}):\n` +
                `- Sites scanned: ${stats.totalScans}\n` +
                `- Findings by severity: ${JSON.stringify(stats.findingsBySeverity)}\n` +
                `- Most common issues: ${stats.topFindingTitles.map((t) => `${t.title} (${t.count}x)`).join(", ") || "none"}` +
                `\n\nWrite ${cadence === "daily" ? "today's cyber security brief" : "this week's cyber security roundup"} in Markdown, leading with the real news/CVE content above.`,
            },
          ],
          max_tokens: 900,
          temperature: 0.6,
        }),
      }
    );
    if (!res.ok) return fallback;
    const json = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    return json.choices?.[0]?.message?.content?.trim() || fallback;
  } catch {
    return fallback;
  }
}

/**
 * Deterministic template for the KEV section. Only ever includes entries
 * that correlate with something fingerprint.ts actually detects — an entry
 * with no matched technology is general threat intel we can't honestly tie
 * to product coverage, so a fully deterministic (non-AI) template omits it
 * rather than risk an overclaim. Returns "" (section omitted entirely) when
 * there's nothing relevant this week — never padded with irrelevant CVEs.
 */
export function buildKevSection(kevMatches: KevMatch[]): string {
  const relevant = kevMatches.filter((m) => m.matchedTech !== null).slice(0, 2);
  if (relevant.length === 0) return "";

  // Every interpolated field below is real external text (CISA's KEV
  // catalog) Hebrides Cyber doesn't control — HTML-escaped before it ever
  // becomes part of the markdown body, so a vulnerability name/product
  // string that happens to contain a literal <script>/<img onerror=...>
  // (not unheard of when a KEV entry describes an XSS itself) can't survive
  // as markup once marked.parse() converts this to HTML. Belt-and-braces
  // with the DOMPurify sanitization at render time (src/app/blog/[slug]/page.tsx) —
  // this is the fix at the point untrusted text enters the document, that
  // one is the fix at the point it's rendered.
  const lines = relevant.map(({ entry, matchedTech }) => {
    const due = entry.dueDate
      ? ` CISA's federal remediation deadline for this one is ${escapeHtml(entry.dueDate)}.`
      : "";
    return (
      `- **${escapeHtml(entry.vulnerabilityName)}** (${escapeHtml(entry.cveId)}, affecting ${escapeHtml(entry.vendorProject)} ` +
      `${escapeHtml(entry.product)}) was added to CISA's Known Exploited Vulnerabilities catalog on ` +
      `${escapeHtml(entry.dateAdded)} — confirmed under active exploitation in the wild.${due} We detect ` +
      `**${escapeHtml(matchedTech ?? "")}** on scanned sites, so if you're running it, it's worth checking your ` +
      `version is current.`
    );
  });

  return `

## Known exploited vulnerabilities to know about

${lines.join("\n")}

*Per [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).*`;
}

export function buildNvdSection(cves: NvdCve[]): string {
  if (cves.length === 0) return "";
  // c.description is NVD's own free-text field — routinely contains a
  // literal <script>/onerror snippet when the CVE it's describing IS an
  // XSS. Escaped for the same reason as buildKevSection above.
  const lines = cves.slice(0, 4).map((c) => {
    const rawDesc = c.description
      ? c.description.slice(0, 220) + (c.description.length > 220 ? "…" : "")
      : "No description available yet.";
    return `- **${escapeHtml(c.cveId)}** (CVSS ${c.cvssScore}, ${escapeHtml(c.severity ?? "unrated")}) — ${escapeHtml(rawDesc)}`;
  });
  return `

## Newly published, high-severity CVEs

${lines.join("\n")}

*Source: [NIST National Vulnerability Database](https://nvd.nist.gov/).*`;
}

export function buildNewsSection(news: NewsArticle[]): string {
  if (news.length === 0) return "";
  // a.title/a.summary/a.source are third-party RSS feed text (see
  // parseRssItems above) — a.summary is already HTML-tag-stripped at parse
  // time, but a.title isn't, so escape all three here for the same reason
  // as buildKevSection/buildNvdSection.
  const lines = news.slice(0, 5).map((a) => {
    const summary = a.summary ? ` — ${escapeHtml(a.summary.slice(0, 200))}${a.summary.length > 200 ? "…" : ""}` : "";
    return `- **[${escapeHtml(a.title)}](${a.link})** (${escapeHtml(a.source)})${summary}`;
  });
  return `

## In the news

${lines.join("\n")}`;
}

function buildDeterministicPost(
  stats: AggregateStats,
  kevMatches: KevMatch[],
  nvdCves: NvdCve[],
  news: NewsArticle[],
  cadence: "daily" | "weekly"
): string {
  const hasRealEventContent = kevMatches.length > 0 || nvdCves.length > 0 || news.length > 0;
  const lookbackLabel = cadence === "daily" ? "the last couple of days" : "the past week";

  const severityLines = Object.entries(stats.findingsBySeverity)
    .map(([sev, count]) => `- **${sev}**: ${count}`)
    .join("\n");

  const topLines = stats.topFindingTitles.map((t) => `1. ${t.title} (seen ${t.count}x)`).join("\n");

  const opening = hasRealEventContent
    ? `A roundup of what's actually happened in security over ${lookbackLabel} — real incidents and newly disclosed vulnerabilities, not filler.`
    : `Nothing major broke in the news over ${lookbackLabel} — a good moment to check your own site's basics instead.`;

  const statsHeading = cadence === "daily" ? "How our own customers' sites are doing" : "This week in our own scan data";

  return `${opening}
${buildNewsSection(news)}
${buildNvdSection(nvdCves)}
${buildKevSection(kevMatches)}

## ${statsHeading}

We ran **${stats.totalScans}** Security Score scans across our customers in the past 7 days.

${severityLines || "No findings recorded this week."}

${topLines ? `Most common issues:\n\n${topLines}` : "Nothing stood out — most sites checked out clean."}

If any of the above sounds familiar, the fix is usually quick: missing
security headers and outdated front-end libraries are the two most common
findings we see, and both are typically a same-day fix. [Run a free
Security Score scan](/dashboard) to see where your own site stands.

*This ${cadence === "daily" ? "brief is generated daily" : "roundup is generated weekly"} from CISA's KEV
catalog, NIST's NVD, a small set of established security news feeds, and
Hebrides Cyber's own (anonymised) scan data. Set
AZURE_OPENAI_ENDPOINT/KEY/DEPLOYMENT for a narrative AI write-up instead of
this templated summary — see src/lib/newsletter.ts.*`;
}
