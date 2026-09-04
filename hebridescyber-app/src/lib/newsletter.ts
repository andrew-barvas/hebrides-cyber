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
export async function fetchRecentHighSeverityCves(daysBack = 1): Promise<NvdCve[]> {
  try {
    const end = new Date();
    const start = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);
    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0` +
      `?pubStartDate=${encodeURIComponent(start.toISOString())}` +
      `&pubEndDate=${encodeURIComponent(end.toISOString())}` +
      `&resultsPerPage=200`;

    const res = await fetch(url, {
      signal: AbortSignal.timeout(15_000),
      headers: { "User-Agent": "HebridesCyberBot/1.0 (+https://hebridescyber.co.uk)" },
    });
    if (!res.ok) return [];

    const json = (await res.json()) as {
      vulnerabilities?: Array<{
        cve?: {
          id?: string;
          published?: string;
          descriptions?: Array<{ lang?: string; value?: string }>;
          metrics?: {
            cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
            cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
            cvssMetricV2?: Array<{ cvssData?: { baseScore?: number } }>;
          };
        };
      }>;
    };

    const parsed: NvdCve[] = (json.vulnerabilities ?? [])
      .map((v) => {
        const cve = v.cve;
        const cvssV31 = cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
        const cvssV30 = cve?.metrics?.cvssMetricV30?.[0]?.cvssData;
        const cvssV2 = cve?.metrics?.cvssMetricV2?.[0]?.cvssData;
        const score = cvssV31?.baseScore ?? cvssV30?.baseScore ?? cvssV2?.baseScore ?? null;
        const severity = cvssV31?.baseSeverity ?? cvssV30?.baseSeverity ?? (score !== null ? severityFromScore(score) : null);
        return {
          cveId: cve?.id ?? "",
          description: (cve?.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "",
          cvssScore: score,
          severity,
          published: cve?.published ?? "",
        };
      })
      .filter((c) => c.cveId && c.cvssScore !== null && c.cvssScore >= 7.0);

    return parsed.sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0)).slice(0, 6);
  } catch {
    return [];
  }
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
};

// Deliberately not a huge list — a handful of established, high-signal
// security news sources rather than a broad scrape. Each publishes a
// standard RSS 2.0 feed with no auth required.
const SECURITY_NEWS_FEEDS: Array<{ name: string; url: string }> = [
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
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
 * Minimal, dependency-free RSS 2.0 item extractor — regex-based rather than
 * pulling in an XML parsing library, matching this codebase's established
 * preference (see action/index.js's header comment for the same reasoning
 * applied to the packaged GitHub Action). Good enough for the small, stable
 * set of well-formed feeds this queries; a malformed or unexpected item is
 * simply skipped rather than throwing.
 */
function parseRssItems(xml: string, sourceName: string, daysBack: number): NewsArticle[] {
  const items: NewsArticle[] = [];
  const cutoff = Date.now() - daysBack * 24 * 60 * 60 * 1000;
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;

  let match: RegExpExecArray | null;
  while (items.length < 20 && (match = itemRegex.exec(xml)) !== null) {
    const block = match[1];
    const rawTitle = extractTag(block, "title");
    const rawLink = extractTag(block, "link");
    const rawPubDate = extractTag(block, "pubDate");
    const rawDescription = extractTag(block, "description");

    if (!rawTitle || !rawPubDate) continue;

    const published = Date.parse(rawPubDate);
    if (Number.isNaN(published) || published < cutoff) continue;

    items.push({
      title: decodeXmlEntities(stripCdata(rawTitle)),
      link: rawLink ? decodeXmlEntities(stripCdata(rawLink)) : "",
      source: sourceName,
      publishedAt: new Date(published).toISOString(),
      summary: rawDescription ? decodeXmlEntities(stripHtmlTags(stripCdata(rawDescription))).slice(0, 300) : "",
    });
  }

  return items;
}

async function fetchOneFeed(name: string, url: string, daysBack: number): Promise<NewsArticle[]> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(10_000),
      headers: { "User-Agent": "HebridesCyberBot/1.0 (+https://hebridescyber.co.uk)" },
    });
    if (!res.ok) return [];
    const xml = await res.text();
    return parseRssItems(xml, name, daysBack);
  } catch {
    return [];
  }
}

/**
 * Fetches recent items across all configured security-news feeds, de-duped
 * by normalised title (the same real story often runs on multiple outlets),
 * newest first, capped. One dead feed never blocks the others —
 * Promise.allSettled, not allSettled-then-throw.
 */
export async function fetchRecentSecurityNews(daysBack = 2, cap = 8): Promise<NewsArticle[]> {
  const results = await Promise.allSettled(
    SECURITY_NEWS_FEEDS.map((f) => fetchOneFeed(f.name, f.url, daysBack))
  );

  const articles = results.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
  articles.sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt));

  const seen = new Set<string>();
  const deduped: NewsArticle[] = [];
  for (const a of articles) {
    const key = a.title.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(a);
  }

  return deduped.slice(0, cap);
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
  const [stats, kevEntries, nvdCves, news] = await Promise.all([
    collectRecentScanStats(supabaseAdmin),
    fetchRecentKevEntries(7), // KEV entries are sparse day-to-day; keep a wider net so a real one isn't missed
    fetchRecentHighSeverityCves(1),
    fetchRecentSecurityNews(2, 8),
  ]);
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
  const [stats, kevEntries, nvdCves, news] = await Promise.all([
    collectRecentScanStats(supabaseAdmin),
    fetchRecentKevEntries(7),
    fetchRecentHighSeverityCves(7),
    fetchRecentSecurityNews(7, 12),
  ]);
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
function buildKevSection(kevMatches: KevMatch[]): string {
  const relevant = kevMatches.filter((m) => m.matchedTech !== null).slice(0, 2);
  if (relevant.length === 0) return "";

  const lines = relevant.map(({ entry, matchedTech }) => {
    const due = entry.dueDate
      ? ` CISA's federal remediation deadline for this one is ${entry.dueDate}.`
      : "";
    return (
      `- **${entry.vulnerabilityName}** (${entry.cveId}, affecting ${entry.vendorProject} ` +
      `${entry.product}) was added to CISA's Known Exploited Vulnerabilities catalog on ` +
      `${entry.dateAdded} — confirmed under active exploitation in the wild.${due} We detect ` +
      `**${matchedTech}** on scanned sites, so if you're running it, it's worth checking your ` +
      `version is current.`
    );
  });

  return `

## Known exploited vulnerabilities to know about

${lines.join("\n")}

*Per [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).*`;
}

function buildNvdSection(cves: NvdCve[]): string {
  if (cves.length === 0) return "";
  const lines = cves.slice(0, 4).map((c) => {
    const desc = c.description ? c.description.slice(0, 220) + (c.description.length > 220 ? "…" : "") : "No description available yet.";
    return `- **${c.cveId}** (CVSS ${c.cvssScore}, ${c.severity}) — ${desc}`;
  });
  return `

## Newly published, high-severity CVEs

${lines.join("\n")}

*Source: [NIST National Vulnerability Database](https://nvd.nist.gov/).*`;
}

function buildNewsSection(news: NewsArticle[]): string {
  if (news.length === 0) return "";
  const lines = news.slice(0, 5).map((a) => {
    const summary = a.summary ? ` — ${a.summary.slice(0, 200)}${a.summary.length > 200 ? "…" : ""}` : "";
    return `- **[${a.title}](${a.link})** (${a.source})${summary}`;
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
