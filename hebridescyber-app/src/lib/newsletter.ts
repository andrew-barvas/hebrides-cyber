// Builds the weekly cybersecurity newsletter/blog post. Grounded in real
// product data (aggregate finding counts across the past week's scans)
// rather than generic AI filler — the same finding-severity vocabulary
// used throughout src/lib/scanners/ drives both the stats and, if Azure
// OpenAI is configured, the prompt for a narrative write-up around them.
//
// Also grounded, as of the CISA KEV integration below, in real external
// threat intel: CISA's Known Exploited Vulnerabilities catalog is a free,
// no-auth feed of CVEs confirmed under active real-world exploitation —
// genuinely "this happened," not synthetic. Entries are only surfaced when
// they're recent AND correlate with something src/lib/scanners/fingerprint.ts
// can actually detect, so the newsletter never implies coverage the product
// doesn't have.
//
// Falls back to a deterministic templated post (still built from the real
// stats, just without AI prose) if Azure OpenAI isn't configured — a
// newsletter should never fail to publish just because a model call did.
// The KEV fetch follows the same contract: any failure degrades to an
// empty list, never a thrown error, so a CISA outage can't block publishing
// either.

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
 * empty array rather than blocking newsletter generation.
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

/** Pulls the past 7 days of scan_results and tallies findings by severity/title. */
async function collectWeeklyStats(supabaseAdmin: SupabaseClient): Promise<AggregateStats> {
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

export async function generateNewsletterPost(supabaseAdmin: SupabaseClient): Promise<NewsletterPost> {
  const stats = await collectWeeklyStats(supabaseAdmin);
  const kevEntries = await fetchRecentKevEntries(7);
  const kevMatches = correlateKevWithFingerprint(kevEntries);
  const weekLabel = new Date().toISOString().slice(0, 10);
  const slug = `week-of-${weekLabel}`;

  const body = await draftBody(stats, kevMatches);
  const title = `This Week in Small Business Security — ${weekLabel}`;
  const excerpt =
    stats.totalScans > 0
      ? `${stats.totalScans} sites scanned this week. Top issue: ${stats.topFindingTitles[0]?.title ?? "none found"}.`
      : "No scans ran this week — here's what to check anyway.";

  return { slug, title, excerpt, body };
}

async function draftBody(stats: AggregateStats, kevMatches: KevMatch[]): Promise<string> {
  const fallback = buildDeterministicPost(stats, kevMatches);

  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  if (!endpoint || !apiKey || !deployment) return fallback;

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
        signal: AbortSignal.timeout(20000),
        body: JSON.stringify({
          messages: [
            {
              role: "system",
              content:
                "You write a short, friendly weekly cybersecurity newsletter for small business owners in " +
                "Scotland, published by Hebrides Cyber. Plain English, no jargon, 4-6 short paragraphs in " +
                "Markdown with a couple of headings. Ground it in the real stats given, don't invent incidents. " +
                "You may also be given recent entries from CISA's Known Exploited Vulnerabilities catalog. " +
                "If, and only if, one or two of them are genuinely relevant to a small business audience, weave " +
                "them in briefly and cite them as being from CISA's KEV catalog — never invent details beyond " +
                "what's given, and never claim we detect a product unless the entry explicitly says we do. If " +
                "none of the KEV entries are relevant (or none were provided), skip that topic entirely and just " +
                "write about the scan stats as usual — do not force in an irrelevant CVE mention.",
            },
            {
              role: "user",
              content:
                `This week's scan stats:\n` +
                `- Sites scanned: ${stats.totalScans}\n` +
                `- Findings by severity: ${JSON.stringify(stats.findingsBySeverity)}\n` +
                `- Most common issues: ${stats.topFindingTitles.map((t) => `${t.title} (${t.count}x)`).join(", ") || "none"}` +
                kevContext +
                `\n\nWrite the newsletter body in Markdown.`,
            },
          ],
          max_tokens: 600,
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

## This week in known exploited vulnerabilities

${lines.join("\n")}

*Per [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).*`;
}

function buildDeterministicPost(stats: AggregateStats, kevMatches: KevMatch[] = []): string {
  const severityLines = Object.entries(stats.findingsBySeverity)
    .map(([sev, count]) => `- **${sev}**: ${count}`)
    .join("\n");

  const topLines = stats.topFindingTitles.map((t) => `1. ${t.title} (seen ${t.count}x)`).join("\n");

  return `## This week, in numbers

We ran **${stats.totalScans}** Security Score scans across our customers this week.

${severityLines || "No findings recorded this week."}

## Most common issues

${topLines || "Nothing stood out this week — most sites checked out clean."}
${buildKevSection(kevMatches)}

## What to do about it

If any of the above sounds familiar, the fix is usually quick: missing
security headers and outdated front-end libraries are the two most common
findings we see, and both are typically a same-day fix. [Run a free
Security Score scan](/dashboard) to see where your own site stands.

*This newsletter is generated automatically from real (anonymised)
Hebrides Cyber scan data. Set AZURE_OPENAI_ENDPOINT/KEY/DEPLOYMENT for a
narrative AI write-up instead of this templated summary — see
src/lib/newsletter.ts.*`;
}
