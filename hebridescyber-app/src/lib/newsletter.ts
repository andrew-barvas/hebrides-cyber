// Builds the weekly cybersecurity newsletter/blog post. Grounded in real
// product data (aggregate finding counts across the past week's scans)
// rather than generic AI filler — the same finding-severity vocabulary
// used throughout src/lib/scanners.ts drives both the stats and, if Azure
// OpenAI is configured, the prompt for a narrative write-up around them.
//
// Falls back to a deterministic templated post (still built from the real
// stats, just without AI prose) if Azure OpenAI isn't configured — a
// newsletter should never fail to publish just because a model call did.

import type { SupabaseClient } from "@supabase/supabase-js";

export type NewsletterPost = {
  slug: string;
  title: string;
  excerpt: string;
  body_markdown: string;
};

type AggregateStats = {
  totalScans: number;
  findingsBySeverity: Record<string, number>;
  topFindingTitles: Array<{ title: string; count: number }>;
};

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
  const weekLabel = new Date().toISOString().slice(0, 10);
  const slug = `week-of-${weekLabel}`;

  const body = await draftBody(stats);
  const title = `This Week in Small Business Security — ${weekLabel}`;
  const excerpt =
    stats.totalScans > 0
      ? `${stats.totalScans} sites scanned this week. Top issue: ${stats.topFindingTitles[0]?.title ?? "none found"}.`
      : "No scans ran this week — here's what to check anyway.";

  return { slug, title, excerpt, body_markdown: body };
}

async function draftBody(stats: AggregateStats): Promise<string> {
  const fallback = buildDeterministicPost(stats);

  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  if (!endpoint || !apiKey || !deployment) return fallback;

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
                "Markdown with a couple of headings. Ground it in the real stats given, don't invent incidents.",
            },
            {
              role: "user",
              content:
                `This week's scan stats:\n` +
                `- Sites scanned: ${stats.totalScans}\n` +
                `- Findings by severity: ${JSON.stringify(stats.findingsBySeverity)}\n` +
                `- Most common issues: ${stats.topFindingTitles.map((t) => `${t.title} (${t.count}x)`).join(", ") || "none"}\n\n` +
                `Write the newsletter body in Markdown.`,
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

function buildDeterministicPost(stats: AggregateStats): string {
  const severityLines = Object.entries(stats.findingsBySeverity)
    .map(([sev, count]) => `- **${sev}**: ${count}`)
    .join("\n");

  const topLines = stats.topFindingTitles.map((t) => `1. ${t.title} (seen ${t.count}x)`).join("\n");

  return `## This week, in numbers

We ran **${stats.totalScans}** Security Score scans across our customers this week.

${severityLines || "No findings recorded this week."}

## Most common issues

${topLines || "Nothing stood out this week — most sites checked out clean."}

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
