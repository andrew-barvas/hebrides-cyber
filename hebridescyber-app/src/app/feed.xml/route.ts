// RSS 2.0 feed for the blog. Both the daily "cyber brief" and weekly
// newsletter posts live in the same blog_posts table, differentiated only
// by slug prefix (see CLAUDE.md's "Content generation" section) — this
// feed lists both together, newest first, exactly as the blog index and
// sitemap already do.
//
// Hand-rolled XML, no dependency: this codebase already hand-rolls the
// smaller XML/feed-adjacent surfaces it touches rather than adding a
// library for them (src/lib/newsletter.ts parses third-party security-news
// RSS with regex, not a parser dependency) and an RSS <channel> is a small,
// fixed shape.
//
// Kept in sync with sitemap.ts's query: same status/published_at filter,
// same blog/<slug> URL construction, so a feed item never points at a post
// the site itself would 404 on.
import { supabase } from "@/lib/supabaseClient";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
const FEED_TITLE = "Security Weekly — Hebrides Cyber";
const FEED_DESCRIPTION = "Cybersecurity insights for small businesses and SaaS teams, grounded in real scan data.";
/** Most-recent posts only — an RSS reader wants new items, not the full archive. */
const MAX_ITEMS = 50;

export const revalidate = 3600;

type FeedPost = {
  slug: string;
  title: string;
  excerpt: string | null;
  meta_description: string | null;
  published_at: string;
};

/** XML text-node escaping. Covers the characters that are ever unsafe inside an element's text content (attribute-only escapes like &apos; aren't needed here — every field below lands in a text node, never an attribute). */
export function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** RFC 822 date, the format RSS's <pubDate> requires. Returns null for an unparseable value rather than emitting "Invalid Date". */
function rfc822(iso: string): string | null {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toUTCString() : null;
}

export function buildFeedXml(posts: FeedPost[], now: Date): string {
  const items = posts
    .map((post) => {
      const pubDate = rfc822(post.published_at);
      const url = `${SITE_URL}/blog/${post.slug}`;
      const description = post.meta_description || post.excerpt || "";
      return `    <item>
      <title>${escapeXml(post.title)}</title>
      <link>${escapeXml(url)}</link>
      <guid isPermaLink="true">${escapeXml(url)}</guid>
      <description>${escapeXml(description)}</description>${pubDate ? `\n      <pubDate>${pubDate}</pubDate>` : ""}
    </item>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>${escapeXml(FEED_TITLE)}</title>
    <link>${escapeXml(SITE_URL)}/blog</link>
    <description>${escapeXml(FEED_DESCRIPTION)}</description>
    <lastBuildDate>${now.toUTCString()}</lastBuildDate>
${items}
  </channel>
</rss>
`;
}

export async function GET(): Promise<Response> {
  const { data } = await supabase
    .from("blog_posts")
    .select("slug, title, excerpt, meta_description, published_at")
    .eq("status", "published")
    .not("published_at", "is", null)
    .order("published_at", { ascending: false })
    .limit(MAX_ITEMS);

  const xml = buildFeedXml((data ?? []) as FeedPost[], new Date());
  return new Response(xml, {
    headers: {
      "Content-Type": "application/rss+xml; charset=utf-8",
    },
  });
}
