import { describe, it, expect, vi } from "vitest";

const { fromMock } = vi.hoisted(() => ({ fromMock: vi.fn() }));
vi.mock("@/lib/supabaseClient", () => ({ supabase: { from: fromMock } }));

import { buildFeedXml, escapeXml, GET } from "./route";

describe("escapeXml", () => {
  it("escapes &, < and >", () => {
    expect(escapeXml("Tom & Jerry <script> x > y")).toBe("Tom &amp; Jerry &lt;script&gt; x &gt; y");
  });

  it("leaves ordinary text untouched", () => {
    expect(escapeXml("A plain title, with punctuation.")).toBe("A plain title, with punctuation.");
  });
});

describe("buildFeedXml", () => {
  const now = new Date("2026-06-15T12:00:00Z");

  it("builds a valid channel with title, link and description", () => {
    const xml = buildFeedXml([], now);
    expect(xml).toContain("<title>Security Weekly — Hebrides Cyber</title>");
    expect(xml).toContain("<link>https://www.hebridescyber.co.uk/blog</link>");
    expect(xml).toContain("<description>Cybersecurity insights for small businesses and SaaS teams, grounded in real scan data.</description>");
    expect(xml).toContain(`<lastBuildDate>${now.toUTCString()}</lastBuildDate>`);
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
  });

  it("renders one <item> per post with title, link, guid, description and pubDate", () => {
    const xml = buildFeedXml(
      [
        { slug: "cyber-brief-2026-06-15", title: "Daily Brief", excerpt: "Today's roundup", meta_description: null, published_at: "2026-06-15T07:00:00Z" },
      ],
      now
    );
    expect(xml).toContain("<title>Daily Brief</title>");
    expect(xml).toContain("<link>https://www.hebridescyber.co.uk/blog/cyber-brief-2026-06-15</link>");
    expect(xml).toContain('<guid isPermaLink="true">https://www.hebridescyber.co.uk/blog/cyber-brief-2026-06-15</guid>');
    expect(xml).toContain("<description>Today's roundup</description>");
    expect(xml).toContain("<pubDate>Mon, 15 Jun 2026 07:00:00 GMT</pubDate>");
  });

  it("prefers meta_description over excerpt when both are present", () => {
    const xml = buildFeedXml(
      [{ slug: "week-of-2026-06-15", title: "Weekly", excerpt: "excerpt text", meta_description: "SEO description", published_at: "2026-06-15T07:00:00Z" }],
      now
    );
    expect(xml).toContain("<description>SEO description</description>");
    expect(xml).not.toContain("excerpt text");
  });

  it("falls back to excerpt when meta_description is empty", () => {
    const xml = buildFeedXml(
      [{ slug: "week-of-2026-06-15", title: "Weekly", excerpt: "excerpt text", meta_description: "", published_at: "2026-06-15T07:00:00Z" }],
      now
    );
    expect(xml).toContain("<description>excerpt text</description>");
  });

  it("omits pubDate rather than emitting an invalid date for an unparseable published_at", () => {
    const xml = buildFeedXml([{ slug: "x", title: "X", excerpt: null, meta_description: null, published_at: "not-a-date" }], now);
    expect(xml).not.toContain("<pubDate>");
    expect(xml).not.toContain("Invalid Date");
  });

  it("escapes XML-unsafe characters in titles and descriptions", () => {
    const xml = buildFeedXml(
      [{ slug: "x", title: "SQL Injection & You <2026>", excerpt: "Stay safe & secure", meta_description: null, published_at: "2026-06-15T07:00:00Z" }],
      now
    );
    expect(xml).toContain("<title>SQL Injection &amp; You &lt;2026&gt;</title>");
    expect(xml).toContain("<description>Stay safe &amp; secure</description>");
  });

  it("combines daily-brief and weekly-newsletter posts in the order given", () => {
    const xml = buildFeedXml(
      [
        { slug: "week-of-2026-06-09", title: "Weekly", excerpt: "w", meta_description: null, published_at: "2026-06-09T07:00:00Z" },
        { slug: "cyber-brief-2026-06-08", title: "Daily", excerpt: "d", meta_description: null, published_at: "2026-06-08T07:00:00Z" },
      ],
      now
    );
    expect(xml.indexOf("Weekly")).toBeLessThan(xml.indexOf("Daily"));
  });

  it("renders an empty <channel> with no items for an empty post list", () => {
    const xml = buildFeedXml([], now);
    expect(xml).not.toContain("<item>");
  });
});

describe("GET", () => {
  it("queries only published posts, newest first, and returns an RSS content type", async () => {
    const limit = vi.fn().mockResolvedValue({
      data: [{ slug: "cyber-brief-2026-06-15", title: "Daily Brief", excerpt: "roundup", meta_description: null, published_at: "2026-06-15T07:00:00Z" }],
    });
    const chain = {
      select: vi.fn(() => chain),
      eq: vi.fn(() => chain),
      not: vi.fn(() => chain),
      order: vi.fn(() => ({ limit })),
    };
    fromMock.mockReturnValue(chain);

    const res = await GET();
    const body = await res.text();

    expect(res.headers.get("Content-Type")).toBe("application/rss+xml; charset=utf-8");
    expect(body).toContain("Daily Brief");
    expect(chain.eq).toHaveBeenCalledWith("status", "published");
    expect(chain.not).toHaveBeenCalledWith("published_at", "is", null);
  });

  it("returns a valid empty feed when the query fails (data undefined)", async () => {
    const chain = {
      select: vi.fn(() => chain),
      eq: vi.fn(() => chain),
      not: vi.fn(() => chain),
      order: vi.fn(() => ({ limit: vi.fn().mockResolvedValue({ data: null }) })),
    };
    fromMock.mockReturnValue(chain);

    const res = await GET();
    const body = await res.text();

    expect(res.ok).toBe(true);
    expect(body).not.toContain("<item>");
  });
});
