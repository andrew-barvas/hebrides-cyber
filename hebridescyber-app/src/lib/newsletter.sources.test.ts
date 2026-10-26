import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  citedCveIds,
  cveRankScore,
  extractCvssScore,
  fetchCvesByIds,
  generateDailyBlogPost,
  withCitedCves,
  fetchRecentHighSeverityCves,
  fetchRecentSecurityNews,
  mergeNvdCves,
  parseFeedItems,
  parseNvdCves,
  rankNews,
  scoreNewsArticle,
} from "./newsletter";

const NOW = Date.parse("2026-10-23T12:00:00Z");
const iso = (hoursAgo: number) => new Date(NOW - hoursAgo * 3_600_000).toISOString();

type Article = Parameters<typeof scoreNewsArticle>[0];
function article(over: Partial<Article> = {}): Article {
  return { title: "A minor story", link: "https://x.example/a", source: "Wire", publishedAt: iso(2), summary: "", ...over };
}

describe("extractCvssScore", () => {
  it("reads a CVE scored only under CVSS v4.0, which used to look unscored", () => {
    expect(extractCvssScore({ cvssMetricV40: [{ cvssData: { baseScore: 9.2, baseSeverity: "CRITICAL" } }] })).toEqual({ score: 9.2, severity: "CRITICAL" });
  });

  it("takes the highest across v4.0, v3.1, v3.0 and v2 (PHP2Shell: v4.0 9.2 and v3.1 9.8)", () => {
    const r = extractCvssScore({
      cvssMetricV40: [{ cvssData: { baseScore: 9.2, baseSeverity: "CRITICAL" } }],
      cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }],
      cvssMetricV2: [{ cvssData: { baseScore: 7.5 } }],
    });
    expect(r.score).toBe(9.8);
  });

  it("derives a severity from the score when only v2 is present", () => {
    expect(extractCvssScore({ cvssMetricV2: [{ cvssData: { baseScore: 7.5 } }] })).toEqual({ score: 7.5, severity: "HIGH" });
  });

  it("returns null for an unscored CVE", () => {
    expect(extractCvssScore({})).toEqual({ score: null, severity: null });
    expect(extractCvssScore(undefined)).toEqual({ score: null, severity: null });
  });
});

describe("parseNvdCves / mergeNvdCves", () => {
  const vuln = (id: string, score?: number) => ({
    cve: {
      id,
      published: "2026-10-21T14:17:09.357",
      descriptions: [{ lang: "en", value: `desc ${id}` }],
      metrics: score === undefined ? {} : { cvssMetricV31: [{ cvssData: { baseScore: score, baseSeverity: "X" } }] },
    },
  });

  it("keeps only scored CVEs at or above 7.0", () => {
    const out = parseNvdCves({ vulnerabilities: [vuln("CVE-1", 9.8), vuln("CVE-2", 6.9), vuln("CVE-3"), vuln("CVE-4", 7.0)] });
    expect(out.map((c) => c.cveId)).toEqual(["CVE-1", "CVE-4"]);
  });

  it("merges, de-duplicates keeping the highest score, sorts and caps", () => {
    const a = parseNvdCves({ vulnerabilities: [vuln("CVE-1", 7.5), vuln("CVE-2", 9.0)] });
    const b = parseNvdCves({ vulnerabilities: [vuln("CVE-1", 9.8), vuln("CVE-3", 8.0)] });
    const merged = mergeNvdCves([a, b], 2);
    expect(merged.map((c) => [c.cveId, c.cvssScore])).toEqual([["CVE-1", 9.8], ["CVE-2", 9.0]]);
  });
});

describe("fetchRecentHighSeverityCves", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const nvd = (id: string, score: number) => ({
    ok: true,
    json: async () => ({ vulnerabilities: [{ cve: { id, published: "x", descriptions: [], metrics: { cvssMetricV31: [{ cvssData: { baseScore: score } }] } } }] }),
  });

  it("asks NVD for severe CVEs server-side (v3 critical, v4 critical, v3 high) instead of reading an unsorted first page", async () => {
    fetchMock.mockImplementation(async () => nvd("CVE-2026-109618", 9.8));
    const out = await fetchRecentHighSeverityCves(2, { pauseMs: 0 });
    const urls = fetchMock.mock.calls.map((c) => c[0] as string);
    expect(urls).toHaveLength(3);
    expect(urls[0]).toContain("cvssV3Severity=CRITICAL");
    expect(urls[1]).toContain("cvssV4Severity=CRITICAL");
    expect(urls[2]).toContain("cvssV3Severity=HIGH");
    expect(out.map((c) => c.cveId)).toEqual(["CVE-2026-109618"]);
  });

  it("combines the three slices and sorts by score", async () => {
    fetchMock.mockResolvedValueOnce(nvd("CVE-A", 7.8)).mockResolvedValueOnce(nvd("CVE-B", 9.2)).mockResolvedValueOnce(nvd("CVE-C", 8.1));
    const out = await fetchRecentHighSeverityCves(2, { pauseMs: 0 });
    expect(out.map((c) => c.cveId)).toEqual(["CVE-B", "CVE-C", "CVE-A"]);
  });

  it("a failing query costs only its own slice", async () => {
    fetchMock.mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce({ ok: false, status: 503 }).mockResolvedValueOnce(nvd("CVE-C", 8.1));
    const out = await fetchRecentHighSeverityCves(2, { pauseMs: 0 });
    expect(out.map((c) => c.cveId)).toEqual(["CVE-C"]);
  });

  it("returns an empty list, never throws, when NVD is down", async () => {
    fetchMock.mockRejectedValue(new Error("down"));
    expect(await fetchRecentHighSeverityCves(2, { pauseMs: 0 })).toEqual([]);
  });
});

describe("parseFeedItems", () => {
  const rss = (pub: string) => `<rss><channel><item><title><![CDATA[PHP flaws &amp; fixes]]></title><link>https://n.example/php</link><pubDate>${pub}</pubDate><description><![CDATA[<p>Two <b>critical</b> bugs.</p>]]></description></item></channel></rss>`;
  const atom = (updated: string) =>
    `<feed xmlns="http://www.w3.org/2005/Atom"><entry><title type="text">Multiple services in europe-west2 are experiencing issues</title><link href="https://status.cloud.google.com/incidents/abc" rel="alternate"/><updated>${updated}</updated><summary type="html">&lt;p&gt;Power event in europe-west2-b&lt;/p&gt;</summary></entry></feed>`;

  it("parses RSS items, decoding entities and stripping HTML", () => {
    const [a] = parseFeedItems(rss(new Date(Date.now() - 3_600_000).toUTCString()), "Wire", 3, "news");
    expect(a).toMatchObject({ title: "PHP flaws & fixes", link: "https://n.example/php", source: "Wire", kind: "news" });
    expect(a.summary).toBe("Two critical bugs.");
  });

  it("parses Atom entries: href link, updated date, summary", () => {
    const [a] = parseFeedItems(atom(new Date(Date.now() - 5 * 3_600_000).toISOString()), "Google Cloud status", 3, "status");
    expect(a).toMatchObject({ title: "Multiple services in europe-west2 are experiencing issues", link: "https://status.cloud.google.com/incidents/abc", kind: "status" });
    expect(a.summary).toContain("Power event in europe-west2-b");
  });

  it("drops items older than the window, and items without a title or date", () => {
    expect(parseFeedItems(rss(new Date(Date.now() - 10 * 86_400_000).toUTCString()), "Wire", 3)).toEqual([]);
    expect(parseFeedItems("<rss><item><title>x</title></item></rss>", "Wire", 3)).toEqual([]);
    expect(parseFeedItems("not xml at all", "Wire", 3)).toEqual([]);
  });
});

describe("scoreNewsArticle / rankNews", () => {
  it("scores CVE ids, exploitation language and real outages above a plain story", () => {
    const plain = scoreNewsArticle(article(), NOW);
    expect(scoreNewsArticle(article({ title: "PHP2Shell: CVE-2026-109618 and CVE-2026-109619 allow unauthenticated RCE" }), NOW)).toBeGreaterThan(plain + 5);
    expect(scoreNewsArticle(article({ kind: "status", title: "Multiple services are experiencing an outage in europe-west2" }), NOW)).toBeGreaterThan(plain + 5);
  });

  it("drops routine status noise", () => {
    expect(scoreNewsArticle(article({ kind: "status", title: "[RESOLVED] Service is operating normally" }), NOW)).toBe(-1);
  });

  it("keeps yesterday's major story ahead of eight newer minor ones (the bug: newest-first capping)", () => {
    const minor = Array.from({ length: 8 }, (_, i) => article({ title: `Minor item ${i}`, publishedAt: iso(1 + i * 0.1) }));
    const major = article({ title: "PHP2Shell: critical RCE CVE-2026-109618 patched", publishedAt: iso(30) });
    const ranked = rankNews([...minor, major], 8, NOW);
    expect(ranked[0].title).toContain("PHP2Shell");
    expect(ranked).toHaveLength(8);
  });

  it("surfaces a cloud outage in a capped list", () => {
    const minor = Array.from({ length: 12 }, (_, i) => article({ title: `Minor ${i}` }));
    const outage = article({ kind: "status", source: "Google Cloud status", title: "Multiple services experiencing issues in europe-west2", publishedAt: iso(40) });
    expect(rankNews([...minor, outage], 5, NOW).map((a) => a.source)).toContain("Google Cloud status");
  });

  it("de-duplicates by title and applies the cap", () => {
    const dup = [article({ title: "Same story!" }), article({ title: "same story", source: "Other" })];
    expect(rankNews(dup, 10, NOW)).toHaveLength(1);
    expect(rankNews(Array.from({ length: 20 }, (_, i) => article({ title: `T${i}` })), 4, NOW)).toHaveLength(4);
  });
});

describe("fetchRecentSecurityNews", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("includes the Google Cloud status feed alongside security news, and survives dead feeds", async () => {
    const recent = new Date(Date.now() - 3_600_000);
    const rss = `<rss><channel><item><title>PHP2Shell CVE-2026-109618 exploited</title><link>https://n.example/p</link><pubDate>${recent.toUTCString()}</pubDate><description>critical</description></item></channel></rss>`;
    const atom = `<feed><entry><title>Multiple services experiencing issues</title><link href="https://status.cloud.google.com/i/1"/><updated>${recent.toISOString()}</updated><summary>europe-west2 outage</summary></entry></feed>`;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("status.cloud.google.com")) return new Response(atom);
        if (url.includes("bleepingcomputer")) return new Response(rss);
        throw new Error("dead feed");
      }),
    );
    const out = await fetchRecentSecurityNews(3, 10);
    expect(out.map((a) => a.source).sort()).toEqual(["BleepingComputer", "Google Cloud status"]);
  });

  it("returns an empty list when every feed is dead", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("offline"))));
    expect(await fetchRecentSecurityNews()).toEqual([]);
  });
});

describe("citedCveIds / fetchCvesByIds / withCitedCves", () => {
  it("collects CVE ids named in titles and summaries, upper-cased and de-duplicated", () => {
    const ids = citedCveIds([
      article({ title: "Third PHP2Shell bug cve-2026-115560", summary: "also CVE-2026-109618" }),
      article({ summary: "CVE-2026-115560 again, and CVE-2026-109619" }),
    ]);
    expect(ids).toEqual(["CVE-2026-115560", "CVE-2026-109618", "CVE-2026-109619"]);
    expect(citedCveIds([article()])).toEqual([]);
  });

  it("looks cited CVEs up by id and keeps them even when NVD has not scored them", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => ({
        ok: true,
        json: async () => ({ vulnerabilities: [{ cve: { id: new URL(url).searchParams.get("cveId"), published: "x", descriptions: [{ lang: "en", value: "d" }], metrics: {} } }] }),
      })),
    );
    const out = await fetchCvesByIds(["CVE-2026-115560"], { pauseMs: 0 });
    expect(out).toEqual([expect.objectContaining({ cveId: "CVE-2026-115560", cvssScore: null })]);
    vi.unstubAllGlobals();
  });

  it("skips a failed lookup without throwing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("down"))));
    expect(await fetchCvesByIds(["CVE-2026-1"], { pauseMs: 0 })).toEqual([]);
    vi.unstubAllGlobals();
  });

  it("puts cited CVEs first and caps the list", () => {
    const cve = (id: string, score: number | null) => ({ cveId: id, description: "", cvssScore: score, severity: null, published: "" });
    const ranked = [cve("A", 10), cve("B", 10), cve("C", 10)];
    const out = withCitedCves(ranked, [cve("PHP", 9.8), cve("B", 10)], 3);
    expect(out.map((c) => c.cveId)).toEqual(["PHP", "B", "A"]);
  });
});

describe("generateDailyBlogPost (end to end, offline)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("mentions PHP2Shell and the Google Cloud outage even when ten unrelated CVSS-10 CVEs outrank the PHP flaws", async () => {
    vi.stubEnv("NVD_PAUSE_MS", "0");
    delete process.env.AZURE_OPENAI_ENDPOINT;
    const recent = new Date(Date.now() - 2 * 3_600_000);
    const nvdItem = (id: string, score: number) => ({ cve: { id, published: recent.toISOString(), descriptions: [{ lang: "en", value: `${id} in some product` }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: score } }] } } });
    const tens = Array.from({ length: 10 }, (_, i) => nvdItem(`CVE-2026-9000${i}`, 10));
    const rss = `<rss><channel><item><title>PHP2Shell: emergency patches for critical PHP RCE</title><link>https://n.example/php</link><pubDate>${recent.toUTCString()}</pubDate><description>CVE-2026-109618 and CVE-2026-109619 allow unauthenticated code execution.</description></item></channel></rss>`;
    const atom = `<feed><entry><title>Multiple services were experiencing issues in the europe-west2 region</title><link href="https://status.cloud.google.com/i/1"/><updated>${recent.toISOString()}</updated><summary>Power event in europe-west2-b</summary></entry></feed>`;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("nvd.nist.gov")) {
          const id = new URL(url).searchParams.get("cveId");
          const body = id ? [nvdItem(id, 9.8)] : url.includes("cvssV3Severity=CRITICAL") ? tens : [];
          return new Response(JSON.stringify({ vulnerabilities: body }));
        }
        if (url.includes("cisa.gov")) return new Response(JSON.stringify({ vulnerabilities: [] }));
        if (url.includes("bleepingcomputer")) return new Response(rss);
        if (url.includes("status.cloud.google.com")) return new Response(atom);
        throw new Error("dead feed");
      }),
    );
    const supabase = { from: () => ({ select: () => ({ gte: () => Promise.resolve({ data: [] }) }) }) };
    const post = await generateDailyBlogPost(supabase as never);
    expect(post.body).toContain("CVE-2026-109618");
    expect(post.body).toContain("PHP2Shell");
    expect(post.body).toContain("europe-west2");
    expect(post.body).toContain("Google Cloud status");
  });
});

describe("cveRankScore", () => {
  const cve = (id: string, score: number, description: string) => ({ cveId: id, description, cvssScore: score, severity: null, published: "" });

  it("ranks a 9.8 PHP flaw above an unrelated 10.0 in an obscure product", () => {
    const merged = mergeNvdCves(
      [[...Array.from({ length: 8 }, (_, i) => cve(`CVE-X-${i}`, 10, "Buffer overflow in AcmeCam firmware")), cve("CVE-2026-109618", 9.8, "PHP out-of-memory handling leads to remote code execution")]],
      6,
    );
    expect(merged[0].cveId).toBe("CVE-2026-109618");
    expect(merged).toHaveLength(6);
  });

  it("does not boost a CVE that names nothing a small business runs, and tolerates a missing score", () => {
    expect(cveRankScore(cve("A", 9, "flaw in AcmeCam firmware"))).toBe(9);
    expect(cveRankScore({ ...cve("B", 0, "PHP"), cvssScore: null })).toBe(2.5);
  });
});
