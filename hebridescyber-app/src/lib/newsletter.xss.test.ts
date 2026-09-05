// Regression coverage for a real finding: buildKevSection/buildNvdSection/
// buildNewsSection embed external, uncontrolled text (CISA's KEV catalog,
// NVD CVE descriptions, RSS feed titles) directly into the markdown that
// becomes a public blog post's body. A CVE description routinely contains
// a literal <script>/onerror snippet as part of describing the
// vulnerability it's about — without escaping here, that snippet would
// survive marked.parse() (which doesn't sanitize) and render on
// /blog/[slug], a fully public, unauthenticated page. Escaping is applied
// at generation time (this file); DOMPurify sanitizes again at render time
// (src/app/blog/[slug]/page.tsx) as a second, independent layer.
import { describe, it, expect } from "vitest";
import { buildKevSection, buildNvdSection, buildNewsSection } from "./newsletter";
import type { KevMatch, NvdCve, NewsArticle } from "./newsletter";

const XSS_PAYLOAD = '<script>alert(1)</script><img src=x onerror=alert(2)>';

describe("buildKevSection — escapes untrusted CISA KEV text", () => {
  it("neutralises a script tag embedded in the vulnerability name", () => {
    const matches: KevMatch[] = [
      {
        entry: {
          cveId: "CVE-2026-0001",
          vendorProject: "Example Corp",
          product: "Example Product",
          vulnerabilityName: XSS_PAYLOAD,
          shortDescription: "",
          dateAdded: "2026-09-01",
          dueDate: null,
        },
        matchedTech: "WordPress",
      },
    ];

    const result = buildKevSection(matches);

    expect(result).not.toContain("<script>");
    expect(result).not.toContain("<img");
    expect(result).toContain("&lt;script&gt;");
  });

  it("neutralises a script tag embedded in the matched technology name", () => {
    const matches: KevMatch[] = [
      {
        entry: {
          cveId: "CVE-2026-0002",
          vendorProject: "Vendor",
          product: "Product",
          vulnerabilityName: "Real vulnerability",
          shortDescription: "",
          dateAdded: "2026-09-01",
          dueDate: null,
        },
        matchedTech: XSS_PAYLOAD,
      },
    ];

    const result = buildKevSection(matches);

    expect(result).not.toContain("<script>");
    expect(result).toContain("&lt;script&gt;");
  });
});

describe("buildNvdSection — escapes untrusted NVD CVE text", () => {
  it("neutralises a script tag embedded in the CVE description", () => {
    const cves: NvdCve[] = [
      {
        cveId: "CVE-2026-0003",
        description: `Cross-site scripting vulnerability allows injection via ${XSS_PAYLOAD}`,
        cvssScore: 8.2,
        severity: "high",
        published: "2026-09-01",
      },
    ];

    const result = buildNvdSection(cves);

    expect(result).not.toContain("<script>");
    expect(result).not.toContain("<img");
    expect(result).toContain("&lt;script&gt;");
  });

  it("handles a null severity without throwing", () => {
    const cves: NvdCve[] = [
      { cveId: "CVE-2026-0004", description: "desc", cvssScore: 7.5, severity: null, published: "2026-09-01" },
    ];

    expect(() => buildNvdSection(cves)).not.toThrow();
  });
});

describe("buildNewsSection — escapes untrusted RSS feed text", () => {
  it("neutralises a script tag embedded in the article title", () => {
    const news: NewsArticle[] = [
      {
        title: `Breach at Example Co ${XSS_PAYLOAD}`,
        link: "https://example.com/article",
        source: "Example News",
        publishedAt: "2026-09-01T00:00:00Z",
        summary: "A summary",
      },
    ];

    const result = buildNewsSection(news);

    expect(result).not.toContain("<script>");
    expect(result).not.toContain("<img");
    expect(result).toContain("&lt;script&gt;");
  });

  it("neutralises a script tag embedded in the article summary", () => {
    const news: NewsArticle[] = [
      {
        title: "Real headline",
        link: "https://example.com/article",
        source: "Example News",
        publishedAt: "2026-09-01T00:00:00Z",
        summary: XSS_PAYLOAD,
      },
    ];

    const result = buildNewsSection(news);

    expect(result).not.toContain("<script>");
    expect(result).toContain("&lt;script&gt;");
  });
});
