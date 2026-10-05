import { describe, it, expect, vi, afterEach } from "vitest";
import { checkCrawl, parseRobots, normaliseUrl, urlShape, skipReason, isSameSite, analysePage, extractLinks } from "./crawler";
import { buildCrawlFindings } from "./crawlFindings";
import { buildScriptInventory, crawledPagesForInventory } from "./scriptInventory";
import { scanCoverage, isCovered } from "../findingLifecycle";

const SECURE = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

type Route = { status?: number; type?: string; body?: string; headers?: Record<string, string> };

/** Stubs fetch with a fixture site; records every request. */
function stubSite(routes: Record<string, Route>) {
  const requests: { url: string; method: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      requests.push({ url: url.href, method: init?.method ?? "GET" });
      const route = routes[url.origin + url.pathname + url.search] ?? routes[url.pathname + url.search] ?? routes[url.pathname];
      if (!route) return new Response("not found", { status: 404, headers: { "content-type": "text/html" } });
      const type = route.type ?? (url.pathname.endsWith(".xml") || url.pathname === "/robots.txt" ? "text/plain" : "text/html");
      return new Response(route.body ?? "", { status: route.status ?? 200, headers: { "content-type": type, ...(route.headers ?? {}) } });
    })
  );
  return requests;
}

const html = (body: string, title = "Page") => ({ body: `<html><head><title>${title}</title></head><body>${body}</body></html>`, headers: SECURE });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("parseRobots", () => {
  const rules = parseRobots(`User-agent: Googlebot\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\nAllow: /admin/public\nDisallow: /*.pdf$\nSitemap: https://x.test/sm.xml`);
  it("uses the * group, longest match wins", () => {
    expect(rules.allows("/admin/secret")).toBe(false);
    expect(rules.allows("/admin/public/a")).toBe(true);
    expect(rules.allows("/about")).toBe(true);
    expect(rules.allows("/doc.pdf")).toBe(false);
    expect(rules.allows("/doc.pdf?x")).toBe(true);
  });
  it("collects sitemaps and treats an empty Disallow as allow-all", () => {
    expect(rules.sitemaps).toEqual(["https://x.test/sm.xml"]);
    expect(parseRobots("User-agent: *\nDisallow:").allows("/anything")).toBe(true);
  });
});

describe("URL handling", () => {
  it("strips fragments and tracking params, sorts and caps the query", () => {
    expect(normaliseUrl("/a?b=2&utm_source=x&a=1#top", "https://x.test/")?.href).toBe("https://x.test/a?a=1&b=2");
    expect(normaliseUrl("/a?a=1&b=2&c=3&d=4", "https://x.test/")?.href).toBe("https://x.test/a");
    expect(normaliseUrl("mailto:a@b.c", "https://x.test/")).toBeNull();
  });
  it("collapses numeric segments into one shape", () => {
    expect(urlShape(new URL("https://x.test/p/1"))).toBe(urlShape(new URL("https://x.test/p/987")));
  });
  it("never follows action links, files or loops", () => {
    expect(skipReason(new URL("https://x.test/logout"))).toBe("action link");
    expect(skipReason(new URL("https://x.test/cart?add-to-cart=3"))).toBe("action link");
    expect(skipReason(new URL("https://x.test/a.pdf"))).toBe("not a page");
    expect(skipReason(new URL("https://x.test/a/b/a/b/a/b/c"))).not.toBeNull();
    expect(skipReason(new URL("https://x.test/about"))).toBeNull();
  });
  it("treats www and apex as one site, other hosts as off-site", () => {
    const start = new URL("https://www.x.test/");
    expect(isSameSite(new URL("https://x.test/a"), start)).toBe(true);
    expect(isSameSite(new URL("https://blog.x.test/a"), start)).toBe(false);
    expect(isSameSite(new URL("https://evil.test/"), start)).toBe(false);
  });
  it("reads links and <base>", () => {
    const { base, hrefs } = extractLinks(`<base href="/sub/"><a href="a">1</a><a href='#x'>2</a><a href="javascript:void(0)">3</a><area href="b&amp;c">`);
    expect(base).toBe("/sub/");
    expect(hrefs).toEqual(["a", "b&c"]);
  });
});

describe("checkCrawl", () => {
  it("crawls inner pages, honouring robots, scope and action links; never submits forms", async () => {
    const requests = stubSite({
      "/robots.txt": { body: "User-agent: *\nDisallow: /admin\nSitemap: https://x.test/sitemap.xml" },
      "/sitemap.xml": { type: "application/xml", body: "<urlset><url><loc>https://x.test/hidden</loc></url><url><loc>https://other.test/x</loc></url></urlset>" },
      "/": html(`<a href="/about">a</a><a href="/login">l</a><a href="/admin">ad</a><a href="/logout">lo</a><a href="https://other.test/">o</a><a href="/f.pdf">p</a>
        ${[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `<a href="/products/${n}">p${n}</a>`).join("")}<form action="/search" method="post"><input name="q"></form>`, "Home"),
      "/about": html("About", "About"),
      "/login": html(`<form action="http://x.test/session"><input type="password"></form><img src="http://cdn.test/a.png">`, "Login"),
      "/hidden": html("hidden", "Hidden"),
    });
    const result = await checkCrawl("https://x.test/");
    expect(result.status).toBe("checked");
    if (result.status === "error") return;
    const paths = result.pages.map((p) => new URL(p.url).pathname);
    expect(paths).toContain("/about");
    expect(paths).toContain("/login");
    expect(paths).toContain("/hidden"); // from the sitemap
    expect(paths).not.toContain("/admin");
    expect(paths).not.toContain("/logout");
    expect(paths).not.toContain("/f.pdf");
    expect(paths.filter((p) => p.startsWith("/products/")).length).toBeLessThanOrEqual(5);
    expect(requests.every((r) => r.method === "GET")).toBe(true);
    expect(requests.some((r) => r.url.includes("other.test"))).toBe(false);
    expect(requests.some((r) => r.url.endsWith("/search"))).toBe(false);
    expect(result.pages[0].title).toBe("Home");
    expect(result.pages[0].checks?.formCount).toBe(1);
  });

  it("does not loop on self-links and query traps", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<a href="/cal?d=1">1</a><a href="/cal?d=2">2</a><a href="/cal?d=3">3</a><a href="/">self</a>`),
      "/cal": html(`<a href="/cal?d=4">n</a><a href="/">home</a>`),
    });
    const result = await checkCrawl("https://x.test/");
    expect(result.status).toBe("checked");
    if (result.status === "error") return;
    const keys = result.pages.map((p) => p.url);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys.filter((u) => u.includes("/cal")).length).toBeLessThanOrEqual(5);
  });

  it("respects the depth limit", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<a href="/l1">1</a>`),
      "/l1": html(`<a href="/l2">2</a>`),
      "/l2": html(`<a href="/l3">3</a>`),
      "/l3": html(`<a href="/l4">4</a>`),
      "/l4": html("deep"),
    });
    const result = await checkCrawl("https://x.test/");
    if (result.status === "error") throw new Error("unexpected");
    expect(result.pages.map((p) => new URL(p.url).pathname)).toEqual(["/", "/l1", "/l2", "/l3"]);
    expect(result.status).toBe("checked");
  });

  it("is partial and truncated at the page cap", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": html([...Array(8)].map((_, i) => `<a href="/p${i}">x</a>`).join("")),
    });
    const result = await checkCrawl("https://x.test/", { maxPages: 3 });
    expect(result.status).toBe("partial");
    if (result.status === "error") return;
    expect(result.pages.length).toBeLessThanOrEqual(3);
    expect(result.truncated).toBe(true);
  });

  it("is partial when the time budget is spent", async () => {
    stubSite({ "/robots.txt": { status: 404 }, "/": html(`<a href="/a">a</a>`), "/a": html("a") });
    const result = await checkCrawl("https://x.test/", { budgetMs: -1 });
    expect(result.status).toBe("partial");
    if (result.status !== "error") expect(result.truncated).toBe(true);
  });

  it("is an error when the start page is blocked or unreachable", async () => {
    stubSite({ "/robots.txt": { status: 404 }, "/": { status: 403, body: "blocked" } });
    expect((await checkCrawl("https://x.test/")).status).toBe("error");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect((await checkCrawl("https://x.test/")).status).toBe("error");
  });

  it("visits only the start page, as partial, when robots.txt can't be read", async () => {
    stubSite({ "/robots.txt": { status: 500 }, "/": html(`<a href="/a">a</a>`), "/a": html("a") });
    const result = await checkCrawl("https://x.test/");
    expect(result.status).toBe("partial");
    if (result.status !== "error") expect(result.pages).toHaveLength(1);
  });

  it("is partial when the site rate-limits the crawler", async () => {
    stubSite({ "/robots.txt": { status: 404 }, "/": html(`<a href="/a">a</a>`), "/a": { status: 429, body: "slow down" } });
    expect((await checkCrawl("https://x.test/")).status).toBe("partial");
  });

  it("follows same-site redirects and records off-site ones without following", async () => {
    const requests = stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<a href="/old">o</a><a href="/away">a</a>`),
      "/old": { status: 301, headers: { location: "/new" } },
      "/new": html("new", "New"),
      "/away": { status: 302, headers: { location: "https://other.test/x" } },
    });
    const result = await checkCrawl("https://x.test/");
    if (result.status === "error") throw new Error("unexpected");
    expect(result.pages.some((p) => p.url.endsWith("/new") && p.title === "New")).toBe(true);
    expect(requests.some((r) => r.url.includes("other.test"))).toBe(false);
  });
});

describe("page checks and findings", () => {
  const insecureHome = { body: `<a href="/shop">s</a><a href="/blog">b</a><a href="/login">l</a><a href="/oops">o</a>`, headers: SECURE };

  it("reports issues found only on inner pages, one finding per gap", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": { ...html(insecureHome.body), headers: { ...SECURE, "set-cookie": "home=1; Secure; HttpOnly; SameSite=Lax" } },
      // /shop and /blog lack CSP and X-Frame-Options (a different route).
      "/shop": { body: `<h1>shop</h1><script src="https://cdn.shop.test/a.js"></script>`, headers: { "strict-transport-security": "max-age=1", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "set-cookie": "cart=1" } },
      "/blog": { body: `<h1>blog</h1>`, headers: { "strict-transport-security": "max-age=1", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" } },
      "/login": { ...html(`<form action="http://x.test/s"><input type="password"></form><script src="http://x.test/m.js"></script>`), headers: SECURE },
      "/oops": { status: 500, type: "text/html", body: "Traceback (most recent call last): boom", headers: {} },
    });
    const result = await checkCrawl("https://x.test/");
    const findings = buildCrawlFindings(result);
    const ids = findings.map((f) => f.checkId ?? "");

    const csp = findings.find((f) => f.checkId === "crawl.header-gap:content-security-policy");
    expect(csp?.detail).toContain("/shop");
    expect(csp?.detail).toContain("/blog");
    expect(ids).toContain("crawl.header-gap:x-frame-options");
    expect(ids.filter((i) => i.startsWith("crawl.header-gap:content-security-policy"))).toHaveLength(1);
    expect(ids).not.toContain("crawl.header-gap:strict-transport-security");
    expect(ids).toContain("crawl.cookie-flags:cart");
    expect(ids).not.toContain("crawl.cookie-flags:home");
    expect(ids).toContain("crawl.insecure-form:/login");
    expect(findings.find((f) => f.checkId === "crawl.mixed-content:/login")?.severity).toBe("high");
    expect(ids).toContain("crawl.error-disclosure:/oops");
    expect(ids).toContain("crawl.missing-sri");
  });

  it("does not report what the start page also lacks (headers.* already does)", () => {
    const res = new Response("", { headers: { "content-type": "text/html" } });
    const page = (url: string, depth: number) => ({
      url, status: 200, contentType: "text/html", title: null, depth,
      checks: analysePage({ url: new URL(url), status: 200, res, html: "<p>x</p>" }),
    });
    const findings = buildCrawlFindings({ status: "checked", startUrl: "https://x.test/", truncated: false, pages: [page("https://x.test/", 0), page("https://x.test/a", 1)] });
    expect(findings).toEqual([]);
  });

  it("only flags error disclosure on real error pages", () => {
    const res = new Response("", { headers: { "content-type": "text/html" } });
    const body = "Traceback (most recent call last)";
    expect(analysePage({ url: new URL("https://x.test/blog"), status: 200, res, html: body }).errorDisclosure).toEqual([]);
    expect(analysePage({ url: new URL("https://x.test/x"), status: 404, res, html: body }).errorDisclosure).toEqual(["Django debug traceback"]);
  });

  it("treats CSP frame-ancestors as satisfying X-Frame-Options", () => {
    const res = new Response("", { headers: { "content-security-policy": "frame-ancestors 'none'" } });
    expect(analysePage({ url: new URL("https://x.test/"), status: 200, res, html: "" }).missingHeaders).not.toContain("x-frame-options");
  });

  it("caps per-page findings", () => {
    const mk = (i: number) => ({
      url: `https://x.test/p${i}`, status: 200, contentType: "text/html", title: null, depth: 1,
      checks: { missingHeaders: [], cookies: [], mixedContent: [{ url: "http://a.test/i.png", active: false }], insecureForms: [], errorDisclosure: [], unprotectedResources: [], scripts: [], paymentSignals: [], formCount: 0 },
    });
    const findings = buildCrawlFindings({ status: "checked", startUrl: "https://x.test/", truncated: false, pages: [{ ...mk(0), depth: 0 }, ...Array.from({ length: 25 }, (_, i) => mk(i + 1))] });
    expect(findings.filter((f) => f.checkId?.startsWith("crawl.mixed-content:"))).toHaveLength(10);
    expect(findings[0].severity).toBe("medium");
  });

  it("yields no findings for an error crawl", () => {
    expect(buildCrawlFindings({ status: "error", note: "x" })).toEqual([]);
    expect(buildCrawlFindings(undefined)).toEqual([]);
  });
});

describe("lifecycle and script inventory", () => {
  it("a partial or error crawl doesn't count as having covered crawl findings", () => {
    for (const status of ["partial", "error"]) {
      const coverage = scanCoverage(null, { crawl: { status } });
      expect(isCovered("base", coverage, "crawl.mixed-content:/login")).toBe(false);
    }
    expect(isCovered("base", scanCoverage(null, { crawl: { status: "checked" } }), "crawl.mixed-content:/login")).toBe(true);
  });

  it("merges third-party scripts from inner pages and marks payment pages", () => {
    const crawl = {
      status: "checked" as const, startUrl: "https://x.test/", truncated: false,
      pages: [
        { url: "https://x.test/", status: 200, contentType: "text/html", title: null, depth: 0 },
        { url: "https://x.test/checkout", status: 200, contentType: "text/html", title: null, depth: 1, checks: { missingHeaders: [], cookies: [], mixedContent: [], insecureForms: [], errorDisclosure: [], unprotectedResources: [], scripts: [{ src: "https://ads.test/a.js", hasIntegrity: false }, { src: "https://x.test/own.js", hasIntegrity: false }], paymentSignals: ["a card input field"], formCount: 1 } },
        { url: "https://x.test/gone", status: 404, contentType: "text/html", title: null, depth: 1, checks: { missingHeaders: [], cookies: [], mixedContent: [], insecureForms: [], errorDisclosure: [], unprotectedResources: [], scripts: [{ src: "https://err.test/e.js", hasIntegrity: false }], paymentSignals: [], formCount: 0 } },
      ],
    };
    const inv = buildScriptInventory({ targetUrl: "https://x.test/", html: { body: "<p>hi</p>", url: "https://x.test/" }, runtime: null, crawledPages: crawledPagesForInventory(crawl) });
    if (inv.status === "error") throw new Error("unexpected");
    expect(inv.origins.map((o) => o.origin)).toEqual(["https://ads.test"]);
    expect(inv.origins[0].paymentPages).toEqual(["/checkout"]);
    expect(inv.paymentPage.detected).toBe(false);
  });
});
