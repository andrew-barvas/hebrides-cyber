import { describe, it, expect, vi, afterEach } from "vitest";
import { nextBuildManifestUrl, parseNextPages, CRAWLER_USER_AGENT, urlKey, extractTitle, checkCrawl, parseRobots, normaliseUrl, urlShape, skipReason, isSameSite, analysePage, extractLinks } from "./crawler";
import { buildCrawlFindings } from "./crawlFindings";
import { buildScriptInventory, checkScriptInventory, crawledPagesForInventory } from "./scriptInventory";
import { scanCoverage, isCovered } from "../findingLifecycle";

const SECURE = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

type Route = { status?: number; type?: string; body?: string; headers?: Record<string, string>; fail?: boolean; textFails?: boolean; noType?: boolean };

/** Stubs fetch with a fixture site; records every request. */
function stubSite(routes: Record<string, Route>) {
  const requests: { url: string; method: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      requests.push({ url: url.href, method: init?.method ?? "GET" });
      const route = routes[url.origin + url.pathname + url.search] ?? routes[url.pathname + url.search] ?? routes[url.pathname];
      if (route?.fail) throw new Error("network down");
      if (route?.textFails) return { status: 200, headers: new Headers({ "content-type": "text/html" }), body: null, text: async () => { throw new Error("reset"); } } as unknown as Response;
      if (!route) return new Response("not found", { status: 404, headers: { "content-type": "text/html" } });
      const type = route.type ?? (url.pathname.endsWith(".xml") || url.pathname === "/robots.txt" ? "text/plain" : "text/html");
      return new Response(route.noType ? null : (route.body ?? ""), { status: route.status ?? 200, headers: { ...(route.noType ? {} : { "content-type": type }), ...(route.headers ?? {}) } });
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

const page = (url: string, depth: number, checks?: import("./crawler").PageChecks, status = 200) => ({ url, status, contentType: "text/html", title: null, depth, ...(checks ? { checks } : {}) });
const emptyChecks = (over: Partial<import("./crawler").PageChecks> = {}): import("./crawler").PageChecks => ({
  missingHeaders: [], cookies: [], mixedContent: [], insecureForms: [], errorDisclosure: [], unprotectedResources: [], scripts: [], paymentSignals: [], formCount: 0, ...over,
});
const crawlOf = (pages: ReturnType<typeof page>[]) => ({ status: "checked" as const, startUrl: "https://x.test/", truncated: false, pages });

describe("URL edge cases", () => {
  it("rejects unparseable URLs and detects relative-link loops", () => {
    expect(normaliseUrl("http://[", "https://x.test/")).toBeNull();
    expect(skipReason(new URL("https://x.test/a/b/a/b/a/b"))).toBe("loop");
  });
});

describe("analysePage edge cases", () => {
  const res = new Response("", { headers: { "content-type": "text/html" } });
  const run = (url: string, html: string) => analysePage({ url: new URL(url), status: 200, res, html });

  it("ignores non-stylesheet links, empty and unparseable references", () => {
    const c = run("https://x.test/", `<link rel="icon" href="https://cdn.test/i.ico"><img alt="no source"><form></form><img src=""><img src="http://[bad"><script src="http://["></script>`);
    expect(c.unprotectedResources).toEqual([]);
    expect(c.mixedContent).toEqual([]);
    expect(c.scripts).toEqual([]);
  });

  it("de-duplicates resources and scripts, and caps scripts", () => {
    const tags = `<script src="https://cdn.test/a.js"></script><script src="https://cdn.test/a.js"></script><link rel="stylesheet" href="https://cdn.test/s.css"><link rel="stylesheet" href="https://cdn.test/s.css">`;
    const c = run("https://x.test/", tags);
    expect(c.unprotectedResources).toHaveLength(2);
    expect(c.scripts).toHaveLength(1);
    const many = Array.from({ length: 50 }, (_, i) => `<script src="https://cdn.test/${i}.js" integrity="sha384-x"></script>`).join("");
    expect(run("https://x.test/", many).scripts).toHaveLength(40);
  });

  it("flags password fields on HTTP pages and ignores empty or invalid form actions", () => {
    const c = run("http://x.test/", `<form action=""></form><form action="http://[bad"></form><input type="password">`);
    expect(c.insecureForms).toEqual(["a password field is on a page served over unencrypted HTTP"]);
    expect(c.formCount).toBe(2);
  });

  it("caps the mixed-content list", () => {
    const imgs = Array.from({ length: 9 }, (_, i) => `<img src="http://a.test/${i}.png">`).join("");
    expect(run("https://x.test/", imgs).mixedContent).toHaveLength(5);
  });
});

describe("checkCrawl edge cases", () => {
  it("rejects an invalid target", async () => {
    expect((await checkCrawl("not a url")).status).toBe("error");
  });

  it("seeds from supplied paths, follows sitemap indexes and caps sitemap URLs", async () => {
    const locs = Array.from({ length: 205 }, (_, i) => `<url><loc>https://x.test/s${i}</loc></url>`).join("");
    stubSite({
      "/robots.txt": { body: "Sitemap: https://x.test/index.xml\nSitemap: https://x.test/gone.xml" },
      "/index.xml": { type: "application/xml", body: "<sitemapindex><sitemap><loc>https://x.test/child.xml</loc></sitemap><sitemap><loc>https://other.test/c.xml</loc></sitemap></sitemapindex>" },
      "/child.xml": { type: "application/xml", body: `<urlset>${locs}</urlset>` },
      "/": html("home"),
      "/seeded": html("seeded", "Seeded"),
    });
    const result = await checkCrawl("https://x.test/", { seedPaths: ["/seeded", "/robots-skipped.pdf"], maxPages: 400 });
    if (result.status === "error") throw new Error("unexpected");
    expect(result.pages.some((p) => p.title === "Seeded")).toBe(true);
    expect(result.pages).toHaveLength(1 + 200 + 1); // start + sitemap capped at 200 + seeded
  });

  it("records non-HTML responses without analysing them, and drops redirects to known pages", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<a href="/feed">f</a><a href="/b">b</a><a href="/a">a</a>`),
      "/feed": { type: "application/json", body: "{}" },
      "/a": { status: 301, headers: { location: "/b" } },
      "/b": html("b", "B"),
    });
    const result = await checkCrawl("https://x.test/");
    if (result.status === "error") throw new Error("unexpected");
    const feed = result.pages.find((p) => p.url.endsWith("/feed"));
    expect(feed?.contentType).toBe("application/json");
    expect(feed?.checks).toBeUndefined();
    expect(result.pages.filter((p) => p.title === "B")).toHaveLength(1);
  });

  it("copes with an invalid <base>, unreadable bodies and a redirect loop", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<base href="http://["><a href="/broken">x</a><a href="/loop">l</a>`),
      "/broken": { textFails: true },
      "/loop": { status: 302, headers: { location: "/loop2" } },
      "/loop2": { status: 302, headers: { location: "/loop3" } },
      "/loop3": { status: 302, headers: { location: "/loop4" } },
      "/loop4": { status: 302, headers: { location: "/loop5" } },
      "/loop5": { status: 302, headers: { location: "/loop" } },
    });
    const result = await checkCrawl("https://x.test/");
    expect(result.status).toBe("partial"); // both followed links failed
  });

  it("is partial when many page requests fail", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>`),
      "/a": { fail: true },
      "/b": { fail: true },
      "/c": html("c"),
    });
    const result = await checkCrawl("https://x.test/");
    expect(result.status).toBe("partial");
    if (result.status !== "error") expect(result.note).toContain("failed");
  });

  it("reports the final URL when the start page redirects", async () => {
    stubSite({ "/robots.txt": { status: 404 }, "/": { status: 302, headers: { location: "/home" } }, "/home": html(`<a href="/x">x</a>`, "Home"), "/x": html("x") });
    const result = await checkCrawl("https://x.test/");
    if (result.status === "error") throw new Error("unexpected");
    expect(result.startUrl).toBe("https://x.test/home");
    expect(result.pages.map((p) => p.title)).toEqual(["Home", "Page"]);
  });
});

describe("buildCrawlFindings edge cases", () => {
  const start = (over = {}) => page("https://x.test/", 0, emptyChecks(over));

  it("handles an empty crawl", () => {
    expect(buildCrawlFindings({ ...crawlOf([]) })).toEqual([]);
  });

  it("lists many pages, singular wording, long paths and skips error-status pages for headers", () => {
    const lacking = Array.from({ length: 12 }, (_, i) => page(`https://x.test/p${i}`, 1, emptyChecks({ missingHeaders: ["x-frame-options"] })));
    const long = page(`https://x.test/${"a".repeat(200)}`, 1, emptyChecks({ missingHeaders: ["referrer-policy"] }));
    const errored = page("https://x.test/err", 1, emptyChecks({ missingHeaders: ["x-content-type-options"] }), 500);
    const findings = buildCrawlFindings(crawlOf([start(), ...lacking, long, errored]));
    const xfo = findings.find((f) => f.checkId === "crawl.header-gap:x-frame-options");
    expect(xfo?.detail).toContain("and 2 more");
    expect(xfo?.title).toContain("12 pages");
    const ref = findings.find((f) => f.checkId === "crawl.header-gap:referrer-policy");
    expect(ref?.title).toContain("1 page");
    expect(ref?.title).not.toContain("1 pages");
    expect(ref?.detail).toContain("…");
    expect(findings.some((f) => f.checkId === "crawl.header-gap:x-content-type-options")).toBe(false);
  });

  it("skips header gaps when the start page has no analysis, and ignores pages without checks", () => {
    const noChecks = page("https://x.test/", 0);
    const findings = buildCrawlFindings(crawlOf([noChecks, page("https://x.test/a", 1), page("https://x.test/b", 1, emptyChecks({ missingHeaders: ["x-frame-options"], mixedContent: [], cookies: [{ name: "c", issues: ["Missing Secure flag"] }] }))]));
    expect(findings.map((f) => f.checkId)).toEqual(["crawl.cookie-flags:c"]);
  });

  it("ignores cookies with no issues or already seen on the start page", () => {
    const findings = buildCrawlFindings(crawlOf([
      start({ cookies: [{ name: "home", issues: [] }] }),
      page("https://x.test/a", 1, emptyChecks({ cookies: [{ name: "home", issues: ["x"] }, { name: "ok", issues: [] }] })),
    ]));
    expect(findings).toEqual([]);
  });

  it("aggregates SRI: stylesheet-only is low, skips what the start page reports, caps the list", () => {
    const res = (n: number, kind: "script" | "stylesheet") => ({ kind, url: `https://cdn.test/${n}` });
    const cssOnly = buildCrawlFindings(crawlOf([start({ unprotectedResources: [res(0, "script")] }), page("https://x.test/a", 1, emptyChecks({ unprotectedResources: [res(0, "script"), res(1, "stylesheet")] }))]));
    expect(cssOnly).toHaveLength(1);
    expect(cssOnly[0].severity).toBe("low");
    expect(cssOnly[0].title).toContain("1 cross-origin resource ");
    const many = buildCrawlFindings(crawlOf([start(), page("https://x.test/a", 1, emptyChecks({ unprotectedResources: [res(1, "script"), res(2, "script"), res(3, "script"), res(4, "script"), res(5, "script")] })), ...Array.from({ length: 8 }, (_, i) => page(`https://x.test/m${i}`, 1, emptyChecks({ unprotectedResources: [res(10 + i, "script")] })))]));
    expect(many[0].severity).toBe("medium");
    expect(many[0].detail).toContain("and 3 more");
  });

  it("reports insecure forms and error disclosure, and ignores pages without those", () => {
    const findings = buildCrawlFindings(crawlOf([
      start({ insecureForms: ["a password field is on a page served over unencrypted HTTP"] }),
      page("https://x.test/a", 1),
      page("https://x.test/b", 1, emptyChecks({ errorDisclosure: ["PHP error"] }), 500),
    ]));
    expect(findings.map((f) => f.checkId)).toEqual(["crawl.insecure-form:/", "crawl.error-disclosure:/b"]);
  });
});

describe("remaining branches", () => {
  it("keys URLs with ports and ignores scheme and www", () => {
    expect(urlKey(new URL("https://www.x.test:8443/a?b=1"))).toBe("x.test:8443/a?b=1");
    expect(urlKey(new URL("http://x.test/a"))).toBe(urlKey(new URL("https://www.x.test/a")));
  });

  it("only treats a true repeat as a loop", () => {
    expect(skipReason(new URL("https://x.test/a/b/a/b/c/d"))).toBeNull();
    expect(skipReason(new URL("https://x.test/a/b/a/c/a/d"))).toBeNull();
    expect(skipReason(new URL("https://x.test/a/b/c/b/a/b"))).toBeNull();
  });

  it("parses odd robots.txt layouts", () => {
    expect(parseRobots("Sitemap:\nDisallow: /early\nUser-agent: a\nUser-agent: *\nDisallow: /x\n# note\nnonsense").allows("/x")).toBe(false);
    expect(parseRobots("Disallow: /early").allows("/early")).toBe(true);
    expect(parseRobots("User-agent: *\nDisallow: /a\nAllow: /a").allows("/a")).toBe(true);
    expect(parseRobots("User-agent: *\nAllow: /a/b\nDisallow: /a").allows("/a/b")).toBe(true);
    expect(parseRobots("User-agent: *\nAllow: /a\nDisallow: /a/b").allows("/a/b")).toBe(false);
    expect(parseRobots("User-agent: *\nSitemap:").sitemaps).toEqual([]);
  });

  it("reads titles and unquoted hrefs", () => {
    expect(extractTitle("<title>  </title>")).toBeNull();
    expect(extractTitle("<p>none</p>")).toBeNull();
    expect(extractLinks("<a href=/plain>x</a>").hrefs).toEqual(["/plain"]);
  });

  it("handles responses with no content-type, a non-HTML start page and http→https redirects", async () => {
    stubSite({
      "/robots.txt": { status: 404 },
      "/": { type: "application/json", body: "{}" },
    });
    const json = await checkCrawl("https://x.test/");
    if (json.status === "error") throw new Error("unexpected");
    expect(json.pages).toHaveLength(1);

    stubSite({
      "/robots.txt": { status: 404 },
      "/": html(`<a href="http://x.test/a">a</a><a href="/blank">b</a>`),
      "http://x.test/a": { status: 301, headers: { location: "https://x.test/a" } },
      "/a": html("a"),
      "/blank": { noType: true },
    });
    const result = await checkCrawl("https://x.test/");
    if (result.status === "error") throw new Error("unexpected");
    expect(result.pages.find((p) => p.url.endsWith("/blank"))?.contentType).toBeNull();
    expect(result.pages.filter((p) => new URL(p.url).pathname === "/a")).toHaveLength(1);
  });

  it("marks the inventory partial when the crawl didn't cover the site, so findings aren't resolved", async () => {
    stubSite({ "/": html("hi") });
    const playwright = { status: "error", note: "x" } as unknown as Parameters<typeof checkScriptInventory>[1];
    const ok = { status: "checked" as const, startUrl: "https://x.test/", truncated: false, pages: [] };
    const browserOk = { status: "checked", loadedOk: true, finalUrl: "https://x.test/", scripts: { requested: [], elements: [] } } as unknown as Parameters<typeof checkScriptInventory>[1];

    expect((await checkScriptInventory("https://x.test/", browserOk, ok)).status).toBe("checked");
    expect((await checkScriptInventory("https://x.test/", browserOk)).status).toBe("checked");
    const partial = await checkScriptInventory("https://x.test/", browserOk, { ...ok, status: "partial" });
    expect(partial.status).toBe("partial");
    if (partial.status === "partial") expect(partial.note).toContain("crawl was incomplete");
    const errored = await checkScriptInventory("https://x.test/", browserOk, { status: "error", note: "x" });
    expect(errored.status).toBe("partial");
    // Already partial (no browser): unchanged, no duplicate note.
    const noBrowser = await checkScriptInventory("https://x.test/", playwright, { ...ok, status: "partial" });
    expect(noBrowser.status).toBe("partial");
  });
});

describe("crawler identity", () => {
  it("prefers a robots.txt group naming the crawler over the * group", () => {
    const rules = parseRobots("User-agent: *\nDisallow: /\n\nUser-agent: HebridesCyberScanner\nDisallow: /private\n");
    expect(rules.allows("/public")).toBe(true);
    expect(rules.allows("/private/x")).toBe(false);
    expect(parseRobots("User-agent: hebridescyber\nDisallow: /").allows("/a")).toBe(false);
  });

  it("sends an identifying User-Agent on every request, including robots.txt and sitemaps", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      seen.push((init?.headers as Record<string, string>)["user-agent"]);
      return new Response("<html><title>x</title></html>", { status: 200, headers: { "content-type": "text/html" } });
    }));
    await checkCrawl("https://x.test/");
    expect(seen.length).toBeGreaterThanOrEqual(3); // robots, start page, sitemap
    expect(new Set(seen)).toEqual(new Set([CRAWLER_USER_AGENT]));
    expect(CRAWLER_USER_AGENT).toContain("hebridescyber.co.uk");
  });
});

describe("Next.js route discovery", () => {
  const start = new URL("https://x.test/");
  const HOME_WITH_MANIFEST = `<html><head><title>Home</title><script src="/_next/static/abc123XYZ/_buildManifest.js" defer></script></head><body>nothing linked</body></html>`;
  const manifest = `self.__BUILD_MANIFEST={__rewrites:{},sortedPages:["/","/_app","/_error","/404","/500","/about","/admin/login","/blog/[slug]","/api/hello","/_next/x","/pricing","bad"]};`;

  it("finds the build manifest in a page, only on the same site", () => {
    expect(nextBuildManifestUrl(HOME_WITH_MANIFEST, start, start)?.href).toBe("https://x.test/_next/static/abc123XYZ/_buildManifest.js");
    expect(nextBuildManifestUrl("<html></html>", start, start)).toBeNull();
    // A manifest served from another site is not ours to fetch.
    expect(nextBuildManifestUrl('<script src="https://cdn.other.test/_next/static/abc123XYZ/_buildManifest.js">', start, start)).toBeNull();
  });

  it("keeps only static page routes", () => {
    expect(parseNextPages(manifest)).toEqual(["/about", "/admin/login", "/pricing"]);
    expect(parseNextPages("no manifest here")).toEqual([]);
    expect(parseNextPages("sortedPages:[]")).toEqual([]);
    const many = `sortedPages:[${Array.from({ length: 250 }, (_, i) => `"/p${i}"`).join(",")}]`;
    expect(parseNextPages(many)).toHaveLength(200);
  });

  it("crawls pages that nothing links to, using the manifest", async () => {
    const requests = stubSite({
      "/robots.txt": { body: "User-agent: *\nAllow: /" },
      "/": html("<p>no links</p>").body ? { body: HOME_WITH_MANIFEST, headers: SECURE } : {},
      "/_next/static/abc123XYZ/_buildManifest.js": { type: "application/javascript", body: manifest },
      "/about": html("about", "About"),
      "/admin/login": html("login", "Login"),
      "/pricing": html("pricing", "Pricing"),
    });
    const crawl = await checkCrawl("https://x.test/");
    const paths = requests.map((r) => new URL(r.url).pathname);
    expect(paths).toEqual(expect.arrayContaining(["/about", "/admin/login", "/pricing"]));
    expect(paths).not.toContain("/blog/[slug]");
    expect(paths).not.toContain("/api/hello");
    expect(crawl.status === "checked" || crawl.status === "partial").toBe(true);
  });

  it("is quiet when the manifest cannot be read", async () => {
    stubSite({ "/robots.txt": { body: "User-agent: *\nAllow: /" }, "/": { body: HOME_WITH_MANIFEST, headers: SECURE }, "/_next/static/abc123XYZ/_buildManifest.js": { status: 404 } });
    const crawl = await checkCrawl("https://x.test/");
    expect(crawl.status).not.toBe("error");
    stubSite({ "/robots.txt": { body: "User-agent: *\nAllow: /" }, "/": { body: HOME_WITH_MANIFEST, headers: SECURE }, "/_next/static/abc123XYZ/_buildManifest.js": { fail: true } });
    expect((await checkCrawl("https://x.test/")).status).not.toBe("error");
  });
});
