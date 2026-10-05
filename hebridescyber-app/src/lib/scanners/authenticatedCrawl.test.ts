import { describe, it, expect, vi, afterEach } from "vitest";
import { buildAuthenticatedCrawlFindings, checkAuthenticatedCrawl, credentialHeaders, landedOnLoginWall } from "./authenticatedCrawl";
import { checkAuthenticated, buildAuthenticatedFindings } from "./authenticatedCheck";
import { skipReason } from "./crawler";
import { getComplianceRefs } from "./compliance";
import { getFixDifficulty } from "./fixDifficulty";

const SECURE = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

type Route = { status?: number; body?: string; headers?: Record<string, string>; location?: string };
type Seen = { url: string; cookie: string | null; authorization: string | null };

/** A fixture site whose app pages answer only when the request carries the cookie "sid=ok". */
function stubApp(routes: Record<string, Route>, opts: { requireCookie?: boolean } = { requireCookie: true }) {
  const seen: Seen[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const h = new Headers(init?.headers);
      seen.push({ url: url.href, cookie: h.get("cookie"), authorization: h.get("authorization") });
      const route = routes[url.pathname];
      if (!route) return new Response("nope", { status: 404, headers: { "content-type": "text/html" } });
      const allowed = !opts.requireCookie || url.pathname === "/robots.txt" || url.pathname === "/login" || h.get("cookie") === "sid=ok";
      if (!allowed) return new Response("", { status: 302, headers: { location: "/login" } });
      return new Response(route.body ?? "", {
        status: route.status ?? 200,
        headers: { "content-type": url.pathname === "/robots.txt" ? "text/plain" : "text/html", ...(route.headers ?? {}), ...(route.location ? { location: route.location } : {}) },
      });
    })
  );
  return seen;
}

const page = (body: string, headers: Record<string, string> = SECURE) => ({ body: `<html><head><title>T</title></head><body>${body}</body></html>`, headers });

afterEach(() => vi.unstubAllGlobals());

describe("credentialHeaders", () => {
  it("builds a Cookie or Basic Authorization header", () => {
    expect(credentialHeaders({ type: "cookie", cookieValue: "sid=ok" })).toEqual({ Cookie: "sid=ok" });
    expect(credentialHeaders({ type: "basic", username: "a", password: "b" })).toEqual({ Authorization: "Basic YTpi" });
  });
});

describe("landedOnLoginWall", () => {
  it("is true only when the start request ended on a login path it did not ask for", () => {
    expect(landedOnLoginWall("https://x.test/app", "https://x.test/login")).toBe(true);
    expect(landedOnLoginWall("https://x.test/app", "https://x.test/app")).toBe(false);
    expect(landedOnLoginWall("https://x.test/login", "https://x.test/login")).toBe(false);
    expect(landedOnLoginWall("https://x.test/app", "https://x.test/dashboard")).toBe(false);
  });
});

describe("signed-in link rules", () => {
  it("skips spend/account-state links only when signed in", () => {
    const url = new URL("https://x.test/account/billing");
    expect(skipReason(url)).toBeNull();
    expect(skipReason(url, true)).toBe("action link");
    expect(skipReason(new URL("https://x.test/account/profile"), true)).toBeNull();
  });
});

describe("checkAuthenticatedCrawl", () => {
  const site = {
    "/robots.txt": { body: "User-agent: *\nAllow: /" },
    "/app": page('<a href="/app/settings">s</a><a href="/app/billing">b</a><a href="/logout">out</a>'),
    "/app/settings": page('<form action="http://x.test/save"><input type="password"></form>', { ...SECURE, "set-cookie": "sess=1; Path=/" }),
    "/app/billing": page("secret"),
    "/logout": page("bye"),
    "/login": page("login"),
  };

  it("crawls signed-in pages, sending the credential but never visiting action links", async () => {
    const seen = stubApp(site);
    const crawl = await checkAuthenticatedCrawl("https://x.test/app", { type: "cookie", cookieValue: "sid=ok" });
    expect(crawl.status === "checked" || crawl.status === "partial").toBe(true);
    const visited = seen.map((s) => new URL(s.url).pathname);
    expect(visited).toContain("/app/settings");
    expect(visited).not.toContain("/app/billing");
    expect(visited).not.toContain("/logout");
    // Every page request carried the cookie; robots.txt and sitemaps did not.
    for (const s of seen) {
      const isPage = !/robots\.txt|sitemap/.test(s.url);
      expect(s.cookie).toBe(isPage ? "sid=ok" : null);
    }
  });

  it("is an error, not a clean result, when the credential is not accepted", async () => {
    stubApp(site);
    const crawl = await checkAuthenticatedCrawl("https://x.test/app", { type: "cookie", cookieValue: "sid=expired" });
    expect(crawl).toMatchObject({ status: "error" });
    expect((crawl as { note: string }).note).toMatch(/not accepted/);
  });

  it("reports an unreachable start page as an error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    const crawl = await checkAuthenticatedCrawl("https://x.test/app", { type: "basic", username: "u", password: "p" });
    expect(crawl).toMatchObject({ status: "error" });
    expect((crawl as { note: string }).note).toMatch(/Signed-in crawl could not run/);
  });

  it("namespaces findings as crawl.auth.* and includes the start page", async () => {
    stubApp(site);
    const crawl = await checkAuthenticatedCrawl("https://x.test/app", { type: "cookie", cookieValue: "sid=ok" });
    const findings = buildAuthenticatedCrawlFindings(crawl);
    const form = findings.find((f) => f.checkId?.startsWith("crawl.auth.insecure-form:"));
    expect(form).toBeDefined();
    expect(form!.title).toMatch(/\(signed in\)$/);
    expect(findings.every((f) => f.checkId?.startsWith("crawl.auth."))).toBe(true);
    // Compliance and fix-difficulty resolve through the crawl.* mapping.
    expect(getComplianceRefs(form!.checkId).length).toBeGreaterThan(0);
    expect(getFixDifficulty(form!.checkId)).toBe("easy");
  });

  it("finds a problem on the start page itself, which the anonymous suite never saw", async () => {
    stubApp({ ...site, "/app": page('<img src="http://x.test/a.png">') });
    const crawl = await checkAuthenticatedCrawl("https://x.test/app", { type: "cookie", cookieValue: "sid=ok" });
    expect(buildAuthenticatedCrawlFindings(crawl).some((f) => f.checkId === "crawl.auth.mixed-content:/app")).toBe(true);
  });

  it("returns nothing for a crawl that did not run", () => {
    expect(buildAuthenticatedCrawlFindings(undefined)).toEqual([]);
    expect(buildAuthenticatedCrawlFindings({ status: "error", note: "x" })).toEqual([]);
  });
});

describe("checkAuthenticated with the signed-in crawl", () => {
  it("is not_applicable without a credential", async () => {
    expect((await checkAuthenticated("https://x.test/app", null)).status).toBe("not_applicable");
  });

  it("attaches the crawl and turns its findings into signed-in findings", async () => {
    stubApp({
      "/robots.txt": { body: "User-agent: *\nAllow: /" },
      "/app": page('<a href="/app/p">p</a>'),
      "/app/p": page('<form action="http://x.test/save"><input type="password"></form>'),
    });
    const result = await checkAuthenticated("https://x.test/app", { type: "cookie", cookieValue: "sid=ok" });
    expect(result.status).toBe("checked");
    const findings = buildAuthenticatedFindings(result);
    expect(findings.some((f) => f.checkId?.startsWith("crawl.auth.insecure-form:"))).toBe(true);
  });

  it("is an error when the page can't be fetched", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect((await checkAuthenticated("https://x.test/app", { type: "cookie", cookieValue: "c" })).status).toBe("error");
  });
});

describe("buildAuthenticatedFindings (header analysis on the signed-in page)", () => {
  it("reports missing headers, absent CSP, insecure session cookies and a CORS wildcard", async () => {
    stubApp(
      { "/robots.txt": { body: "User-agent: *\nDisallow: /" }, "/app": { body: "<html><title>T</title></html>", headers: { "set-cookie": "sid=1; Path=/", "access-control-allow-origin": "*" } } },
      { requireCookie: false }
    );
    const result = await checkAuthenticated("https://x.test/app", { type: "basic", username: "u", password: "p" });
    const ids = buildAuthenticatedFindings(result).map((f) => f.checkId);
    expect(ids).toEqual(expect.arrayContaining(["auth-check.missing-headers", "auth-check.csp-absent", "auth-check.session-cookie-insecure:sid", "auth-check.cors-wildcard"]));
  });

  it("reports nothing for a result that did not run", () => {
    expect(buildAuthenticatedFindings({ status: "not_applicable", note: "x" })).toEqual([]);
  });
});

describe("buildAuthenticatedFindings on a well-configured signed-in page", () => {
  it("has no header, cookie or CORS findings", async () => {
    stubApp(
      { "/robots.txt": { body: "User-agent: *\nDisallow: /" }, "/app": page("ok", { ...SECURE, "permissions-policy": "geolocation=()", "cross-origin-embedder-policy": "require-corp", "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin", "cache-control": "no-store", "set-cookie": "sid=1; Path=/; Secure; HttpOnly; SameSite=Strict" }) },
      { requireCookie: false }
    );
    const result = await checkAuthenticated("https://x.test/app", { type: "basic", username: "u", password: "p" });
    expect(buildAuthenticatedFindings(result).filter((f) => !f.checkId?.startsWith("crawl.auth."))).toEqual([]);
  });
});
