import { describe, it, expect, vi, afterEach } from "vitest";
import { checkExposure } from "./exposure";

afterEach(() => vi.unstubAllGlobals());

type Reply = { status?: number; body?: string; type?: string; headers?: Record<string, string> };

/**
 * Serves `routes` by exact path; everything else gets `fallback` — a real
 * 404 by default, or a catch-all shell to model an SPA/CMS that answers 200
 * for every URL (the case exposure.ts exists to avoid reporting).
 */
function serve(routes: Record<string, Reply>, fallback: Reply = { status: 404, body: "Not Found", type: "text/plain" }) {
  const fetchMock = vi.fn(async (url: string) => {
    const path = new URL(url).pathname;
    const r = routes[path] ?? fallback;
    return new Response(r.body ?? "", {
      status: r.status ?? 200,
      headers: { "content-type": r.type ?? "text/plain", ...(r.headers ?? {}) },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const SPA_SHELL = '<!doctype html><html><head><title>Shop</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>';

async function exposedPaths(targetUrl = "https://example.com") {
  const result = await checkExposure(targetUrl);
  if (result.status !== "checked") throw new Error(`expected checked, got ${JSON.stringify(result)}`);
  return result.exposed.map((f) => `${f.severity}:${f.path}`);
}

describe("checkExposure — real exposures", () => {
  it("reports a real .env file", async () => {
    serve({ "/.env": { body: "APP_ENV=production\nDB_PASSWORD=hunter2\n" } });
    expect(await exposedPaths()).toContain("critical:/.env");
  });

  it("reports an exposed git repository", async () => {
    serve({ "/.git/HEAD": { body: "ref: refs/heads/main\n" } });
    expect(await exposedPaths()).toContain("critical:/.git/HEAD");
  });

  it("reports a phpinfo page, which is legitimately HTML", async () => {
    serve({ "/phpinfo.php": { type: "text/html", body: "<html><h1>PHP Version 7.4.33</h1></html>" } });
    expect(await exposedPaths()).toContain("high:/phpinfo.php");
  });

  it("reports a SQL dump by its content", async () => {
    serve({ "/backup.sql": { body: "-- MySQL dump\nINSERT INTO users VALUES (1,'a');" } });
    expect(await exposedPaths()).toContain("critical:/backup.sql");
  });
});

// The whole point of the module: SPAs and CMSes answer 200 for every URL.
describe("checkExposure — evidence discipline", () => {
  it("reports nothing on an SPA that returns its HTML shell for every path", async () => {
    serve({}, { status: 200, type: "text/html", body: SPA_SHELL });
    expect(await exposedPaths()).toEqual([]);
  });

  it("reports nothing on a catch-all that returns the same plain-text body everywhere", async () => {
    serve({}, { status: 200, type: "text/plain", body: "Welcome to our site" });
    expect(await exposedPaths()).toEqual([]);
  });

  it("ignores a 200 /.env whose body isn't actually env-format", async () => {
    serve({ "/.env": { body: "nothing to see = here, just prose" } });
    expect(await exposedPaths()).not.toContain("critical:/.env");
  });

  it("ignores a .env path answered with HTML", async () => {
    serve({ "/.env": { type: "text/html", body: "<html>DB_PASSWORD=x</html>" } });
    expect(await exposedPaths()).not.toContain("critical:/.env");
  });

  it("treats a redirect as not exposed", async () => {
    serve({ "/.env": { status: 301, headers: { location: "/" } } });
    expect(await exposedPaths()).not.toContain("critical:/.env");
  });

  it("doesn't let a page that echoes the URL satisfy a content check", async () => {
    // A catch-all that prints the requested path: "/.git/HEAD" contains no
    // "ref:", but a shell echoing "ref:" from a query/path must not count.
    serve({}, { status: 200, type: "text/plain", body: "Page /PATH not found" });
    expect(await exposedPaths()).toEqual([]);
  });

  it("ignores a backup archive with the same ETag as the homepage", async () => {
    serve({
      "/": { headers: { etag: '"home-1"' } },
      "/backup.zip": { type: "application/zip", body: "PK...", headers: { etag: '"home-1"' } },
    });
    expect(await exposedPaths()).not.toContain("high:/backup.zip");
  });
});

describe("checkExposure — security.txt", () => {
  it("credits a real security.txt (has a Contact: field)", async () => {
    serve({ "/.well-known/security.txt": { body: "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n" } });
    const result = await checkExposure("https://example.com");
    expect(result).toMatchObject({ status: "checked", securityTxt: true });
  });

  // Regression: a present security.txt was also listed as an "exposed file",
  // with leaked-file remediation and compliance refs.
  it("never reports security.txt as an exposed file", async () => {
    serve({ "/.well-known/security.txt": { body: "Contact: mailto:security@example.com" } });
    const result = await checkExposure("https://example.com");
    expect(result.status === "checked" && result.exposed.map((f) => f.path)).toEqual([]);
  });

  it("does not credit a catch-all page as a security.txt", async () => {
    serve({}, { status: 200, type: "text/html", body: SPA_SHELL });
    expect(await checkExposure("https://example.com")).toMatchObject({ securityTxt: false });
  });
});

describe("checkExposure — failure handling", () => {
  it("treats network errors as no findings, not a failed scan", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNRESET")));
    expect(await checkExposure("https://example.com")).toEqual({ status: "checked", exposed: [], securityTxt: false });
  });

  it("returns an error result for an unparseable target", async () => {
    expect((await checkExposure("not a url")).status).toBe("error");
  });
});
