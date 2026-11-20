import { afterEach, describe, expect, it, vi } from "vitest";
import { checkWaybackDiscovery, waybackCheckId } from "./waybackDiscovery";
import { isCovered, scanCoverage } from "../findingLifecycle";

const ORIGIN = "https://www.example.com";
const HEADER = ["original", "statuscode", "mimetype"];
const SHELL = "<html><body><div id=root>Example app shell</div></body></html>";

type Route = (url: string, init?: RequestInit) => Response | Promise<Response>;

/**
 * Routes fetch by URL: the CDX query, the baseline's HEAD on "/" and its
 * random not-found slug, and each live probe. `live` maps a probed path to its
 * reply; anything not listed 404s.
 */
function stubSite(opts: { rows: unknown; live?: Record<string, Route>; catchAll?: boolean }) {
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith("https://web.archive.org/cdx/")) return new Response(JSON.stringify(opts.rows), { status: 200 });
    const path = new URL(url).pathname;
    if (path === "/" && init?.method === "HEAD") return new Response(null, { status: 200 });
    if (path.startsWith("/hc-probe-")) return opts.catchAll ? new Response(SHELL, { status: 200 }) : new Response("nope", { status: 404 });
    const route = opts.live?.[path];
    return route ? route(url, init) : new Response("nope", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const probedPaths = (fetchMock: ReturnType<typeof stubSite>) =>
  fetchMock.mock.calls
    .map(([u]) => String(u))
    .filter((u) => !u.startsWith("https://web.archive.org/") && !u.includes("/hc-probe-") && new URL(u).pathname !== "/")
    .map((u) => new URL(u).pathname);

describe("checkWaybackDiscovery: candidates", () => {
  it("drops static assets, code-like crawler noise, curated paths, bad URLs and duplicates", async () => {
    const fetchMock = stubSite({
      rows: [
        HEADER,
        [`${ORIGIN}/admin-old`, "200", "text/html"],
        [`${ORIGIN}/admin-old`, "200", "text/html"], // duplicate
        [`${ORIGIN}/logo.PNG`, "200", "image/png"], // static by extension
        [`${ORIGIN}/bundle`, "200", "application/javascript"], // static by exact mime
        [`${ORIGIN}/font-file`, "200", "font/woff2"], // static by mime prefix
        [`${ORIGIN}/!==l?v.zoom=1`, "200", "text/html"], // code-like
        [`${ORIGIN}/x'y`, "200", "text/html"], // a quote: misparsed markup
        [`${ORIGIN}/${"x".repeat(201)}`, "200", "text/html"], // too long
        [`${ORIGIN}/`, "200", "text/html"], // root
        [`${ORIGIN}/.env`, "200", "text/plain"], // already curated
        [`${ORIGIN}/.env/`, "200", "text/html"], // curated once the trailing slash is stripped
        ["not a url", "200", "text/html"],
        "not a row",
        [42, "200", "text/html"],
        [`${ORIGIN}/reports/2019`], // no mimetype column
      ],
    });
    const r = await checkWaybackDiscovery(`${ORIGIN}/somewhere`);
    expect(r).toMatchObject({ status: "checked", discovered: [], candidatesConsidered: 2, candidatesProbed: 2 });
    expect(probedPaths(fetchMock).sort()).toEqual(["/admin-old", "/reports/2019"]);
  });

  it("probes priority keywords first and caps the live probes at 40", async () => {
    const plain = Array.from({ length: 45 }, (_, i) => [`${ORIGIN}/page-${String(i).padStart(2, "0")}`, "200", "text/html"]);
    const fetchMock = stubSite({ rows: [HEADER, ...plain, [`${ORIGIN}/zz-debug`, "200", "text/html"]] });
    const r = await checkWaybackDiscovery(ORIGIN);
    expect(r).toMatchObject({ status: "checked", candidatesConsidered: 46, candidatesProbed: 40 });
    const probed = probedPaths(fetchMock);
    expect(probed).toHaveLength(40);
    // Sorted last alphabetically, but probed because "debug" is a priority keyword.
    expect(probed).toContain("/zz-debug");
    expect(probed).not.toContain("/page-44");
  });

  it("is checked without touching the site when every archived URL is filtered out", async () => {
    const fetchMock = stubSite({ rows: [HEADER, [`${ORIGIN}/style.css`, "200", "text/css"]] });
    expect(await checkWaybackDiscovery(ORIGIN)).toEqual({ status: "checked", discovered: [], candidatesConsidered: 0, candidatesProbed: 0 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("is an error only for a malformed target URL", async () => {
    expect(await checkWaybackDiscovery("not a url")).toEqual({ status: "error", note: "Invalid URL" });
  });

  it("is partial when the CDX reply is JSON but not an array", async () => {
    stubSite({ rows: { error: "busy" } });
    expect((await checkWaybackDiscovery(ORIGIN)).status).toBe("partial");
  });
});

describe("checkWaybackDiscovery: live probes", () => {
  it("reports a path that is live with its own content, scored low when its name suggests risk", async () => {
    stubSite({
      rows: [HEADER, [`${ORIGIN}/backup-2019`, "200", "text/html"], [`${ORIGIN}/team-page`, "200", "text/html"]],
      live: {
        "/backup-2019": () => new Response("Index of /backup-2019: site.tar", { status: 200 }),
        "/team-page": () => new Response("Meet the team", { status: 200 }),
      },
    });
    const r = await checkWaybackDiscovery(ORIGIN);
    if (r.status !== "checked") throw new Error("expected checked");
    const byPath = Object.fromEntries(r.discovered.map((f) => [f.path, f]));
    expect(byPath["/backup-2019"]).toMatchObject({ severity: "low", checkId: waybackCheckId("/backup-2019") });
    expect(byPath["/backup-2019"].hint).toContain("scored above informational");
    expect(byPath["/team-page"]).toMatchObject({ severity: "info" });
    expect(byPath["/team-page"].hint).not.toContain("scored above informational");
  });

  it("ignores redirects, errors, the site's catch-all shell and network failures", async () => {
    stubSite({
      catchAll: true,
      rows: [
        HEADER,
        [`${ORIGIN}/old-login`, "200", "text/html"],
        [`${ORIGIN}/old-api`, "200", "text/html"],
        [`${ORIGIN}/old-shell`, "200", "text/html"],
        [`${ORIGIN}/old-down`, "200", "text/html"],
        [`${ORIGIN}/old-unreadable`, "200", "text/html"],
      ],
      live: {
        "/old-login": () => new Response(null, { status: 302, headers: { location: "/" } }),
        "/old-api": () => new Response("err", { status: 500 }),
        "/old-shell": () => new Response(SHELL, { status: 200 }),
        "/old-down": () => Promise.reject(new Error("ECONNRESET")),
        "/old-unreadable": () => {
          const res = new Response("x", { status: 200 });
          vi.spyOn(res, "arrayBuffer").mockRejectedValue(new Error("aborted"));
          return res;
        },
      },
    });
    const r = await checkWaybackDiscovery(ORIGIN);
    expect(r).toMatchObject({ status: "checked", discovered: [], candidatesProbed: 5 });
  });

  it("treats a reply carrying the homepage's ETag as the same document", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.startsWith("https://web.archive.org/")) return new Response(JSON.stringify([HEADER, [`${ORIGIN}/legacy`, "200", "text/html"]]), { status: 200 });
      if (init?.method === "HEAD") return new Response(null, { status: 200, headers: { etag: '"home-v1"' } });
      if (url.includes("/hc-probe-")) return new Response("nope", { status: 404 });
      return new Response("Legacy page", { status: 200, headers: { etag: '"home-v1"' } });
    });
    vi.stubGlobal("fetch", fetchMock);
    expect(await checkWaybackDiscovery(ORIGIN)).toMatchObject({ status: "checked", discovered: [] });
  });

  it("reads a reply with no body as empty text", async () => {
    stubSite({
      rows: [HEADER, [`${ORIGIN}/empty-endpoint`, "200", "text/html"]],
      live: { "/empty-endpoint": () => new Response(null, { status: 200 }) },
    });
    const r = await checkWaybackDiscovery(ORIGIN);
    if (r.status !== "checked") throw new Error("expected checked");
    expect(r.discovered.map((f) => f.path)).toEqual(["/empty-endpoint"]);
  });
});

describe("waybackCheckId", () => {
  it("is stable per path and follows the module.check:key shape", () => {
    expect(waybackCheckId("/admin-old")).toBe(waybackCheckId("/admin-old"));
    expect(waybackCheckId("/admin-old")).not.toBe(waybackCheckId("/admin-new"));
    expect(waybackCheckId("/a b?c=d")).toMatch(/^wayback-discovery\.live-path:[0-9a-f]{16}$/);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkWaybackDiscovery when the archive can't be read (audit M3)", () => {
  it.each([
    ["a network failure", () => Promise.reject(new Error("ETIMEDOUT"))],
    ["an HTTP error", () => Promise.resolve(new Response("busy", { status: 503 }))],
    ["an unreadable body", () => Promise.resolve(new Response("<html>", { status: 200 }))],
  ])("is partial on %s, never a clean checked", async (_label, reply) => {
    vi.stubGlobal("fetch", vi.fn(reply));
    const r = await checkWaybackDiscovery("https://www.example.com");
    expect(r.status).toBe("partial");
  });

  it("is checked with nothing found when the archive is genuinely empty", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify([["original", "statuscode", "mimetype"]]), { status: 200 }))));
    expect(await checkWaybackDiscovery("https://www.example.com")).toMatchObject({ status: "checked", discovered: [] });
  });

  it("so last scan's wayback findings stay open instead of being marked fixed", () => {
    const coverage = scanCoverage(null, { waybackDiscovery: { status: "partial", note: "x", discovered: [] } });
    expect(isCovered("base", coverage, "wayback-discovery.live-path:/old-admin")).toBe(false);
    const ok = scanCoverage(null, { waybackDiscovery: { status: "checked", discovered: [] } });
    expect(isCovered("base", ok, "wayback-discovery.live-path:/old-admin")).toBe(true);
  });
});
