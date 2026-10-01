import { describe, it, expect, vi, afterEach } from "vitest";
import { checkWebApp, isVersionBelow, type WebAppResult } from "./webapp";

afterEach(() => vi.unstubAllGlobals());

const NO_CMS = { isWordPress: false, isJoomla: false, isDrupal: false };
const ORIGIN = "https://example.com";

type Site = {
  page?: string;
  robots?: string;
  optionsHeaders?: Record<string, string>;
  notFound?: { body: string; type?: string };
  cors?: Record<string, string>;
  paths?: Record<string, { status?: number; body?: string; type?: string }>;
};

/** One fake site. Anything not described answers 404, including OSV lookups. */
function serve(site: Site) {
  const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
    const path = url.startsWith(ORIGIN) ? url.slice(ORIGIN.length) || "/" : url;
    const headers = new Headers(init.headers);
    if (init.method === "OPTIONS") return new Response(null, { status: 204, headers: site.optionsHeaders ?? {} });
    if (path === "/" || path === "/home") {
      if (headers.get("origin")) return new Response("", { headers: site.cors ?? {} });
      return new Response(site.page ?? "<html></html>", { headers: { "content-type": "text/html" } });
    }
    if (path === "/robots.txt" && site.robots !== undefined) return new Response(site.robots);
    const known = site.paths?.[path];
    if (known) return new Response(known.body ?? "", { status: known.status ?? 200, headers: { "content-type": known.type ?? "text/plain" } });
    if (path.startsWith("/hc-probe-") && site.notFound) {
      return new Response(site.notFound.body, { status: 404, headers: { "content-type": site.notFound.type ?? "text/html" } });
    }
    return new Response("Not found", { status: 404, headers: { "content-type": "text/html" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function scan(site: Site, cms = NO_CMS) {
  serve(site);
  const result = await checkWebApp(`${ORIGIN}/`, cms);
  if (result.status !== "checked") throw new Error(JSON.stringify(result));
  return result as Extract<WebAppResult, { status: "checked" }>;
}

describe("isVersionBelow", () => {
  it("compares to the patch level", () => {
    expect(isVersionBelow("4.17.15", "4.17.21")).toBe(true);
    expect(isVersionBelow("4.17.21", "4.17.21")).toBe(false);
    expect(isVersionBelow("3.5", "3.5.0")).toBe(false);
    expect(isVersionBelow("3.4", "3.5.0")).toBe(true);
    expect(isVersionBelow("10.0.0", "9.9.9")).toBe(false);
  });
});

describe("robots.txt", () => {
  it("collects disallowed paths, flags the interesting ones, and reads sitemaps", async () => {
    const { robots } = await scan({ robots: "User-agent: *\nDisallow: /admin/\nDisallow: /blog/drafts\nSitemap: https://example.com/sitemap.xml\n" });
    expect(robots).toEqual({
      accessible: true,
      interestingPaths: ["/admin/"],
      allDisallowed: ["/admin/", "/blog/drafts"],
      sitemapUrls: ["https://example.com/sitemap.xml"],
    });
  });

  it("reports an inaccessible robots.txt without failing the check", async () => {
    expect((await scan({})).robots?.accessible).toBe(false);
  });
});

describe("HTTP methods", () => {
  it("flags dangerous methods the server's Allow header lists", async () => {
    const { httpMethods } = await scan({ optionsHeaders: { allow: "GET, HEAD, PUT, DELETE, TRACE" } });
    expect(httpMethods.dangerousMethods).toEqual(["PUT", "DELETE", "TRACE"]);
  });

  // Regression: a CORS preflight default list was reported as "server allows PUT/DELETE".
  it("ignores Access-Control-Allow-Methods, which is CORS, not the server's methods", async () => {
    const { httpMethods } = await scan({ optionsHeaders: { "access-control-allow-methods": "GET, POST, PUT, DELETE, PATCH" } });
    expect(httpMethods).toEqual({ allowHeader: null, dangerousMethods: [] });
  });
});

describe("error page disclosure", () => {
  it("recognises a framework's own error page", async () => {
    const { errorDisclosure } = await scan({
      notFound: { body: "Traceback (most recent call last):\n  File \"/app/views.py\", line 12, in index" },
    });
    expect(errorDisclosure.disclosedStrings).toEqual(expect.arrayContaining(["Python stack trace", "Django debug traceback"]));
  });

  it("recognises a Laravel stack and a version-stamped nginx page", async () => {
    const laravel = await scan({ notFound: { body: "at Illuminate\\Routing\\Router->dispatch()" } });
    expect(laravel.errorDisclosure.disclosedStrings).toEqual(["Laravel debug page"]);
    const nginx = await scan({ notFound: { body: "<hr><center>nginx/1.18.0</center>" } });
    expect(nginx.errorDisclosure.disclosedStrings).toEqual(["Nginx version in error page"]);
  });

  // Regression: ordinary 404 copy matched the bare words "Whoops!", "ASP.NET" and "Laravel".
  it("does not flag a friendly 404 that merely names a framework", async () => {
    const { errorDisclosure } = await scan({
      notFound: { body: "<h1>Whoops! Page not found</h1><p>We build sites in Laravel and ASP.NET. Ask about ActiveRecord tuning.</p>" },
    });
    expect(errorDisclosure.disclosesFramework).toBe(false);
  });

  it("only inspects HTML or text responses", async () => {
    const { errorDisclosure } = await scan({ notFound: { body: '{"trace":"java.lang.NullPointerException"}', type: "application/json" } });
    expect(errorDisclosure).toEqual({ probed: true, disclosesFramework: false, disclosedStrings: [] });
  });
});

describe("CORS reflected origin", () => {
  it("reports reflection, and credentials only alongside it", async () => {
    const reflected = await scan({ cors: { "access-control-allow-origin": "https://evil.example.com", "access-control-allow-credentials": "true" } });
    expect(reflected.corsReflected).toMatchObject({ reflectsOrigin: true, credentialsAllowed: true });

    const wildcard = await scan({ cors: { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" } });
    expect(wildcard.corsReflected).toMatchObject({ reflectsOrigin: false, credentialsAllowed: false });
  });
});

describe("JS library versions", () => {
  const lib = async (page: string, name: string) => (await scan({ page })).jsLibraries.find((l) => l.name === name);

  it("flags a vulnerable version named in the filename, with CVEs from the reason as fallback", async () => {
    expect(await lib('<script src="/js/jquery-3.4.1.min.js"></script>', "jQuery")).toMatchObject({
      version: "3.4.1",
      isVulnerable: true,
      cveIds: ["CVE-2020-11022"],
    });
  });

  // Regression: the major.minor threshold passed versions inside the CVE range.
  it("flags patch releases below the fix", async () => {
    expect(await lib('<script src="/lodash-4.17.15.min.js"></script>', "Lodash")).toMatchObject({ isVulnerable: true });
    expect(await lib('<script src="/moment-2.29.1.min.js"></script>', "Moment.js")).toMatchObject({ isVulnerable: true });
    expect(await lib('<script src="/lodash-4.17.21.min.js"></script>', "Lodash")).toMatchObject({ isVulnerable: false });
  });

  // Regression: the CDN path carries the version; the filename alone didn't.
  it("reads the version from cdnjs, jsDelivr and unpkg paths", async () => {
    expect(await lib('<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>', "jQuery")).toMatchObject({
      version: "3.4.1",
      isVulnerable: true,
    });
    expect(await lib('<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>', "Bootstrap")).toMatchObject({
      version: "5.3.3",
      isVulnerable: false,
    });
    expect(await lib('<script src="https://unpkg.com/angular@1.8.3/angular.min.js"></script>', "AngularJS")).toMatchObject({
      version: "1.8.3",
      isVulnerable: true,
    });
  });

  it("reports a library with no readable version as informational", async () => {
    expect(await lib('<script src="/assets/moment.min.js"></script>', "Moment.js")).toMatchObject({ version: "unknown", isVulnerable: false });
  });

  it("does not mistake Angular 2+ packages for AngularJS", async () => {
    expect(await lib('<script src="https://cdn.jsdelivr.net/npm/@angular/core@17.0.0/fesm2022/core.mjs"></script>', "AngularJS")).toBeUndefined();
  });
});

describe("Subresource Integrity", () => {
  it("flags cross-origin scripts and stylesheets with no integrity attribute", async () => {
    const { unprotectedResources } = await scan({
      page: [
        '<script src="https://cdn.example.net/a.js"></script>',
        '<script src="https://cdn.example.net/b.js" integrity="sha384-abc" crossorigin="anonymous"></script>',
        '<script src="/local.js"></script>',
        "<script>inline()</script>",
        '<link href="https://fonts.example.net/f.css" rel="stylesheet">',
        '<link rel="stylesheet" href="/site.css">',
      ].join("\n"),
    });
    expect(unprotectedResources).toEqual([
      { kind: "script", url: "https://cdn.example.net/a.js" },
      { kind: "stylesheet", url: "https://fonts.example.net/f.css" },
    ]);
  });

  it("caps the list at 15", async () => {
    const page = Array.from({ length: 30 }, (_, i) => `<script src="https://cdn${i}.example.net/x.js"></script>`).join("");
    expect((await scan({ page })).unprotectedResources).toHaveLength(15);
  });
});

describe("CMS deep scans", () => {
  it("skips every CMS probe when nothing was fingerprinted", async () => {
    const result = await scan({});
    expect(result).toMatchObject({ wordpress: null, joomla: null, drupal: null });
  });

  it("WordPress: reads exposed users and real plugin readme versions", async () => {
    const { wordpress } = await scan(
      {
        paths: {
          "/xmlrpc.php": { body: "XML-RPC server accepts POST requests only." },
          "/wp-json/wp/v2/users": { body: JSON.stringify([{ name: "Site Admin", slug: "admin" }]), type: "application/json" },
          "/wp-content/plugins/elementor/readme.txt": { body: "=== Elementor ===\nStable tag: 3.5.0\n" },
          // A 200 with no Stable tag is not a plugin.
          "/wp-content/plugins/jetpack/readme.txt": { body: "<html>maintenance page</html>" },
        },
      },
      { ...NO_CMS, isWordPress: true }
    );
    expect(wordpress).toMatchObject({
      xmlRpcEnabled: true,
      userEnumerationPossible: true,
      enumeratedUsers: ["Site Admin"],
      debugLogAccessible: false,
      plugins: [{ slug: "elementor", name: "Elementor", version: "3.5.0" }],
    });
  });

  // A site that answers every path with its shell must not "have" every plugin.
  it("WordPress: a catch-all site reports no plugins", async () => {
    serve({});
    const shell = "<html><body>app shell</body></html>";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.endsWith("/wp-json/wp/v2/users") ? new Response("[]") : new Response(`${shell}\nStable tag: 1.0`, { status: 200, headers: { "content-type": "text/html" } })
      )
    );
    const result = await checkWebApp(`${ORIGIN}/`, { ...NO_CMS, isWordPress: true });
    expect(result.status === "checked" && result.wordpress?.plugins).toEqual([]);
  });

  it("Joomla: version from the manifest, and leftover install files", async () => {
    const { joomla } = await scan(
      {
        paths: {
          "/administrator/manifests/files/joomla.xml": { body: "<extension><version>3.9.27</version></extension>" },
          "/htaccess.txt": { body: "##\n# @package Joomla" },
        },
      },
      { ...NO_CMS, isJoomla: true }
    );
    expect(joomla).toEqual({ version: "3.9.27", installFilesPresent: true });
  });

  it("Drupal: version from CHANGELOG.txt and an exposed JSON:API", async () => {
    serve({});
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("/core/CHANGELOG.txt")) return new Response("Drupal 9.2.6, 2021-09-15\n");
        if (url.endsWith("/jsonapi")) return new Response("{}", { headers: { "content-type": "application/vnd.api+json" } });
        return new Response("Not found", { status: 404 });
      })
    );
    const result = await checkWebApp(`${ORIGIN}/`, { ...NO_CMS, isDrupal: true });
    expect(result.status === "checked" && result.drupal).toEqual({
      version: "9.2.6",
      updatePhpAccessible: false,
      jsonApiExposed: true,
      uid1ProfileAccessible: false,
    });
  });
});

describe("checkWebApp", () => {
  it("returns an error result for an unparseable URL", async () => {
    expect((await checkWebApp("not a url", NO_CMS)).status).toBe("error");
  });

  it("treats network failures as absence of evidence, not findings", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNRESET")));
    const result = await checkWebApp(`${ORIGIN}/`, NO_CMS);
    expect(result).toMatchObject({
      status: "checked",
      robots: null,
      httpMethods: { dangerousMethods: [] },
      errorDisclosure: { probed: false, disclosesFramework: false },
      corsReflected: { reflectsOrigin: false },
      jsLibraries: [],
      unprotectedResources: [],
    });
  });
});
