import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { resolveCnameMock, resolve4Mock } = vi.hoisted(() => ({ resolveCnameMock: vi.fn(), resolve4Mock: vi.fn() }));

// Static factory — see dns.test.ts for why importOriginal doesn't intercept.
vi.mock("node:dns/promises", () => {
  const exports = { resolveCname: resolveCnameMock, resolve4: resolve4Mock };
  return { ...exports, default: exports };
});

import { MAX_HOSTS, candidateHosts, checkTakeover, matchProvider } from "./takeover";
import { registrableDomain } from "./registrableDomain";

const dnsError = (code: string) => Object.assign(new Error(code), { code });

/** name → CNAME targets; anything else has no CNAME. */
let cnames: Record<string, string[]>;
/** CNAME target → resolve4 outcome. */
let targets: Record<string, "exists" | "nxdomain" | "servfail">;
/** host → body served. */
let bodies: Record<string, string>;

beforeEach(() => {
  cnames = {};
  targets = {};
  bodies = {};
  resolveCnameMock.mockReset().mockImplementation(async (name: string) => {
    if (cnames[name]) return cnames[name];
    throw dnsError("ENODATA");
  });
  resolve4Mock.mockReset().mockImplementation(async (name: string) => {
    const outcome = targets[name] ?? "exists";
    if (outcome === "nxdomain") throw dnsError("ENOTFOUND");
    if (outcome === "servfail") throw dnsError("ESERVFAIL");
    return ["203.0.113.10"];
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const host = new URL(url).hostname;
      return new Response(bodies[host] ?? "<html>ordinary page</html>", { status: bodies[host] ? 404 : 200 });
    })
  );
});
afterEach(() => vi.unstubAllGlobals());

describe("registrableDomain", () => {
  it.each([
    ["www.example.com", "example.com"],
    ["shop.example.co.uk", "example.co.uk"],
    ["example.co.uk", "example.co.uk"],
    ["a.b.example.org.uk", "example.org.uk"],
    ["Example.COM.", "example.com"],
  ])("%s → %s", (host, domain) => {
    expect(registrableDomain(host)).toBe(domain);
  });

  it.each(["localhost", "co.uk", "203.0.113.7", "[::1]"])("has none for %s", (host) => {
    expect(registrableDomain(host)).toBeNull();
  });
});

describe("matchProvider", () => {
  it("recognises provider hostnames, including a trailing dot", () => {
    expect(matchProvider("oldapp.azurewebsites.net.")?.name).toBe("Azure App Service");
    expect(matchProvider("assets.s3.eu-west-2.amazonaws.com")?.name).toBe("Amazon S3");
    expect(matchProvider("acme.github.io")?.name).toBe("GitHub Pages");
    expect(matchProvider("cdn.example.net")).toBeNull();
  });
});

describe("candidateHosts", () => {
  it("keeps in-scope names, splits CT multi-name entries and drops wildcards", () => {
    expect(candidateHosts("www.example.co.uk", ["shop.example.co.uk\nblog.example.co.uk", "*.example.co.uk", "evil.com", "WWW.example.co.uk"])).toEqual([
      "blog.example.co.uk",
      "shop.example.co.uk",
      "www.example.co.uk",
    ]);
  });

  it("never takes in other sites on a shared hosting domain or a county's school zone", () => {
    expect(candidateHosts("mysite.github.io", ["docs.mysite.github.io", "someone-else.github.io"])).toEqual(["docs.mysite.github.io", "mysite.github.io"]);
    expect(candidateHosts("www.stmarys.herts.sch.uk", ["mail.stmarys.herts.sch.uk", "www.stjohns.herts.sch.uk"])).toEqual([
      "mail.stmarys.herts.sch.uk",
      "www.stmarys.herts.sch.uk",
    ]);
  });

  it(`caps the list at ${MAX_HOSTS}`, () => {
    const many = Array.from({ length: 100 }, (_, i) => `h${i}.example.com`);
    expect(candidateHosts("example.com", many)).toHaveLength(MAX_HOSTS);
  });
});

describe("checkTakeover", () => {
  it("reports a CNAME to a deleted Azure app (NXDOMAIN) as high confidence", async () => {
    cnames["old.example.com"] = ["oldapp.azurewebsites.net"];
    targets["oldapp.azurewebsites.net"] = "nxdomain";
    const result = await checkTakeover("https://www.example.com", ["old.example.com"]);
    expect(result).toEqual({
      status: "checked",
      hostsChecked: 2,
      dangling: [
        {
          host: "old.example.com",
          cname: "oldapp.azurewebsites.net",
          provider: "Azure App Service",
          confidence: "high",
          evidence: "oldapp.azurewebsites.net does not exist (NXDOMAIN)",
        },
      ],
    });
  });

  it("stays quiet when the Azure resource still exists", async () => {
    cnames["app.example.com"] = ["liveapp.azurewebsites.net"];
    const result = await checkTakeover("https://example.com", ["app.example.com"]);
    expect(result).toMatchObject({ dangling: [] });
  });

  // SERVFAIL/timeouts say nothing about whether the name is free.
  it("treats a resolver failure as unknown, not as NXDOMAIN", async () => {
    cnames["app.example.com"] = ["flaky.azurewebsites.net"];
    targets["flaky.azurewebsites.net"] = "servfail";
    expect(await checkTakeover("https://example.com", ["app.example.com"])).toMatchObject({ dangling: [] });
  });

  it("reports an unclaimed GitHub Pages site from GitHub's own page", async () => {
    cnames["docs.example.com"] = ["acme.github.io"];
    bodies["docs.example.com"] = "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>";
    const result = await checkTakeover("https://example.com", ["docs.example.com"]);
    expect(result).toMatchObject({ dangling: [{ host: "docs.example.com", provider: "GitHub Pages", confidence: "high" }] });
  });

  it("marks providers with extra verification as medium confidence", async () => {
    cnames["shop.example.com"] = ["acme.myshopify.com"];
    bodies["shop.example.com"] = "Sorry, this shop is currently unavailable.";
    expect(await checkTakeover("https://example.com", ["shop.example.com"])).toMatchObject({
      dangling: [{ provider: "Shopify", confidence: "medium" }],
    });
  });

  it("needs the provider's page, not just any error page", async () => {
    cnames["docs.example.com"] = ["acme.github.io"];
    bodies["docs.example.com"] = "<h1>404 Not Found</h1>";
    expect(await checkTakeover("https://example.com", ["docs.example.com"])).toMatchObject({ dangling: [] });
  });

  it("ignores CNAMEs to providers outside the list", async () => {
    cnames["cdn.example.com"] = ["edge.somecdn.example.net"];
    targets["edge.somecdn.example.net"] = "nxdomain";
    expect(await checkTakeover("https://example.com", ["cdn.example.com"])).toMatchObject({ dangling: [] });
  });

  it("is not applicable to a bare IP target", async () => {
    expect((await checkTakeover("https://203.0.113.7", [])).status).toBe("not_applicable");
  });
});
