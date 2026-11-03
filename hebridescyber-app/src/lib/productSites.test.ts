import { describe, it, expect } from "vitest";
import { isNoindexPath, mainSiteUrl, routeProductSite } from "./productSites";

describe("routeProductSite", () => {
  it("leaves the main site and unknown hosts alone", () => {
    expect(routeProductSite("www.hebridescyber.co.uk", "/")).toBeNull();
    expect(routeProductSite("hebridescyber.co.uk", "/lookout")).toBeNull();
    expect(routeProductSite("lookout.example.com", "/")).toBeNull();
    expect(routeProductSite(null, "/")).toBeNull();
  });

  it("serves each product's page at its subdomain root", () => {
    expect(routeProductSite("lookout.hebridescyber.co.uk", "/")).toEqual({ kind: "rewrite", pathname: "/lookout", indexable: true });
    expect(routeProductSite("exploit.hebridescyber.co.uk", "/")).toEqual({ kind: "rewrite", pathname: "/exploit", indexable: false });
  });

  it("ignores host case and port, and maps <product>.localhost for local testing", () => {
    expect(routeProductSite("Lookout.HebridesCyber.co.uk:443", "/")).toMatchObject({ pathname: "/lookout" });
    expect(routeProductSite("exploit.localhost:3000", "/")).toMatchObject({ pathname: "/exploit" });
  });

  it("redirects the product's own path to the clean root, keeping the query", () => {
    expect(routeProductSite("lookout.hebridescyber.co.uk", "/lookout", "?utm_source=x")).toEqual({ kind: "redirect", url: "/?utm_source=x" });
    expect(routeProductSite("lookout.hebridescyber.co.uk", "/lookout/")).toEqual({ kind: "redirect", url: "/" });
  });

  it("sends every other path to the main site, where sign-in and the platform live", () => {
    expect(routeProductSite("lookout.hebridescyber.co.uk", "/login", "?redirect=/dashboard")).toEqual({ kind: "redirect", url: mainSiteUrl("/login?redirect=/dashboard") });
    expect(routeProductSite("exploit.hebridescyber.co.uk", "/dashboard")).toEqual({ kind: "redirect", url: mainSiteUrl("/dashboard") });
    // A product host never serves another product's page.
    expect(routeProductSite("lookout.hebridescyber.co.uk", "/exploit")).toEqual({ kind: "redirect", url: mainSiteUrl("/exploit") });
  });
});

describe("isNoindexPath", () => {
  it("keeps Exploit out of search and leaves Lookout and the rest indexable", () => {
    expect(isNoindexPath("/exploit")).toBe(true);
    expect(isNoindexPath("/exploit/anything")).toBe(true);
    expect(isNoindexPath("/exploitable")).toBe(false);
    expect(isNoindexPath("/lookout")).toBe(false);
    expect(isNoindexPath("/")).toBe(false);
  });
});
