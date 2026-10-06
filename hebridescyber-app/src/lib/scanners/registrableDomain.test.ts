import { describe, it, expect } from "vitest";
import { isWithinDomain, ownerDomain, registrableDomain } from "./registrableDomain";

describe("registrableDomain (registry level, ICANN suffixes)", () => {
  it.each([
    ["example.com", "example.com"],
    ["www.example.com", "example.com"],
    ["a.b.example.com", "example.com"],
    ["shop.example.co.uk", "example.co.uk"],
    ["example.co.uk", "example.co.uk"],
    ["Example.COM.", "example.com"],
    ["council.gov.uk", "council.gov.uk"],
    ["x.y.example.com.au", "example.com.au"],
    // The hand-picked list got these wrong.
    ["www.stmarys.herts.sch.uk", "stmarys.herts.sch.uk"], // not the county's herts.sch.uk
    ["shop.example.co.ke", "example.co.ke"], // not the registry's co.ke
    ["www.example.org.ng", "example.org.ng"],
    // A platform's shared domain is what's registered.
    ["mysite.github.io", "github.io"],
  ])("%s → %s", (host, expected) => {
    expect(registrableDomain(host)).toBe(expected);
  });

  it.each(["localhost", "co.uk", "herts.sch.uk", "192.0.2.1", "::1", "[::1]", "a..b.com", "", "  "])("has no registrable domain for %j", (host) => {
    expect(registrableDomain(host)).toBeNull();
  });
});

describe("ownerDomain (what one customer controls, private suffixes included)", () => {
  it.each([
    ["www.example.co.uk", "example.co.uk"],
    ["www.stmarys.herts.sch.uk", "stmarys.herts.sch.uk"],
    ["mysite.github.io", "mysite.github.io"],
    ["docs.mysite.github.io", "mysite.github.io"],
    ["app.azurewebsites.net", "app.azurewebsites.net"],
    ["shop.myshopify.com", "shop.myshopify.com"],
  ])("%s → %s", (host, expected) => {
    expect(ownerDomain(host)).toBe(expected);
  });

  it.each(["github.io", "localhost", "203.0.113.7"])("has none for %s", (host) => {
    expect(ownerDomain(host)).toBeNull();
  });
});

describe("isWithinDomain", () => {
  it("matches the domain and its subdomains, not lookalikes", () => {
    expect(isWithinDomain("example.com", "example.com")).toBe(true);
    expect(isWithinDomain("api.Example.com.", "example.com")).toBe(true);
    expect(isWithinDomain("notexample.com", "example.com")).toBe(false);
    expect(isWithinDomain("example.com.evil.net", "example.com")).toBe(false);
  });
});
