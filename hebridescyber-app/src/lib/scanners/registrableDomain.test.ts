import { describe, it, expect } from "vitest";
import { isWithinDomain, registrableDomain } from "./registrableDomain";

describe("registrableDomain", () => {
  it.each([
    ["example.com", "example.com"],
    ["www.example.com", "example.com"],
    ["a.b.example.com", "example.com"],
    ["shop.example.co.uk", "example.co.uk"],
    ["example.co.uk", "example.co.uk"],
    ["Example.COM.", "example.com"],
    ["council.gov.uk", "council.gov.uk"],
    ["x.y.example.com.au", "example.com.au"],
  ])("%s → %s", (host, expected) => {
    expect(registrableDomain(host)).toBe(expected);
  });

  it.each(["localhost", "co.uk", "192.0.2.1", "::1", "a..b.com", ""])("has no registrable domain for %j", (host) => {
    expect(registrableDomain(host)).toBeNull();
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
