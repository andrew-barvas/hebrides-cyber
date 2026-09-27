import { describe, it, expect } from "vitest";
import { MAX_ALLOWLIST_ENTRIES, isIpAllowed, normaliseIp, parseCidr, validateAllowlist } from "./ipAllowlist";

describe("normaliseIp", () => {
  it.each([
    ["203.0.113.7", "203.0.113.7"],
    [" 203.0.113.7 ", "203.0.113.7"],
    ["203.0.113.7:63546", "203.0.113.7"], // Azure's X-Forwarded-For format
    ["::ffff:203.0.113.7", "203.0.113.7"],
    ["2001:DB8::1", "2001:db8::1"],
    ["[2001:db8::1]:443", "2001:db8::1"],
    ["fe80::1%eth0", "fe80::1"],
  ])("%s → %s", (raw, expected) => {
    expect(normaliseIp(raw)).toBe(expected);
  });

  it.each(["", "unknown", "example.com", "203.0.113", "999.0.0.1"])("rejects %j", (raw) => {
    expect(normaliseIp(raw)).toBeNull();
  });
});

describe("parseCidr", () => {
  it("treats a bare address as a single host", () => {
    expect(parseCidr("203.0.113.7")).toEqual({ address: "203.0.113.7", prefix: 32, family: "ipv4" });
    expect(parseCidr("2001:db8::1")).toEqual({ address: "2001:db8::1", prefix: 128, family: "ipv6" });
  });

  it("parses ranges in both families", () => {
    expect(parseCidr("203.0.113.0/24")).toEqual({ address: "203.0.113.0", prefix: 24, family: "ipv4" });
    expect(parseCidr("2001:db8::/32")).toEqual({ address: "2001:db8::", prefix: 32, family: "ipv6" });
  });

  it.each(["not-an-ip", "203.0.113.0/33", "2001:db8::/129", "203.0.113.0/", "203.0.113.0/-1", "203.0.113.0/24/1", "256.0.0.1"])(
    "rejects %j",
    (cidr) => {
      expect(parseCidr(cidr)).toBeNull();
    }
  );
});

describe("validateAllowlist", () => {
  it("tidies, drops blanks and de-duplicates", () => {
    expect(validateAllowlist([" 203.0.113.7/32 ", "", "203.0.113.7", "2001:DB8::/48"])).toEqual({
      ok: true,
      cidrs: ["203.0.113.7", "2001:db8::/48"],
    });
  });

  it("names the bad entry", () => {
    const result = validateAllowlist(["203.0.113.7", "office"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('"office"');
  });

  // An allowlist of "everything" is no allowlist — say so rather than store a
  // setting that looks like protection.
  it.each(["0.0.0.0/0", "::/0"])("refuses %s", (cidr) => {
    expect(validateAllowlist([cidr]).ok).toBe(false);
  });

  it(`caps the list at ${MAX_ALLOWLIST_ENTRIES} entries`, () => {
    const many = Array.from({ length: MAX_ALLOWLIST_ENTRIES + 1 }, (_, i) => `198.51.100.${i}`);
    expect(validateAllowlist(many).ok).toBe(false);
    expect(validateAllowlist(many.slice(1)).ok).toBe(true);
  });
});

describe("isIpAllowed", () => {
  it("allows everything when the allowlist is empty", () => {
    expect(isIpAllowed("203.0.113.7", [])).toBe(true);
  });

  it("matches single hosts and ranges", () => {
    const list = ["198.51.100.0/24", "203.0.113.7"];
    expect(isIpAllowed("198.51.100.200", list)).toBe(true);
    expect(isIpAllowed("203.0.113.7", list)).toBe(true);
    expect(isIpAllowed("203.0.113.8", list)).toBe(false);
    expect(isIpAllowed("198.51.101.1", list)).toBe(false);
  });

  it("matches IPv6", () => {
    expect(isIpAllowed("2001:db8:1234::42", ["2001:db8::/32"])).toBe(true);
    expect(isIpAllowed("2001:db9::1", ["2001:db8::/32"])).toBe(false);
  });

  it("matches an address however the proxy formatted it", () => {
    expect(isIpAllowed("203.0.113.7:51234", ["203.0.113.0/24"])).toBe(true);
    expect(isIpAllowed("::ffff:203.0.113.7", ["203.0.113.0/24"])).toBe(true);
  });

  // This gates authentication: anything it can't read is a denial.
  it("fails closed on an unreadable caller address", () => {
    expect(isIpAllowed("unknown", ["203.0.113.0/24"])).toBe(false);
    expect(isIpAllowed("", ["203.0.113.0/24"])).toBe(false);
  });

  it("ignores a corrupt stored entry rather than widening access", () => {
    expect(isIpAllowed("203.0.113.7", ["garbage"])).toBe(false);
    expect(isIpAllowed("203.0.113.7", ["garbage", "203.0.113.7"])).toBe(true);
  });

  it("doesn't let an IPv4 entry match an unrelated IPv6 caller", () => {
    expect(isIpAllowed("2001:db8::1", ["203.0.113.0/24"])).toBe(false);
  });
});
