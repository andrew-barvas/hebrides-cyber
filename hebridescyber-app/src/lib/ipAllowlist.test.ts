import { describe, it, expect } from "vitest";
import { parseCidr, isIpInCidr, isIpAllowed, validateAllowlistEntry } from "./ipAllowlist";

describe("parseCidr", () => {
  it("parses a single IP as /32", () => {
    const result = parseCidr("10.0.0.1");
    expect(result).not.toBeNull();
    expect(result!.mask).toBe(0xffffffff);
  });

  it("parses /24", () => {
    const result = parseCidr("192.168.1.0/24");
    expect(result).not.toBeNull();
    expect(result!.mask).toBe(0xffffff00);
  });

  it("rejects invalid input", () => {
    expect(parseCidr("not-an-ip")).toBeNull();
    expect(parseCidr("10.0.0.1/33")).toBeNull();
    expect(parseCidr("256.0.0.1")).toBeNull();
  });
});

describe("isIpInCidr", () => {
  it("matches exact IP", () => {
    expect(isIpInCidr("10.0.0.1", "10.0.0.1")).toBe(true);
    expect(isIpInCidr("10.0.0.2", "10.0.0.1")).toBe(false);
  });

  it("matches within /24 range", () => {
    expect(isIpInCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(isIpInCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
  });

  it("matches within /16 range", () => {
    expect(isIpInCidr("10.1.255.255", "10.1.0.0/16")).toBe(true);
    expect(isIpInCidr("10.2.0.1", "10.1.0.0/16")).toBe(false);
  });

  it("handles /0 (match all)", () => {
    expect(isIpInCidr("8.8.8.8", "0.0.0.0/0")).toBe(true);
  });
});

describe("isIpAllowed", () => {
  it("allows all when allowlist is empty", () => {
    expect(isIpAllowed("1.2.3.4", [])).toBe(true);
  });

  it("allows matching IPs", () => {
    const list = [{ cidr: "10.0.0.0/8" }, { cidr: "192.168.1.50" }];
    expect(isIpAllowed("10.5.5.5", list)).toBe(true);
    expect(isIpAllowed("192.168.1.50", list)).toBe(true);
  });

  it("blocks non-matching IPs", () => {
    const list = [{ cidr: "10.0.0.0/8" }];
    expect(isIpAllowed("172.16.0.1", list)).toBe(false);
  });
});

describe("validateAllowlistEntry", () => {
  it("validates correct CIDR", () => {
    expect(validateAllowlistEntry("10.0.0.0/24")).toEqual({ valid: true });
  });

  it("rejects empty", () => {
    const r = validateAllowlistEntry("");
    expect(r.valid).toBe(false);
  });

  it("rejects garbage", () => {
    const r = validateAllowlistEntry("hello");
    expect(r.valid).toBe(false);
  });
});
