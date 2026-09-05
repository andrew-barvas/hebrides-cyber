import { describe, it, expect } from "vitest";
import { EXTENDED_TOOL_PREFIXES, isExtendedToolFinding } from "./extendedToolCheckIds";

describe("isExtendedToolFinding", () => {
  it.each(EXTENDED_TOOL_PREFIXES)("returns true for a %s.* checkId", (prefix) => {
    expect(isExtendedToolFinding(`${prefix}.some-check:key`)).toBe(true);
  });

  it.each(["recon.subdomains-found", "headers.missing", "tls.expiring", "wpscan.outdated-plugin"])(
    "returns false for the non-extended checkId %s",
    (checkId) => {
      expect(isExtendedToolFinding(checkId)).toBe(false);
    }
  );

  it("returns false for undefined without throwing", () => {
    expect(isExtendedToolFinding(undefined)).toBe(false);
  });

  it("returns false for an empty string", () => {
    expect(isExtendedToolFinding("")).toBe(false);
  });
});
