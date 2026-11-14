import { describe, it, expect } from "vitest";
import { safeNextPath } from "./safeRedirect";

describe("safeNextPath", () => {
  it("keeps a path on this site, with its query", () => {
    expect(safeNextPath("/pricing?checkout=pro")).toBe("/pricing?checkout=pro");
    expect(safeNextPath("/dashboard/scans/abc")).toBe("/dashboard/scans/abc");
  });

  it("falls back for anything that could leave the site", () => {
    for (const bad of ["@evil.example", "//evil.example", "/\\evil.example", "https://evil.example", "evil.example", "/ /x", "/\t/evil.example", "/x\\y", "", null, undefined, `/${"a".repeat(600)}`]) {
      expect(safeNextPath(bad as string | null | undefined), String(bad)).toBe("/dashboard");
    }
  });

  it("uses the given fallback", () => {
    expect(safeNextPath("//evil", "/")).toBe("/");
  });
});
