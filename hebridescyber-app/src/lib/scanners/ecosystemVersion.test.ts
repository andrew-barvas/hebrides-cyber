import { describe, it, expect } from "vitest";
import { compareEcosystemVersions as cmp, isComparableVersion } from "./ecosystemVersion";

const sign = (n: number | null) => (n === null ? null : Math.sign(n));

describe("compareEcosystemVersions", () => {
  it("orders SemVer, prereleases below their release", () => {
    expect(sign(cmp("npm", "1.2.3", "1.10.0"))).toBe(-1);
    expect(sign(cmp("npm", "2.0.0-rc.1", "2.0.0"))).toBe(-1);
    expect(sign(cmp("npm", "1.0.0-alpha.1", "1.0.0-alpha.beta"))).toBe(-1);
    expect(sign(cmp("npm", "1.0.0-rc.2", "1.0.0-rc.10"))).toBe(-1);
    expect(sign(cmp("npm", "1.0.0+build.5", "1.0.0"))).toBe(0);
    expect(sign(cmp("Go", "v1.4.0", "1.4.0"))).toBe(0);
    expect(sign(cmp("Go", "0.0.0-20210101000000-abcdef123456", "0.1.0"))).toBe(-1);
    expect(sign(cmp("NuGet", "4.0.0.1", "4.0.0"))).toBe(1);
  });

  it("orders PEP 440 versions", () => {
    expect(sign(cmp("PyPI", "1.0.dev1", "1.0a1"))).toBe(-1);
    expect(sign(cmp("PyPI", "1.0a1", "1.0b1"))).toBe(-1);
    expect(sign(cmp("PyPI", "1.0rc1", "1.0"))).toBe(-1);
    expect(sign(cmp("PyPI", "1.0", "1.0.post1"))).toBe(-1);
    expect(sign(cmp("PyPI", "1.0.post1", "1.0.1"))).toBe(-1);
    expect(sign(cmp("PyPI", "1.0", "1.0.0"))).toBe(0);
    expect(sign(cmp("PyPI", "1!0.5", "2.0"))).toBe(1);
    expect(sign(cmp("PyPI", "2.0c1", "2.0rc1"))).toBe(0);
  });

  it("orders Maven qualifiers, unknown ones above the release", () => {
    expect(sign(cmp("Maven", "1.0-alpha-1", "1.0-beta-1"))).toBe(-1);
    expect(sign(cmp("Maven", "1.0-rc1", "1.0-SNAPSHOT"))).toBe(-1);
    expect(sign(cmp("Maven", "1.0-SNAPSHOT", "1.0"))).toBe(-1);
    expect(sign(cmp("Maven", "1.0.Final", "1.0"))).toBe(0);
    expect(sign(cmp("Maven", "1.0", "1.0-sp1"))).toBe(-1);
    expect(sign(cmp("Maven", "31.1-jre", "31.1"))).toBe(1);
    expect(sign(cmp("Maven", "31.1-jre", "32.0.0-android"))).toBe(-1);
  });

  it("orders RubyGems and Composer versions", () => {
    expect(sign(cmp("RubyGems", "1.2.3.pre", "1.2.3"))).toBe(-1);
    expect(sign(cmp("RubyGems", "1.2.3.beta1", "1.2.3.rc1"))).toBe(-1);
    expect(sign(cmp("Packagist", "v5.4.0", "5.4.0"))).toBe(0);
    expect(sign(cmp("Packagist", "1.0.0-RC1", "1.0.0"))).toBe(-1);
    expect(sign(cmp("Packagist", "1.0.0", "1.0.0-p1"))).toBe(-1);
  });

  it("returns null for versions it can't read", () => {
    expect(cmp("Packagist", "dev-main", "1.0.0")).toBeNull();
    expect(cmp("npm", "1.0.0", "latest")).toBeNull();
    expect(isComparableVersion("npm", "1.0.0")).toBe(true);
    expect(isComparableVersion("Go", "abcdef")).toBe(false);
  });
});
