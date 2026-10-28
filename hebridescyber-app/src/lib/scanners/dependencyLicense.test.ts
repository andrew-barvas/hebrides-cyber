import { describe, it, expect } from "vitest";
import { isCopyleft, isUnknownLicense, buildLicenseFindings } from "./dependencyLicense";
import type { DependencyInventoryPackage } from "./dependencyManifest";

const pkg = (name: string, license?: string[], version = "1.0.0"): DependencyInventoryPackage => ({
  ecosystem: "npm",
  name,
  version,
  direct: true,
  fileIndex: 0,
  ...(license ? { license } : {}),
});

describe("isCopyleft", () => {
  it("flags GPL/AGPL/LGPL/SSPL variants, case-insensitively, with version suffixes", () => {
    expect(isCopyleft(["GPL-3.0-only"])).toBe(true);
    expect(isCopyleft(["AGPL-3.0-or-later"])).toBe(true);
    expect(isCopyleft(["lgpl-2.1"])).toBe(true);
    expect(isCopyleft(["SSPL-1.0"])).toBe(true);
  });
  it("does not flag permissive licences", () => {
    expect(isCopyleft(["MIT"])).toBe(false);
    expect(isCopyleft(["Apache-2.0", "BSD-3-Clause"])).toBe(false);
  });
});

describe("isUnknownLicense", () => {
  it("is true only when every entry is an unknown marker", () => {
    expect(isUnknownLicense(["non-standard"])).toBe(true);
    expect(isUnknownLicense(["NOASSERTION"])).toBe(true);
    expect(isUnknownLicense(["MIT"])).toBe(false);
    expect(isUnknownLicense(["non-standard", "MIT"])).toBe(false); // MIT is known
    expect(isUnknownLicense([])).toBe(false);
  });
});

describe("buildLicenseFindings", () => {
  it("emits a medium copyleft finding and an info unknown finding", () => {
    const findings = buildLicenseFindings([
      pkg("mysql-connector", ["GPL-2.0-only"]),
      pkg("mystery-lib", ["non-standard"]),
      pkg("lodash", ["MIT"]),
    ]);
    const ids = findings.map((f) => f.checkId);
    expect(ids).toContain("dependency-license.copyleft:mysql-connector");
    expect(ids).toContain("dependency-license.unknown:mystery-lib");
    expect(ids).not.toContain("dependency-license.copyleft:lodash");
    const copyleft = findings.find((f) => f.checkId === "dependency-license.copyleft:mysql-connector")!;
    expect(copyleft.severity).toBe("medium");
    expect(copyleft.title).toContain("GPL-2.0-only");
    expect(findings.find((f) => f.checkId === "dependency-license.unknown:mystery-lib")!.severity).toBe("info");
  });

  it("ignores packages with no licence data (a failed/absent deps.dev lookup is never a finding)", () => {
    expect(buildLicenseFindings([pkg("no-data"), pkg("empty", [])])).toEqual([]);
  });

  it("reports each package name once even across versions", () => {
    const findings = buildLicenseFindings([pkg("dup", ["GPL-3.0-only"], "1.0.0"), pkg("dup", ["GPL-3.0-only"], "2.0.0")]);
    expect(findings.filter((f) => f.checkId === "dependency-license.copyleft:dup")).toHaveLength(1);
  });
});
