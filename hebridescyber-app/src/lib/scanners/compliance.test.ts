import { describe, it, expect } from "vitest";
import { getComplianceRefs, COMPLIANCE_FRAMEWORK_LABELS } from "./compliance";

describe("getComplianceRefs", () => {
  it("returns an empty array for an undefined checkId", () => {
    expect(getComplianceRefs(undefined)).toEqual([]);
  });

  it("returns an empty array for a checkId with no mapping (deliberately uncategorised)", () => {
    expect(getComplianceRefs("some-check-nobody-has-mapped-yet")).toEqual([]);
  });

  it("returns real refs for a directly-mapped checkId", () => {
    const refs = getComplianceRefs("sqlmap.sqli");
    expect(refs.length).toBeGreaterThan(0);
    expect(refs).toContainEqual({ framework: "owasp-top-10", control: "A03:2021 – Injection" });
  });

  it("matches on the checkId's base, before the first colon", () => {
    const withoutKey = getComplianceRefs("sqlmap.sqli");
    const withKey = getComplianceRefs("sqlmap.sqli:id");
    expect(withKey).toEqual(withoutKey);
  });

  it("gives the two new extended-tool checks (xsser, commix) the same OWASP A03 mapping as sqlmap", () => {
    const sqlmapRefs = getComplianceRefs("sqlmap.sqli");
    expect(getComplianceRefs("xsser.xss")).toEqual(sqlmapRefs);
    expect(getComplianceRefs("commix.command-injection")).toEqual(sqlmapRefs);
  });

  it("only uses the part before the first colon even with multiple colons in the key", () => {
    // dependency-manifest.npm findings key on "<checkId>:<package-name>",
    // and package names can't contain a colon, but this guards the
    // indexOf(":")-based split logic itself against a multi-colon key.
    const refs = getComplianceRefs("dependency-manifest.npm:some:weird:key");
    expect(refs).toEqual(getComplianceRefs("dependency-manifest.npm"));
  });
});

describe("COMPLIANCE_FRAMEWORK_LABELS", () => {
  it("has a human-readable label for every framework getComplianceRefs can return", () => {
    const frameworks = new Set(getComplianceRefs("sqlmap.sqli").map((r) => r.framework));
    for (const framework of frameworks) {
      expect(COMPLIANCE_FRAMEWORK_LABELS[framework]).toBeTruthy();
    }
    expect(Object.keys(COMPLIANCE_FRAMEWORK_LABELS)).toEqual(["cyber-essentials", "owasp-top-10", "cis-controls-v8"]);
  });
});
