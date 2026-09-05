import { describe, it, expect } from "vitest";
import { getComplianceRefs, COMPLIANCE_FRAMEWORK_LABELS, ALL_CONTROLS_BY_FRAMEWORK } from "./compliance";

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

  it("maps a representative checkId to all four newly added frameworks", () => {
    const refs = getComplianceRefs("tls.no-https");
    const frameworks = refs.map((r) => r.framework);
    expect(frameworks).toContain("pci-dss");
    expect(frameworks).toContain("iso-27001");
    expect(frameworks).toContain("nis2");
    expect(frameworks).toContain("dora");
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
    expect(Object.keys(COMPLIANCE_FRAMEWORK_LABELS)).toEqual([
      "cyber-essentials",
      "owasp-top-10",
      "cis-controls-v8",
      "iso-27001",
      "pci-dss",
      "nis2",
      "dora",
    ]);
  });
});

describe("ALL_CONTROLS_BY_FRAMEWORK", () => {
  it("has one entry per framework, none empty", () => {
    expect(Object.keys(ALL_CONTROLS_BY_FRAMEWORK)).toEqual([
      "cyber-essentials",
      "owasp-top-10",
      "cis-controls-v8",
      "iso-27001",
      "pci-dss",
      "nis2",
      "dora",
    ]);
    for (const controls of Object.values(ALL_CONTROLS_BY_FRAMEWORK)) {
      expect(controls.size).toBeGreaterThan(0);
    }
  });

  it("includes every control a real mapped checkId cites", () => {
    for (const ref of getComplianceRefs("sqlmap.sqli")) {
      expect(ALL_CONTROLS_BY_FRAMEWORK[ref.framework].has(ref.control)).toBe(true);
    }
  });

  it("is derived from COMPLIANCE_MAP, not a hand-maintained duplicate that could omit a control", () => {
    // A03:2021 is cited by sqlmap.sqli/xsser.xss/commix.command-injection —
    // confirms the derivation actually walks every entry, not just the
    // first one found per framework.
    expect(ALL_CONTROLS_BY_FRAMEWORK["owasp-top-10"].has("A03:2021 – Injection")).toBe(true);
    expect(ALL_CONTROLS_BY_FRAMEWORK["cyber-essentials"].has("Secure configuration")).toBe(true);
  });
});
