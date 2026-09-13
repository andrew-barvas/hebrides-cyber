import { describe, it, expect } from "vitest";
import { computeCriticalPaths } from "./attackPathAnalysis";
import type { Finding } from "./scanners";

function finding(checkId: string, overrides: Partial<Finding> = {}): Finding {
  return { severity: "medium", title: checkId, detail: "", checkId, ...overrides };
}

describe("computeCriticalPaths", () => {
  it("returns nothing when findings don't satisfy any rule's full combination", () => {
    expect(computeCriticalPaths([finding("tls.no-https")])).toEqual([]);
  });

  it("returns nothing for an empty findings list", () => {
    expect(computeCriticalPaths([])).toEqual([]);
  });

  it("fires the .git-exposure chain when an exposed .git directory pairs with any secretScan finding", () => {
    const findings = [finding("exposure.exposed-file:.git"), finding("secretScan.exposed-secret:abc123")];
    const paths = computeCriticalPaths(findings);
    expect(paths).toHaveLength(1);
    expect(paths[0].title).toContain("Exposed .git directory");
    expect(paths[0].severity).toBe("critical");
    expect(paths[0].findingCheckIds.sort()).toEqual(["exposure.exposed-file:.git", "secretScan.exposed-secret:abc123"].sort());
  });

  it("does not fire a chain when only one of its two requirements is present", () => {
    expect(computeCriticalPaths([finding("exposure.exposed-file:.git")])).toEqual([]);
    expect(computeCriticalPaths([finding("secretScan.exposed-secret:abc")])).toEqual([]);
  });

  it("the '.*' module-wildcard requirement matches any check within that module, not just one specific check name", () => {
    // secretScan.* should match a different secretScan sub-check just as
    // well as secretScan.exposed-secret — verifies the wildcard isn't
    // accidentally an exact-string match in disguise.
    const findings = [finding("exposure.exposed-file:.git"), finding("secretScan.some-other-check:xyz")];
    expect(computeCriticalPaths(findings)).toHaveLength(1);
  });

  it("fires multiple independent chains at once when their findings are all present", () => {
    const findings = [
      finding("exposure.exposed-file:.git"),
      finding("secretScan.exposed-secret:abc"),
      finding("sqlmap.sqli:id"),
      finding("nmap.dangerous-port:6379"),
    ];
    const paths = computeCriticalPaths(findings);
    expect(paths).toHaveLength(2);
  });

  it("ignores a finding with no checkId when matching requirements", () => {
    const findings = [finding("exposure.exposed-file:.git"), { severity: "high", title: "no checkid", detail: "" } as Finding];
    expect(computeCriticalPaths(findings)).toEqual([]);
  });

  it("deduplicates findingCheckIds when the same finding could satisfy a requirement more than once", () => {
    const findings = [finding("exposure.exposed-file:.git"), finding("secretScan.exposed-secret:abc"), finding("secretScan.exposed-secret:def")];
    const paths = computeCriticalPaths(findings);
    expect(paths[0].findingCheckIds).toHaveLength(3); // .git + 2 distinct secretScan findings, no duplicates
  });
});
