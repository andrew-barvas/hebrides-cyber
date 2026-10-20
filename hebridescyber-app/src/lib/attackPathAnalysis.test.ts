import { describe, it, expect } from "vitest";
import { computeCriticalPaths, computeChokepoints } from "./attackPathAnalysis";
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

  it("attaches ordered entry → pivot → impact steps whose matched checkIds union to findingCheckIds", () => {
    const findings = [finding("exposure.exposed-file:.git"), finding("secretScan.exposed-secret:abc")];
    const [path] = computeCriticalPaths(findings);
    expect(path.steps.map((s) => s.role)).toEqual(["entry", "pivot", "impact"]);
    // The impact stage is a consequence, not a finding — no checkIds.
    expect(path.steps[2].checkIds).toEqual([]);
    expect(path.steps[0].checkIds).toEqual(["exposure.exposed-file:.git"]);
    expect(path.steps[1].checkIds).toEqual(["secretScan.exposed-secret:abc"]);
    expect([...path.findingCheckIds].sort()).toEqual([...new Set(path.steps.flatMap((s) => s.checkIds))].sort());
  });

  it("fires the v2 subdomain-takeover → loose-cookie → account-takeover chain", () => {
    const findings = [finding("takeover.dangling-cname:old.example.com"), finding("headers.cookie-flags:session")];
    const [path] = computeCriticalPaths(findings);
    expect(path.severity).toBe("critical");
    expect(path.title).toContain("takeable subdomain");
    expect(path.steps[2].label).toContain("takeover");
  });

  it("fires the v2 service_role-key → open-table data-exfiltration chain", () => {
    const findings = [finding("backend-exposure.service-key:abcd"), finding("backend-exposure.open-table:abcd:users")];
    const [path] = computeCriticalPaths(findings);
    expect(path.severity).toBe("critical");
    expect(path.findingCheckIds).toContain("backend-exposure.service-key:abcd");
  });

  it("does not fire the service_role chain on the service-key finding alone", () => {
    expect(computeCriticalPaths([finding("backend-exposure.service-key:abcd")])).toEqual([]);
  });
});

describe("computeChokepoints", () => {
  it("returns nothing when there are no paths", () => {
    expect(computeChokepoints([])).toEqual([]);
  });

  it("ranks a finding that breaks more paths above one that breaks fewer", () => {
    // exposure.exposed-file:.git is a stage in BOTH the .git→secret chain and
    // the open-directory→exposed-file chain, so fixing it collapses two paths.
    const findings = [
      finding("exposure.exposed-file:.git"),
      finding("secretScan.exposed-secret:abc"),
      finding("directory-listing.open-directory:/uploads"),
    ];
    const paths = computeCriticalPaths(findings);
    expect(paths.length).toBeGreaterThanOrEqual(2);
    const chokepoints = computeChokepoints(paths);
    expect(chokepoints[0].checkId).toBe("exposure.exposed-file:.git");
    expect(chokepoints[0].pathCount).toBe(2);
    expect(chokepoints[0].pathTitles).toHaveLength(2);
    // It carries the highest severity among the paths it sits on (critical here).
    expect(chokepoints[0].severity).toBe("critical");
  });
});
