import { describe, it, expect } from "vitest";
import { applyAttackRefs, attackUrl, getAttackRefs, getCweIds, ATTACK_MAPPED_CHECK_IDS, ATTACK_TECHNIQUE_IDS } from "./attackMap";
import { getComplianceRefs } from "./compliance";

describe("getAttackRefs", () => {
  it("returns [] for an undefined or unmapped checkId", () => {
    expect(getAttackRefs(undefined)).toEqual([]);
    expect(getAttackRefs("headers.csp-weak")).toEqual([]);
  });

  it("maps an exposed service to external remote services and public-facing application", () => {
    expect(getAttackRefs("network-exposure.open-port:3389").map((r) => r.id)).toEqual(["T1133", "T1190"]);
    expect(getAttackRefs("network-exposure.open-port:3389")[0]).toEqual({
      id: "T1133",
      name: "External Remote Services",
      url: "https://attack.mitre.org/techniques/T1133/",
    });
  });

  it("matches on the checkId base and folds signed-in and katana crawl copies into crawl.*", () => {
    expect(getAttackRefs("crawl.auth.cookie-flags:sid").map((r) => r.id)).toEqual(["T1539"]);
    expect(getAttackRefs("katana.mixed-content:https://x/a").map((r) => r.id)).toEqual(["T1557"]);
  });
});

describe("attackUrl", () => {
  it("puts a sub-technique under its parent's path", () => {
    expect(attackUrl("T1552.001")).toBe("https://attack.mitre.org/techniques/T1552/001/");
  });
});

describe("getCweIds", () => {
  it("returns the weakness ids for a mapped check and [] otherwise", () => {
    expect(getCweIds("sqlmap.sqli:id")).toEqual(["CWE-89"]);
    expect(getCweIds("dns.spf-missing")).toEqual([]);
    expect(getCweIds(undefined)).toEqual([]);
  });
});

describe("the table", () => {
  it("only maps real checks: every key is a checkId base compliance.ts also maps", () => {
    for (const id of ATTACK_MAPPED_CHECK_IDS) expect(getComplianceRefs(id).length, id).toBeGreaterThan(0);
  });

  it("names every technique it cites, with a well-formed id", () => {
    for (const id of ATTACK_TECHNIQUE_IDS) {
      expect(id).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(getAttackRefs(ATTACK_MAPPED_CHECK_IDS.find((c) => getAttackRefs(c).some((r) => r.id === id))).find((r) => r.id === id)?.name, id).toBeTruthy();
    }
  });

  it("uses well-formed CWE ids", () => {
    for (const id of ATTACK_MAPPED_CHECK_IDS) for (const cwe of getCweIds(id)) expect(cwe).toMatch(/^CWE-\d+$/);
  });
});

describe("applyAttackRefs", () => {
  it("adds refs to mapped findings and leaves unmapped ones without the fields", () => {
    const findings: Parameters<typeof applyAttackRefs>[0] = [{ checkId: "tls.no-https" }, { checkId: "meta.no-issues" }, {}];
    applyAttackRefs(findings);
    expect(findings[0].attackRefs?.map((r) => r.id)).toEqual(["T1557"]);
    expect(findings[0].cwe).toEqual(["CWE-319"]);
    expect(findings[1]).toEqual({ checkId: "meta.no-issues" });
    expect(findings[2]).toEqual({});
  });
});
