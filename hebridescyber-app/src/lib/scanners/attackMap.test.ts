import { describe, it, expect } from "vitest";
import { applyAttackRefs, attackUrl, getAttackRefs, getCweIds, getWhatToLog, ATTACK_MAPPED_CHECK_IDS, ATTACK_TECHNIQUE_IDS, NAMED_TECHNIQUE_IDS, WHAT_TO_LOG_TECHNIQUE_IDS } from "./attackMap";
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

describe("getWhatToLog", () => {
  it("has guidance written for every named technique, so a new one can't ship without it", () => {
    expect([...WHAT_TO_LOG_TECHNIQUE_IDS].sort()).toEqual([...NAMED_TECHNIQUE_IDS].sort());
  });

  it("names concrete logs for techniques used against the customer's systems", () => {
    expect(getWhatToLog("T1133").join(" ")).toMatch(/remote-access service/);
    expect(getWhatToLog("T1566").join(" ")).toMatch(/DMARC aggregate reports/);
    for (const id of ATTACK_TECHNIQUE_IDS.filter((t) => !/^T15(89|90|92)/.test(t))) expect(getWhatToLog(id).length, id).toBeGreaterThan(0);
  });

  it("gives nothing for reconnaissance, which happens outside the customer's systems, or an unknown id", () => {
    for (const id of ["T1589", "T1589.002", "T1590", "T1592", "T1592.002", "T9999"]) expect(getWhatToLog(id)).toEqual([]);
  });

  it("contains guidance only: no commands, queries or detection rules", () => {
    for (const id of WHAT_TO_LOG_TECHNIQUE_IDS) for (const line of getWhatToLog(id)) expect(line).not.toMatch(/[|`$]|index=|SELECT |EventID|sigma/i);
  });
});
