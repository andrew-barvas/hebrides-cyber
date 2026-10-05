import { describe, it, expect } from "vitest";
import { consolidateFindings, corroboratingTools, EQUIVALENCES, findingCheckIds } from "./findingConsolidation";
import type { Finding } from "./scanners";

function f(checkId: string | undefined, overrides: Partial<Finding> = {}): Finding {
  return { severity: "medium", title: `title of ${checkId}`, detail: "detail", checkId, ...overrides };
}
const zap = (name: string, overrides: Partial<Finding> = {}) => f(`zap.alert:${name}`, { title: `[ZAP] ${name}`, ...overrides });
const nuclei = (id: string, overrides: Partial<Finding> = {}) => f(`nuclei.finding:${id}`, { title: `[Nuclei] ${id}`, ...overrides });
const testssl = (id: string, overrides: Partial<Finding> = {}) => f(`deep-tls.finding:${id}`, { title: `[testssl] ${id}`, ...overrides });

const HSTS_ZAP = "Strict-Transport-Security Header Not Set";

describe("equivalence table", () => {
  it("is non-trivial and every issue is reported by at least two sources", () => {
    expect(EQUIVALENCES.length).toBeGreaterThanOrEqual(10);
    for (const e of EQUIVALENCES) {
      const sources = [e.own, e.nuclei, e.zap, e.testssl].filter((s) => s && s.length > 0).length;
      // xcto-missing is the one issue whose own-side finding is an aggregate (headers.missing-critical).
      if (e.issue !== "xcto-missing") expect(sources, e.issue).toBeGreaterThanOrEqual(2);
    }
  });
});

describe("consolidateFindings", () => {
  it("folds a ZAP alert into our own check and keeps the canonical checkId", () => {
    const own = f("tls.hsts-missing", { severity: "medium" });
    const { findings, mergedCount } = consolidateFindings([own, zap(HSTS_ZAP, { severity: "low" })]);
    expect(mergedCount).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe("tls.hsts-missing");
    expect(findings[0].corroboratedBy).toEqual([{ tool: "ZAP", checkId: `zap.alert:${HSTS_ZAP}`, title: `[ZAP] ${HSTS_ZAP}` }]);
    expect(findings[0].severity).toBe("medium");
  });

  it("does not mutate its input", () => {
    const own = f("tls.hsts-missing");
    consolidateFindings([own, zap(HSTS_ZAP)]);
    expect(own.corroboratedBy).toBeUndefined();
  });

  it("takes the maximum severity of the group", () => {
    const { findings } = consolidateFindings([f("headers.csp-absent", { severity: "low" }), zap("Content Security Policy (CSP) Header Not Set", { severity: "high" })]);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].checkId).toBe("headers.csp-absent");
  });

  it("keeps the order of the surviving findings", () => {
    const { findings } = consolidateFindings([f("dns.spf-missing"), zap(HSTS_ZAP), f("tls.hsts-missing"), f("dns.dmarc-missing")]);
    expect(findings.map((x) => x.checkId)).toEqual(["dns.spf-missing", "tls.hsts-missing", "dns.dmarc-missing"]);
  });

  it("folds a path-specific nuclei template into the matching exposure finding only", () => {
    const { findings } = consolidateFindings([
      f("exposure.exposed-file:/.env", { severity: "critical" }),
      nuclei("dotenv-file", { severity: "high" }),
      nuclei("dotenv-file-2"),
    ]);
    expect(findings.map((x) => x.checkId)).toEqual(["exposure.exposed-file:/.env", "nuclei.finding:dotenv-file-2"]);
    expect(findings[0].corroboratedBy?.map((c) => c.tool)).toEqual(["nuclei"]);
  });

  it("does not fold it into a different exposed path", () => {
    const { findings } = consolidateFindings([f("exposure.exposed-file:/.env.local"), nuclei("dotenv-file")]);
    expect(findings).toHaveLength(2);
  });

  it("matches nuclei template ids case-insensitively", () => {
    const { findings } = consolidateFindings([f("tls.cert-expired"), nuclei("Expired-SSL")]);
    expect(findings).toHaveLength(1);
  });

  it("folds testssl legacy-protocol findings into tls.weak-protocol, but not SSLv3", () => {
    const { findings } = consolidateFindings([f("tls.weak-protocol", { severity: "high" }), testssl("TLS1"), testssl("TLS1_1"), testssl("SSLv3", { severity: "critical" })]);
    expect(findings.map((x) => x.checkId)).toEqual(["tls.weak-protocol", "deep-tls.finding:SSLv3"]);
    expect(findings[0].corroboratedBy).toHaveLength(2);
    expect(corroboratingTools(findings[0].corroboratedBy)).toEqual(["testssl"]);
  });

  it("does not merge two findings from the same tool, even with identical keys", () => {
    const { findings, mergedCount } = consolidateFindings([testssl("TLS1"), testssl("TLS1_1")]);
    expect(mergedCount).toBe(0);
    expect(findings).toHaveLength(2);
  });

  it("prefers the better evidence tier when the own check is absent", () => {
    const { findings } = consolidateFindings([nuclei("deprecated-tls"), testssl("TLS1")]);
    expect(findings.map((x) => x.checkId)).toEqual(["deep-tls.finding:TLS1"]);
    expect(findings[0].corroboratedBy?.[0].tool).toBe("nuclei");
  });

  it("chains: nuclei and testssl both fold into our own check", () => {
    const { findings } = consolidateFindings([nuclei("deprecated-tls"), testssl("TLS1_1"), f("tls.weak-protocol")]);
    expect(findings).toHaveLength(1);
    expect(findings[0].corroboratedBy?.map((c) => c.tool).sort()).toEqual(["nuclei", "testssl"]);
  });

  describe("aggregates", () => {
    const missingCritical = f("headers.missing-critical", {
      severity: "high",
      detail: "strict-transport-security, content-security-policy, x-content-type-options, some-unknown",
    });

    it("lets an aggregate absorb a single-header duplicate it lists", () => {
      const { findings } = consolidateFindings([missingCritical, zap("X-Content-Type-Options Header Missing")]);
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe("headers.missing-critical");
    });

    it("never absorbs a duplicate for a header the aggregate does not list", () => {
      const partial = f("headers.missing-critical", { detail: "content-security-policy" });
      const { findings } = consolidateFindings([partial, zap("X-Content-Type-Options Header Missing")]);
      expect(findings).toHaveLength(2);
    });

    it("prefers the most specific own finding over an aggregate", () => {
      const { findings } = consolidateFindings([missingCritical, f("tls.hsts-missing"), zap(HSTS_ZAP)]);
      expect(findings.map((x) => x.checkId)).toEqual(["headers.missing-critical", "tls.hsts-missing"]);
      expect(findings[1].corroboratedBy?.map((c) => c.tool)).toEqual(["ZAP"]);
      expect(findings[0].corroboratedBy).toBeUndefined();
    });

    it("never merges our own checks into one another", () => {
      const { findings, mergedCount } = consolidateFindings([missingCritical, f("tls.hsts-missing"), f("headers.csp-absent")]);
      expect(mergedCount).toBe(0);
      expect(findings).toHaveLength(3);
    });

    it("treats a tie between equally good canonicals as ambiguous and merges nothing", () => {
      const a = f("headers.missing-critical", { detail: "strict-transport-security" });
      const b = f("tls.hsts-missing");
      const { findings } = consolidateFindings([a, b, zap(HSTS_ZAP)]);
      expect(findings).toHaveLength(3);
    });
  });

  describe("CVE matching", () => {
    it("folds a nuclei CVE finding into a JS-library finding that lists every one of its CVEs", () => {
      const lib = f("webapp.vulnerable-js-lib:jquery", { cveIds: ["CVE-2020-11022", "CVE-2020-11023"] });
      const { findings } = consolidateFindings([lib, nuclei("jquery-xss", { cveIds: ["cve-2020-11022"] })]);
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe("webapp.vulnerable-js-lib:jquery");
      expect(findings[0].cveIds).toEqual(["CVE-2020-11022", "CVE-2020-11023"]);
    });

    it("carries over a CVE the canonical did not list yet", () => {
      const lib = f("webapp.vulnerable-js-lib:jquery", { cveIds: ["CVE-1-1"] });
      const { findings } = consolidateFindings([lib, nuclei("a", { cveIds: ["CVE-1-1"] }), nuclei("b", { cveIds: ["CVE-1-1"] })]);
      expect(findings[0].cveIds).toEqual(["CVE-1-1"]);
      const noCves = consolidateFindings([f("tls.hsts-missing"), zap(HSTS_ZAP)]).findings[0];
      expect(noCves.cveIds).toBeUndefined();
    });

    it("takes the higher severity from the folded CVE finding", () => {
      const lib = f("wpvdb.plugin-vulnerability:p:1", { cveIds: ["CVE-2024-1"] });
      const { findings } = consolidateFindings([lib, nuclei("x", { cveIds: ["CVE-2024-1"], severity: "critical" })]);
      expect(findings[0].severity).toBe("critical");
    });

    it("does not merge when the duplicate reports a CVE the canonical does not list", () => {
      const lib = f("webapp.vulnerable-js-lib:jquery", { cveIds: ["CVE-2020-11022"] });
      const { findings } = consolidateFindings([lib, nuclei("two", { cveIds: ["CVE-2020-11022", "CVE-2099-1"] })]);
      expect(findings).toHaveLength(2);
    });

    it("ignores CVEs on repo-side findings (not evidence about this target)", () => {
      const dep = f("dependency-manifest.npm:lodash", { cveIds: ["CVE-2021-23337"] });
      const { findings } = consolidateFindings([dep, nuclei("x", { cveIds: ["CVE-2021-23337"] })]);
      expect(findings).toHaveLength(2);
    });

    it("ignores CVEs on tools that are not CVE reporters", () => {
      const lib = f("webapp.vulnerable-js-lib:jquery", { cveIds: ["CVE-1-1"] });
      const { findings } = consolidateFindings([lib, zap("Vulnerable JS Library", { cveIds: ["CVE-1-1"] })]);
      expect(findings).toHaveLength(2);
    });
  });

  describe("left untouched", () => {
    it("a lone finding", () => {
      const only = f("tls.hsts-missing");
      expect(consolidateFindings([only]).findings[0]).toBe(only);
    });

    it("a duplicate with no canonical present", () => {
      const { findings } = consolidateFindings([zap(HSTS_ZAP)]);
      expect(findings).toHaveLength(1);
      expect(findings[0].corroboratedBy).toBeUndefined();
    });

    it("an unmapped ZAP alert, even with a near-identical title", () => {
      const own = f("tls.hsts-missing", { title: "HSTS header missing" });
      const { findings } = consolidateFindings([own, zap("HSTS header missing")]);
      expect(findings).toHaveLength(2);
    });

    it("findings without a checkId, both as duplicate and as canonical", () => {
      const { findings } = consolidateFindings([f(undefined), f(undefined, { title: "other" }), zap(HSTS_ZAP)]);
      expect(findings).toHaveLength(3);
    });

    it("a multi-header nuclei template (it cannot be tied to one issue)", () => {
      const { findings } = consolidateFindings([f("tls.hsts-missing"), nuclei("http-missing-security-headers")]);
      expect(findings).toHaveLength(2);
    });

    it("tools with no table entries (sqlmap, commix)", () => {
      const { findings } = consolidateFindings([f("sqlmap.sqli:id"), f("commix.command-injection:id"), zap("SQL Injection")]);
      expect(findings).toHaveLength(3);
    });

    it("a duplicate the customer has triaged", () => {
      const own = f("tls.hsts-missing");
      const dup = zap(HSTS_ZAP);
      const kept = consolidateFindings([own, dup], { isTriaged: (id) => id === dup.checkId });
      expect(kept.findings).toHaveLength(2);
      const folded = consolidateFindings([own, dup], { isTriaged: () => false });
      expect(folded.findings).toHaveLength(1);
    });
  });

  it("is idempotent and does not duplicate an existing corroboratedBy entry", () => {
    const first = consolidateFindings([f("tls.hsts-missing"), zap(HSTS_ZAP)]).findings;
    expect(consolidateFindings(first).findings).toEqual(first);

    const again = consolidateFindings([first[0], zap(HSTS_ZAP)]).findings;
    expect(again[0].corroboratedBy).toHaveLength(1);
  });

  it("treats an empty input as empty", () => {
    expect(consolidateFindings([])).toEqual({ findings: [], mergedCount: 0 });
  });
});

describe("helpers", () => {
  it("findingCheckIds lists the finding's own id then the folded ones", () => {
    expect(findingCheckIds({ checkId: "a", corroboratedBy: [{ checkId: "b" }, { checkId: "c" }] })).toEqual(["a", "b", "c"]);
    expect(findingCheckIds({})).toEqual([]);
    expect(findingCheckIds({ checkId: "a" })).toEqual(["a"]);
  });

  it("corroboratingTools is distinct and ordered, and tolerates absence", () => {
    expect(corroboratingTools([{ tool: "nuclei" }, { tool: "ZAP" }, { tool: "nuclei" }])).toEqual(["nuclei", "ZAP"]);
    expect(corroboratingTools(undefined)).toEqual([]);
  });
});
