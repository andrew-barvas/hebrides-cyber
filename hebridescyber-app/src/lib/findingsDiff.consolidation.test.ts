import { describe, it, expect } from "vitest";
import { diffFindings } from "./findingsDiff";
import type { Finding } from "./scanners";

function finding(checkId: string | undefined): Finding {
  return { severity: "medium", title: checkId ?? "untagged", detail: "detail", checkId };
}

// findingConsolidation.ts folds duplicates into a canonical finding and
// records their checkIds in corroboratedBy; a diff must treat those ids as
// still present.
describe("diffFindings with consolidated duplicates", () => {
  const canonical = (...folded: string[]): Finding => ({
    ...finding("tls.hsts-missing"),
    corroboratedBy: folded.map((checkId) => ({ tool: "ZAP", checkId, title: checkId })),
  });

  it("does not report an old duplicate as fixed when its issue now lives on the canonical", () => {
    const previous = [finding("tls.hsts-missing"), finding("zap.alert:HSTS")];
    const result = diffFindings([canonical("zap.alert:HSTS")], previous);
    expect(result.fixed).toEqual([]);
    expect(result.unchanged.map((x) => x.checkId)).toEqual(["tls.hsts-missing"]);
  });

  it("does not report a canonical as new when only its duplicate was reported before", () => {
    const result = diffFindings([canonical("zap.alert:HSTS")], [finding("zap.alert:HSTS")]);
    expect(result.added).toEqual([]);
    expect(result.unchanged).toHaveLength(1);
    expect(result.fixed).toEqual([]);
  });

  it("recognises a duplicate that reappears on its own after a consolidated scan", () => {
    const result = diffFindings([finding("zap.alert:HSTS")], [canonical("zap.alert:HSTS")]);
    expect(result.unchanged).toHaveLength(1);
    expect(result.added).toEqual([]);
    expect(result.fixed).toEqual([]);
  });

  it("still reports a consolidated finding as fixed when none of its ids remain", () => {
    const result = diffFindings([], [canonical("zap.alert:HSTS")]);
    expect(result.fixed.map((x) => x.checkId)).toEqual(["tls.hsts-missing"]);
  });

  it("keeps untagged findings reading as new and fixed", () => {
    const result = diffFindings([finding(undefined)], [finding(undefined)]);
    expect(result.added).toHaveLength(1);
    expect(result.fixed).toHaveLength(1);
  });
});
