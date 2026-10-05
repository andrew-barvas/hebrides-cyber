import { describe, it, expect } from "vitest";
import { diffFindings } from "./findingsDiff";
import type { Finding } from "./scanners";

function finding(checkId: string | undefined, title = checkId ?? "untagged"): Finding {
  return { severity: "medium", title, detail: "detail", checkId };
}

describe("diffFindings", () => {
  it("marks a finding present in both scans as unchanged", () => {
    const current = [finding("tls.grade")];
    const previous = [finding("tls.grade")];

    const result = diffFindings(current, previous);

    expect(result.unchanged).toHaveLength(1);
    expect(result.unchanged[0].status).toBe("unchanged");
    expect(result.added).toHaveLength(0);
    expect(result.fixed).toHaveLength(0);
  });

  it("marks a finding only in the current scan as added", () => {
    const current = [finding("headers.missing-csp")];
    const previous: Finding[] = [];

    const result = diffFindings(current, previous);

    expect(result.added).toHaveLength(1);
    expect(result.added[0].status).toBe("new");
    expect(result.added[0].checkId).toBe("headers.missing-csp");
  });

  it("marks a finding only in the previous scan as fixed", () => {
    const current: Finding[] = [];
    const previous = [finding("exposure.env-file")];

    const result = diffFindings(current, previous);

    expect(result.fixed).toHaveLength(1);
    expect(result.fixed[0].status).toBe("fixed");
    expect(result.fixed[0].checkId).toBe("exposure.env-file");
  });

  it("keeps current text for an unchanged finding rather than the previous scan's text", () => {
    const current = [finding("tls.grade", "TLS grade: B (updated wording)")];
    const previous = [finding("tls.grade", "TLS grade: B")];

    const result = diffFindings(current, previous);

    expect(result.unchanged[0].title).toBe("TLS grade: B (updated wording)");
  });

  it("treats an untagged finding (no checkId) as always new, never matching anything", () => {
    const current = [finding(undefined, "legacy finding from before checkId existed")];
    const previous = [finding(undefined, "legacy finding from before checkId existed")];

    const result = diffFindings(current, previous);

    // Same title/detail, but with no checkId neither side can be matched to
    // the other — the conservative behaviour documented in the module
    // header. It should show as both added (from current) and fixed (from
    // previous), never as unchanged.
    expect(result.unchanged).toHaveLength(0);
    expect(result.added).toHaveLength(1);
    expect(result.fixed).toHaveLength(1);
  });

  it("handles two completely empty scans", () => {
    const result = diffFindings([], []);
    expect(result).toEqual({ added: [], fixed: [], unchanged: [] });
  });

  it("distinguishes multiple findings by checkId independently", () => {
    const current = [finding("a.check"), finding("b.check"), finding("c.check")];
    const previous = [finding("a.check"), finding("b.check"), finding("d.check")];

    const result = diffFindings(current, previous);

    expect(result.unchanged.map((f) => f.checkId)).toEqual(["a.check", "b.check"]);
    expect(result.added.map((f) => f.checkId)).toEqual(["c.check"]);
    expect(result.fixed.map((f) => f.checkId)).toEqual(["d.check"]);
  });
});

describe("diffFindings with canDetect", () => {
  const f = (checkId: string): Finding => ({ severity: "high", title: checkId, detail: "d", checkId });

  it("does not call a finding fixed when the current scan could not have seen it", () => {
    const previous = [f("sqlmap.sqli:id"), f("headers.hsts")];
    const diff = diffFindings([], previous, { canDetect: (x) => !x.checkId?.startsWith("sqlmap") });
    expect(diff.fixed.map((x) => x.checkId)).toEqual(["headers.hsts"]);
  });

  it("keeps the old behaviour without canDetect", () => {
    expect(diffFindings([], [f("a.b")]).fixed).toHaveLength(1);
  });
});
