import { describe, it, expect } from "vitest";
import { getFixDifficulty, estimateFixMinutes } from "./fixDifficulty";

describe("getFixDifficulty", () => {
  it("returns undefined for an undefined checkId", () => {
    expect(getFixDifficulty(undefined)).toBeUndefined();
  });

  it("returns undefined for a checkId with no mapping (deliberately not a forced guess)", () => {
    expect(getFixDifficulty("some-check-nobody-has-mapped-yet")).toBeUndefined();
  });

  it("returns the mapped difficulty for a directly-mapped checkId", () => {
    expect(getFixDifficulty("tls.hsts-missing")).toBe("trivial");
    expect(getFixDifficulty("sqlmap.sqli")).toBe("hard");
  });

  it("matches on the checkId's base, before the first colon", () => {
    expect(getFixDifficulty("dependency-manifest.npm:lodash")).toBe(getFixDifficulty("dependency-manifest.npm"));
  });

  it("only uses the part before the first colon even with multiple colons in the key", () => {
    expect(getFixDifficulty("dependency-manifest.npm:some:weird:key")).toBe(getFixDifficulty("dependency-manifest.npm"));
  });
});

describe("estimateFixMinutes", () => {
  it("returns the four fixed estimates, one per difficulty", () => {
    expect(estimateFixMinutes("trivial")).toBe(15);
    expect(estimateFixMinutes("easy")).toBe(60);
    expect(estimateFixMinutes("moderate")).toBe(240);
    expect(estimateFixMinutes("hard")).toBe(960);
  });

  it("increases monotonically with difficulty", () => {
    expect(estimateFixMinutes("trivial")).toBeLessThan(estimateFixMinutes("easy"));
    expect(estimateFixMinutes("easy")).toBeLessThan(estimateFixMinutes("moderate"));
    expect(estimateFixMinutes("moderate")).toBeLessThan(estimateFixMinutes("hard"));
  });
});
