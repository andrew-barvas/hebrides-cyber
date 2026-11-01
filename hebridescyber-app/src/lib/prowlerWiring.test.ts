import { describe, it, expect } from "vitest";
import { EXTENDED_TOOL_NAMES, resolveToolConfig } from "./scanProfiles";
import { isExtendedToolFinding } from "./extendedToolCheckIds";
import { findingSource, isCovered, scanCoverage } from "./findingLifecycle";

describe("prowler wiring", () => {
  it("is an extended tool, on in full and offensive, off in safe", () => {
    expect(EXTENDED_TOOL_NAMES).toContain("prowler");
    expect(resolveToolConfig("full").prowler).toBe(true);
    expect(resolveToolConfig("offensive").prowler).toBe(true);
    expect(resolveToolConfig("safe").prowler).toBe(false);
  });

  it("recognises prowler.* as an extended-tool finding", () => {
    expect(isExtendedToolFinding("prowler.iam_root_mfa_enabled:1:x")).toBe(true);
  });

  it("only treats a prowler finding as covered when prowler completed", () => {
    const source = findingSource("prowler.iam_root_mfa_enabled:1:x", true, ["prowler"]);
    expect(source).toBe("prowler");
    expect(isCovered(source, scanCoverage({ prowler: { status: "completed" } }))).toBe(true);
    expect(isCovered(source, scanCoverage({ prowler: { status: "error" } }))).toBe(false);
    expect(isCovered(source, scanCoverage({ prowler: { status: "not_configured" } }))).toBe(false);
  });
});
