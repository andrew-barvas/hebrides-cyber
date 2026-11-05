import { describe, it, expect } from "vitest";
import { EXTENDED_TOOL_PREFIXES, isExtendedToolFinding } from "./extendedToolCheckIds";
import { canDetectFromResults } from "./findingLifecycle";

describe("isExtendedToolFinding", () => {
  it.each(EXTENDED_TOOL_PREFIXES)("returns true for a %s.* checkId", (prefix) => {
    expect(isExtendedToolFinding(`${prefix}.some-check:key`)).toBe(true);
  });

  it.each(["recon.subdomains-found", "headers.missing", "tls.expiring", "wpvdb.outdated-plugin"])(
    "returns false for the non-extended checkId %s",
    (checkId) => {
      expect(isExtendedToolFinding(checkId)).toBe(false);
    }
  );

  it("returns false for undefined without throwing", () => {
    expect(isExtendedToolFinding(undefined)).toBe(false);
  });

  it("returns false for an empty string", () => {
    expect(isExtendedToolFinding("")).toBe(false);
  });
});

describe("API-spec findings", () => {
  it("are extended only when the injection tool produced them", () => {
    expect(isExtendedToolFinding("api-spec.sqli:GET:/users:id")).toBe(true);
    expect(isExtendedToolFinding("api-spec.sqli-path:GET:/users/{id}:id")).toBe(true);
    expect(isExtendedToolFinding("api-spec.xss:POST:/search:q")).toBe(true);
    // The base suite's passive API-spec check shares the namespace.
    expect(isExtendedToolFinding("api-spec.auth-bypass:GET:/admin")).toBe(false);
    expect(isExtendedToolFinding("api-spec.excessive-data:/users")).toBe(false);
  });

  it("can't be resolved by a passive scan's diff", () => {
    const canDetect = canDetectFromResults({ tls: { status: "checked" } });
    expect(canDetect({ checkId: "api-spec.sqli:GET:/users:id" })).toBe(false);
    expect(canDetect({ checkId: "api-spec.auth-bypass:GET:/admin" })).toBe(true);
  });

  it("are resolved only by a scan whose apiSpecInjection completed", () => {
    const canDetect = canDetectFromResults({ extended: { apiSpecInjection: { status: "completed", findings: [] } } });
    expect(canDetect({ checkId: "api-spec.xss:POST:/search:q" })).toBe(true);
    const failed = canDetectFromResults({ extended: { apiSpecInjection: { status: "error", findings: [] } } });
    expect(failed({ checkId: "api-spec.xss:POST:/search:q" })).toBe(false);
  });
});

describe("signed-in crawl findings", () => {
  it("are extended-only (an on-demand scan can't re-verify them), unlike the anonymous crawl", () => {
    expect(isExtendedToolFinding("crawl.auth.mixed-content:/app")).toBe(true);
    expect(isExtendedToolFinding("crawl.mixed-content:/")).toBe(false);
  });
});
