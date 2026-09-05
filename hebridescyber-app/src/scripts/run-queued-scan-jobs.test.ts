import { describe, it, expect } from "vitest";
import { decideScanConfig } from "./run-queued-scan-jobs";

describe("decideScanConfig", () => {
  it("an explicit per-job override wins outright, even over a target's own profile", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: "cms" },
      { scan_profile: "full", scan_bundle_id: null },
      null
    );
    expect(config).toEqual({ profile: "cms" });
  });

  it("an on-demand job (scan_id preset) always resolves to 'safe', regardless of the target's profile", () => {
    const config = decideScanConfig(
      { scan_id: "scan-1", scan_profile: null },
      { scan_profile: "full", scan_bundle_id: null },
      null
    );
    expect(config).toEqual({ profile: "safe" });
  });

  it("a scheduled job with no target row at all defaults to 'full' (matches today's unconditional-extended-tools behaviour)", () => {
    const config = decideScanConfig({ scan_id: null, scan_profile: null }, null, null);
    expect(config).toEqual({ profile: "full" });
  });

  it("a scheduled job inherits the target's plain scan_profile column when there's no bundle", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: null },
      { scan_profile: "osint", scan_bundle_id: null },
      null
    );
    expect(config).toEqual({ profile: "osint" });
  });

  it("a target's scan_bundle_id wins over its plain scan_profile column when the bundle row is found", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: null },
      { scan_profile: "full", scan_bundle_id: "bundle-1" },
      { base_profile: "api", tool_overrides: { nmap: true } }
    );
    expect(config).toEqual({ profile: "api", toolOverrides: { nmap: true } });
  });

  it("falls back to the target's plain scan_profile if scan_bundle_id is set but the bundle row wasn't found", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: null },
      { scan_profile: "cms", scan_bundle_id: "deleted-bundle" },
      null
    );
    expect(config).toEqual({ profile: "cms" });
  });
});
