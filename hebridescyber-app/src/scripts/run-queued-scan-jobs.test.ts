import { describe, it, expect } from "vitest";
import { decideScanConfig } from "./run-queued-scan-jobs";
import { enablesOffensiveTools } from "../lib/scanProfiles";

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

// The queue worker gates offensive tools on enablesOffensiveTools(profile,
// toolOverrides) applied to whatever decideScanConfig() resolved. These cases
// walk the real path a stored value takes — monitored_targets.scan_profile,
// which MonitoredTargets.tsx writes straight from the browser under RLS with
// no server-side validation — through to the gate's answer.
describe("decideScanConfig + the offensive-tools gate", () => {
  it("a target storing 'ai-pentest' resolves to a config that must be gated", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: null },
      { scan_profile: "ai-pentest", scan_bundle_id: null },
      null
    );
    expect(config).toEqual({ profile: "ai-pentest" });
    // Regression: the gate compared profile === "offensive" and let this run
    // with no Tier A check, no authorization row and no audit event.
    expect(enablesOffensiveTools(config.profile, config.toolOverrides)).toBe(true);
  });

  it("a target storing 'offensive' is still gated", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: null },
      { scan_profile: "offensive", scan_bundle_id: null },
      null
    );
    expect(enablesOffensiveTools(config.profile, config.toolOverrides)).toBe(true);
  });

  it("a bundle that overrides an offensive tool onto a tame base profile is gated", () => {
    const config = decideScanConfig(
      { scan_id: null, scan_profile: null },
      { scan_profile: "full", scan_bundle_id: "bundle-1" },
      { base_profile: "full", tool_overrides: { contentDiscovery: true } }
    );
    expect(enablesOffensiveTools(config.profile, config.toolOverrides)).toBe(true);
  });

  it("an on-demand job is never gated, since it always resolves to 'safe'", () => {
    const config = decideScanConfig(
      { scan_id: "scan-1", scan_profile: null },
      { scan_profile: "ai-pentest", scan_bundle_id: null },
      null
    );
    expect(config).toEqual({ profile: "safe" });
    expect(enablesOffensiveTools(config.profile, config.toolOverrides)).toBe(false);
  });

  it("the ordinary scheduled profiles are not gated", () => {
    for (const profile of ["safe", "full", "api", "cms", "osint"] as const) {
      const config = decideScanConfig(
        { scan_id: null, scan_profile: null },
        { scan_profile: profile, scan_bundle_id: null },
        null
      );
      expect(enablesOffensiveTools(config.profile, config.toolOverrides), profile).toBe(false);
    }
  });
});
