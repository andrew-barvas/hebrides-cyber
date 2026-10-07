import { describe, it, expect } from "vitest";
import { resolveToolConfig, EXTENDED_TOOL_NAMES, OFFENSIVE_ONLY_TOOLS } from "./scanProfiles";

describe("resolveToolConfig", () => {
  it("'full' enables every extended tool except the offensive-only suite", () => {
    const config = resolveToolConfig("full");
    for (const name of EXTENDED_TOOL_NAMES) {
      if (OFFENSIVE_ONLY_TOOLS.has(name)) {
        expect(config[name]).toBe(false);
      } else {
        expect(config[name]).toBe(true);
      }
    }
    expect(Object.keys(config).length).toBe(EXTENDED_TOOL_NAMES.length);
  });

  it("'offensive' (Tier A) enables every extended tool, including the offensive-only suite", () => {
    const config = resolveToolConfig("offensive");
    for (const name of EXTENDED_TOOL_NAMES) {
      expect(config[name]).toBe(true);
    }
    expect(Object.keys(config).length).toBe(EXTENDED_TOOL_NAMES.length);
  });

  it("offensive-only tools (brute-force / exploit) are off in every non-offensive profile", () => {
    for (const profile of ["safe", "full", "api", "cms", "osint"] as const) {
      const config = resolveToolConfig(profile);
      for (const name of OFFENSIVE_ONLY_TOOLS) {
        expect(config[name], `${name} must be off in ${profile}`).toBe(false);
      }
    }
  });

  it("'ai-pentest' enables every extended tool including cost-gated AI tools", () => {
    const config = resolveToolConfig("ai-pentest");
    for (const name of EXTENDED_TOOL_NAMES) {
      expect(config[name]).toBe(true);
    }
    expect(Object.keys(config).length).toBe(EXTENDED_TOOL_NAMES.length);
  });

  it("'safe' disables every extended tool", () => {
    const config = resolveToolConfig("safe");
    for (const name of EXTENDED_TOOL_NAMES) {
      expect(config[name]).toBe(false);
    }
  });

  it("always returns every tool name as a key, even for a narrow profile", () => {
    const config = resolveToolConfig("api");
    expect(Object.keys(config).sort()).toEqual([...EXTENDED_TOOL_NAMES].sort());
  });

  it("'api' enables only its declared subset", () => {
    const config = resolveToolConfig("api");
    expect(config.nuclei).toBe(true);
    expect(config.zap).toBe(true);
    expect(config.sqlmap).toBe(true);
    expect(config.commix).toBe(true);
    expect(config.authCheck).toBe(true);
    expect(config.nmap).toBe(false);
    expect(config.secretScan).toBe(false);
    expect(config.trivyImage).toBe(false);
  });

  it("'cms' enables only its declared subset", () => {
    const config = resolveToolConfig("cms");
    expect(config.nuclei).toBe(true);
    expect(config.zap).toBe(true);
    expect(config.authCheck).toBe(true);
    expect(config.sqlmap).toBe(false);
    expect(config.nmap).toBe(false);
  });

  it("'osint' enables only passive/discovery tools, no active exploitation", () => {
    const config = resolveToolConfig("osint");
    expect(config.subdomains).toBe(true);
    expect(config.deepTls).toBe(true);
    expect(config.secretScan).toBe(true);
    expect(config.trivyImage).toBe(true);
    expect(config.trivyConfig).toBe(true);
    expect(config.sqlmap).toBe(false);
    expect(config.commix).toBe(false);
    expect(config.zap).toBe(false);
  });

  it("bundleOverrides win over the base profile's own tool list", () => {
    expect(resolveToolConfig("safe", { nuclei: true }).nuclei).toBe(true);
    expect(resolveToolConfig("full", { sqlmap: false }).sqlmap).toBe(false);
  });

  it("bundleOverrides leave unrelated tools at the base profile's setting", () => {
    const config = resolveToolConfig("api", { nmap: true });
    expect(config.nmap).toBe(true);
    expect(config.sqlmap).toBe(true); // still true from the "api" profile itself
    expect(config.secretScan).toBe(false); // untouched
  });
});
