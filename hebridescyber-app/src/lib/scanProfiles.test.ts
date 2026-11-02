import { describe, it, expect, vi, afterEach } from "vitest";
import { resolveToolConfig, enablesOffensiveTools, isNonIntrusiveProfile, EXTENDED_TOOL_NAMES, OFFENSIVE_ONLY_TOOLS, EXCLUDED_FROM_FULL, EXPOSURE_TOOLS } from "./scanProfiles";
import { runZap } from "../worker/tools/zap";

describe("resolveToolConfig", () => {
  it("'full' enables every extended tool except the offensive-only suite and the tools excluded from full", () => {
    const config = resolveToolConfig("full");
    for (const name of EXTENDED_TOOL_NAMES) {
      if (OFFENSIVE_ONLY_TOOLS.has(name) || EXCLUDED_FROM_FULL.has(name)) {
        expect(config[name], `${name} must be off in full`).toBe(false);
      } else {
        expect(config[name], `${name} must be on in full`).toBe(true);
      }
    }
    expect(Object.keys(config).length).toBe(EXTENDED_TOOL_NAMES.length);
  });

  it("'full' keeps the verified tools and drops the unverified ones", () => {
    const config = resolveToolConfig("full");
    // Verified by real-binary integration tests, so they stay in the default profile.
    expect(config.nmap).toBe(true);
    expect(config.zap).toBe(true);
    expect(config.arjun).toBe(true);
    // Excluded from full until they can be verified against a hermetic target.
    expect(config.wpscan).toBe(false);
    expect(config.cmsmap).toBe(false);
    expect(config.photon).toBe(false);
  });

  it("'full' does not run the injection testers; 'api' and 'offensive' still do", () => {
    const full = resolveToolConfig("full");
    for (const name of ["sqlmap", "commix", "dalfox"] as const) {
      expect(full[name], `${name} must be off in full`).toBe(false);
      expect(EXCLUDED_FROM_FULL.has(name)).toBe(true);
      expect(resolveToolConfig("api")[name], `${name} must stay on in api`).toBe(true);
      expect(resolveToolConfig("offensive")[name], `${name} must stay on in offensive`).toBe(true);
    }
  });

  it("'offensive' (Tier A) enables every extended tool, including the offensive-only suite", () => {
    const config = resolveToolConfig("offensive");
    for (const name of EXTENDED_TOOL_NAMES) {
      expect(config[name]).toBe(true);
    }
    expect(Object.keys(config).length).toBe(EXTENDED_TOOL_NAMES.length);
  });

  it("offensive-only tools (brute-force / exploit) are off in every non-offensive profile", () => {
    for (const profile of ["safe", "full", "api", "cms", "osint", "exposure"] as const) {
      const config = resolveToolConfig(profile);
      for (const name of OFFENSIVE_ONLY_TOOLS) {
        expect(config[name], `${name} must be off in ${profile}`).toBe(false);
      }
    }
  });

  // This is true and deliberate, but it means 'ai-pentest' also enables the
  // four OFFENSIVE_ONLY_TOOLS — so it must pass the same Tier A +
  // authorization gate as 'offensive'. See the enablesOffensiveTools block
  // below, which is what the queue worker actually gates on.
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
    expect(config.sast).toBe(true);
    expect(config.workflowSecurity).toBe(true);
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

describe("'exposure' (managed exposure review)", () => {
  // Sold as "no exploitation, no test payloads" (docs/DEFENSIVE-ASSESSMENT-PLAN.md).
  const PAYLOAD_TOOLS = ["sqlmap", "commix", "dalfox", "zapAjaxSpider", "apiSpecInjection", "arjun", "kiterunner", "sessionCheck", ...OFFENSIVE_ONLY_TOOLS] as const;

  it("enables exactly its own tool list", () => {
    const config = resolveToolConfig("exposure");
    for (const name of EXTENDED_TOOL_NAMES) expect(config[name], name).toBe(EXPOSURE_TOOLS.has(name));
    expect([...EXPOSURE_TOOLS].sort()).toEqual(["httpx", "networkExposure", "nmap", "nuclei", "zap"]);
  });

  it("never enables an injection tester, ZAP's active scan or an offensive-only tool", () => {
    const config = resolveToolConfig("exposure");
    for (const name of PAYLOAD_TOOLS) expect(config[name], name).toBe(false);
  });

  it("a bundle can switch its tools off but cannot add a payload-sending one", () => {
    const everything = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, true]));
    const config = resolveToolConfig("exposure", everything);
    for (const name of EXTENDED_TOOL_NAMES) expect(config[name], name).toBe(EXPOSURE_TOOLS.has(name));
    expect(resolveToolConfig("exposure", { nmap: false }).nmap).toBe(false);
    expect(enablesOffensiveTools("exposure", everything)).toBe(false);
  });

  it("counts as non-intrusive, like 'safe', and no active profile does", () => {
    expect(isNonIntrusiveProfile("exposure")).toBe(true);
    expect(isNonIntrusiveProfile("safe")).toBe(true);
    for (const profile of ["full", "api", "cms", "osint", "offensive", "ai-pentest"] as const) {
      expect(isNonIntrusiveProfile(profile), profile).toBe(false);
    }
  });

  describe("ZAP passive-only mode", () => {
    afterEach(() => {
      vi.unstubAllGlobals();
      delete process.env.ZAP_API_URL;
      delete process.env.ZAP_API_KEY;
    });

    // Answers each ZAP API call by path, and records every path requested.
    function stubZap(): string[] {
      const paths: string[] = [];
      vi.stubGlobal("fetch", vi.fn(async (url: string) => {
        const path = new URL(url).pathname;
        paths.push(path);
        const body: Record<string, unknown> =
          path === "/JSON/spider/action/scan/" ? { scan: "1" }
          : path === "/JSON/spider/view/status/" ? { status: "100" }
          : path === "/JSON/pscan/view/recordsToScan/" ? { recordsToScan: "0" }
          : path === "/JSON/ascan/action/scan/" ? { scan: "2" }
          : path === "/JSON/ascan/view/status/" ? { status: "100" }
          : path === "/JSON/core/view/alerts/" ? { alerts: [{ risk: "Low", name: "Missing header", description: "d", url: "https://example.com/", solution: "s", reference: "" }] }
          : {};
        return { ok: true, json: () => Promise.resolve(body) };
      }));
      process.env.ZAP_API_URL = "http://localhost:8090";
      process.env.ZAP_API_KEY = "testkey";
      return paths;
    }

    it("spiders, drains the passive queue and reads alerts with no ascan request", async () => {
      const paths = stubZap();
      const result = await runZap("https://example.com/", { passiveOnly: isNonIntrusiveProfile("exposure") });
      expect(result.status).toBe("completed");
      expect(result.alerts).toHaveLength(1);
      expect(paths).toContain("/JSON/pscan/view/recordsToScan/");
      expect(paths.filter((p) => p.includes("/ascan/"))).toEqual([]);
    });

    it("an active profile still runs the active scan", async () => {
      const paths = stubZap();
      const result = await runZap("https://example.com/", { passiveOnly: isNonIntrusiveProfile("full") });
      expect(result.status).toBe("completed");
      expect(paths).toContain("/JSON/ascan/action/scan/");
    });
  });
});

describe("enablesOffensiveTools", () => {
  // The queue worker's Tier A + per-target-authorization gate keys off this
  // function. It used to compare the profile to "offensive" directly, which
  // let "ai-pentest" run the same four brute-force / exploit tools with no
  // Tier A check, no authorization row and neither audit event.
  it("is true for 'offensive'", () => {
    expect(enablesOffensiveTools("offensive")).toBe(true);
  });

  it("is true for 'ai-pentest' — the gap a profile-name check missed", () => {
    expect(enablesOffensiveTools("ai-pentest")).toBe(true);
  });

  it("is false for every profile that enables no offensive-only tool", () => {
    for (const profile of ["safe", "full", "api", "cms", "osint", "exposure"] as const) {
      expect(enablesOffensiveTools(profile), profile).toBe(false);
    }
  });

  it("is true for any profile the table gives an offensive-only tool to", () => {
    // Guards the table itself rather than a hand-kept list of profile names:
    // add an offensive-only tool to any profile and that profile must gate.
    for (const profile of ["safe", "full", "api", "cms", "osint", "exposure", "offensive", "ai-pentest"] as const) {
      const config = resolveToolConfig(profile);
      const hasOffensive = [...OFFENSIVE_ONLY_TOOLS].some((t) => config[t]);
      expect(enablesOffensiveTools(profile), profile).toBe(hasOffensive);
    }
  });

  it("is true when a scan bundle's tool_overrides turn one on over a tame profile", () => {
    expect(enablesOffensiveTools("full", { contentDiscovery: true })).toBe(true);
    expect(enablesOffensiveTools("safe", { credentialSpray: true })).toBe(true);
  });

  it("is false when overrides turn the offensive tools off on an offensive profile", () => {
    const off = { contentDiscovery: false, credentialSpray: false, strix: false, cairn: false };
    expect(enablesOffensiveTools("offensive", off)).toBe(false);
    expect(enablesOffensiveTools("ai-pentest", off)).toBe(false);
  });
});
