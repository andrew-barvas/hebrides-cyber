import { describe, it, expect } from "vitest";
import { parseDisabledTools, applyKillSwitch } from "./toolKillSwitch";
import { EXTENDED_TOOL_NAMES, resolveToolConfig, type ExtendedToolName } from "./scanProfiles";

describe("parseDisabledTools", () => {
  it("collects only rows that are both known tools and disabled", () => {
    const set = parseDisabledTools([
      { tool_name: "nuclei", disabled: true },
      { tool_name: "zap", disabled: false },
      { tool_name: "sqlmap", disabled: true },
    ]);
    expect([...set].sort()).toEqual(["nuclei", "sqlmap"]);
  });

  it("ignores unknown tool names (a renamed/removed tool never disables another)", () => {
    const set = parseDisabledTools([
      { tool_name: "not_a_tool", disabled: true },
      { tool_name: "nuclei", disabled: true },
    ]);
    expect([...set]).toEqual(["nuclei"]);
  });

  it("returns an empty set for null/undefined/empty input", () => {
    expect(parseDisabledTools(null).size).toBe(0);
    expect(parseDisabledTools(undefined).size).toBe(0);
    expect(parseDisabledTools([]).size).toBe(0);
  });
});

describe("applyKillSwitch", () => {
  it("forces every disabled tool to false and leaves the rest untouched", () => {
    const base = resolveToolConfig("full");
    const out = applyKillSwitch(base, new Set<ExtendedToolName>(["nuclei"]));
    expect(out.nuclei).toBe(false);
    expect(out.zap).toBe(base.zap); // a non-disabled tool keeps its profile value
  });

  it("returns the same object reference when nothing is disabled (no needless copy)", () => {
    const base = resolveToolConfig("full");
    expect(applyKillSwitch(base, new Set())).toBe(base);
  });

  it("never enables a tool the profile had off", () => {
    const safe = resolveToolConfig("safe"); // everything false
    const out = applyKillSwitch(safe, new Set<ExtendedToolName>(["nuclei", "zap"]));
    for (const name of EXTENDED_TOOL_NAMES) expect(out[name]).toBe(false);
  });

  it("does not mutate the input config", () => {
    const base = resolveToolConfig("full");
    const before = base.nuclei;
    applyKillSwitch(base, new Set<ExtendedToolName>(["nuclei"]));
    expect(base.nuclei).toBe(before);
  });
});
