// Wiring guard: adding a scanner tool touches several registries by hand
// (EXTENDED_TOOL_NAMES, a profile, the orchestrator, the finding-lifecycle
// alias map). A missed one doesn't fail loudly — the tool just never runs, or
// its findings never get marked fixed. This reads the source so the omission
// fails CI instead. See the /new-scanner-check skill for the full checklist.
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { EXTENDED_TOOL_NAMES, OFFENSIVE_ONLY_TOOLS, resolveToolConfig, type ScanProfile } from "./scanProfiles";

const read = (rel: string) => readFileSync(join(process.cwd(), rel), "utf8");
const execution = read("src/lib/scanExecution.ts");

const PROFILES: ScanProfile[] = ["safe", "full", "api", "cms", "osint", "offensive", "ai-pentest"];

describe("extended tool wiring", () => {
  it("has no duplicate tool names", () => {
    expect(new Set(EXTENDED_TOOL_NAMES).size).toBe(EXTENDED_TOOL_NAMES.length);
  });

  it.each([...EXTENDED_TOOL_NAMES])("%s is dispatched by the orchestrator", (tool) => {
    // scanExecution reads each tool's switch as tools.<name> / config.<name>.
    expect(execution).toMatch(new RegExp(`\\b${tool}\\b`));
  });

  it.each([...EXTENDED_TOOL_NAMES])("%s is enabled in at least one profile", (tool) => {
    expect(PROFILES.some((p) => resolveToolConfig(p)[tool])).toBe(true);
  });

  it("keeps offensive-only tools out of every non-offensive profile except ai-pentest's superset", () => {
    for (const profile of PROFILES.filter((p) => p !== "offensive" && p !== "ai-pentest")) {
      const config = resolveToolConfig(profile);
      for (const tool of OFFENSIVE_ONLY_TOOLS) expect(config[tool], `${profile} enables ${tool}`).toBe(false);
    }
  });

  it("only the offensive profiles enable the offensive-only tools", () => {
    for (const tool of OFFENSIVE_ONLY_TOOLS) {
      expect(resolveToolConfig("offensive")[tool]).toBe(true);
    }
  });
});

describe("worker tool modules", () => {
  const toolsDir = join(process.cwd(), "src/worker/tools");
  const modules = readdirSync(toolsDir)
    .filter((f) => f.endsWith(".ts") && !f.includes(".test.") && !f.includes(".integration."))
    .map((f) => f.replace(/\.ts$/, ""));

  // Every non-test module must be imported by something other than its own
  // tests — an orphaned tool is code that ships but never runs.
  const importers = [
    ...readdirSync(join(process.cwd(), "src/lib")).filter((f) => f.endsWith(".ts") && !f.includes(".test.")).map((f) => join("src/lib", f)),
    ...readdirSync(toolsDir).filter((f) => f.endsWith(".ts") && !f.includes(".test.") && !f.includes(".integration.")).map((f) => join("src/worker/tools", f)),
    ...readdirSync(join(process.cwd(), "src/scripts")).filter((f) => f.endsWith(".ts") && !f.includes(".test.")).map((f) => join("src/scripts", f)),
  ].map((rel) => ({ rel, text: read(rel) }));

  it.each(modules)("%s is imported by a non-test module", (mod) => {
    const importedBy = importers.filter(({ rel, text }) => !rel.endsWith(`/${mod}.ts`) && new RegExp(`from ["'](?:\\./|@/worker/tools/|\\.\\./worker/tools/)${mod}["']`).test(text));
    expect(importedBy.map((i) => i.rel), `${mod}.ts is orphaned`).not.toEqual([]);
  });
});
