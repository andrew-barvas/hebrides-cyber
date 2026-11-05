import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const { exec } = vi.hoisted(() => ({ exec: vi.fn() }));
vi.mock("../../lib/execTool", () => ({ execTool: exec }));

import { buildCustomNucleiArgs, runCustomNuclei } from "./customNuclei";

const yaml = (id: string, pathLine = '"{{BaseURL}}/x"') => `id: ${id}
info:
  name: ${id} name
  severity: medium
http:
  - method: GET
    path: [${pathLine}]
    matchers:
      - type: status
        status: [200]
`;

beforeEach(() => {
  exec.mockReset();
});

describe("buildCustomNucleiArgs", () => {
  const args = buildCustomNucleiArgs("https://example.com", "/tmp/d", "/tmp/d/out.json");
  const flags = args.filter((a) => a.startsWith("-"));

  it("targets one site, from one directory", () => {
    expect(args.slice(args.indexOf("-target"), args.indexOf("-target") + 2)).toEqual(["-target", "https://example.com"]);
    expect(args.filter((a) => a === "-target")).toHaveLength(1);
    expect(args[args.indexOf("-t") + 1]).toBe("/tmp/d");
  });

  it("turns off out-of-band callbacks and update checks, and never enables code, headless or local files", () => {
    expect(flags).toEqual(expect.arrayContaining(["-ni", "-duc"]));
    for (const banned of ["-code", "-headless", "-lfa", "-allow-local-file-access", "-dast", "-fuzz", "-iserver", "-l", "-list"]) expect(flags).not.toContain(banned);
  });

  it("is rate limited", () => {
    expect(args[args.indexOf("-rl") + 1]).toBe("5");
    expect(args[args.indexOf("-c") + 1]).toBe("3");
  });
});

describe("runCustomNuclei", () => {
  it("re-validates every template and never hands an invalid one to nuclei", async () => {
    let seen: string[] = [];
    exec.mockImplementation(async (...a: unknown[]) => {
      const args = a[1] as string[];
      const dir = args[args.indexOf("-t") + 1];
      seen = readdirSync(dir).sort();
      // Nothing from the invalid templates was written for nuclei to read.
      writeFileSync(path.join(dir, "results.json"), "[]");
      return { stdout: "", stderr: "" };
    });
    const r = await runCustomNuclei("https://example.com", [
      { template_id: "good-one", yaml: yaml("good-one") },
      { template_id: "offsite", yaml: yaml("offsite", '"http://evil.example/"') },
      { template_id: "id-mismatch", yaml: yaml("someone-elses") },
    ]);
    expect(seen).toEqual(["good-one.yaml"]);
    expect(r).toMatchObject({ status: "completed", skipped: ["offsite", "id-mismatch"] });
  });

  it("does not run nuclei at all when nothing validates", async () => {
    const r = await runCustomNuclei("https://example.com", [{ template_id: "offsite", yaml: yaml("offsite", '"http://evil.example/"') }]);
    expect(exec).not.toHaveBeenCalled();
    expect(r).toEqual({ status: "completed", findings: [], skipped: ["offsite"] });
  });

  it("returns only findings from the customer's own templates", async () => {
    exec.mockImplementation(async (_bin: string, args: string[]) => {
      const out = args[args.indexOf("-json-export") + 1];
      writeFileSync(out, JSON.stringify([
        { "template-id": "good-one", info: { name: "Found it", severity: "high" }, "matched-at": "https://example.com/x" },
        { "template-id": "not-ours", info: { name: "Stray", severity: "critical" } },
      ]));
      return { stdout: "", stderr: "" };
    });
    const r = await runCustomNuclei("https://example.com", [{ template_id: "good-one", yaml: yaml("good-one") }]);
    expect(r.status === "completed" && r.findings).toEqual([{ severity: "high", title: "Found it", detail: "Matched at: https://example.com/x", templateId: "good-one" }]);
  });

  it("reports a missing binary as not_configured and any other failure as an error, without throwing", async () => {
    exec.mockRejectedValueOnce(Object.assign(new Error("spawn nuclei ENOENT"), { code: "ENOENT" }));
    expect((await runCustomNuclei("https://example.com", [{ template_id: "good-one", yaml: yaml("good-one") }])).status).toBe("not_configured");
    exec.mockRejectedValueOnce(new Error("timed out"));
    expect((await runCustomNuclei("https://example.com", [{ template_id: "good-one", yaml: yaml("good-one") }])).status).toBe("error");
  });

  it("writes the templates readable by the worker only", async () => {
    let mode = 0;
    exec.mockImplementation(async (_bin: string, args: string[]) => {
      const dir = args[args.indexOf("-t") + 1];
      mode = (await import("node:fs")).statSync(path.join(dir, "good-one.yaml")).mode & 0o077;
      expect(readFileSync(path.join(dir, "good-one.yaml"), "utf8")).toContain("good-one");
      return { stdout: "", stderr: "" };
    });
    await runCustomNuclei("https://example.com", [{ template_id: "good-one", yaml: yaml("good-one") }]);
    // POSIX only; Windows reports permissive modes for every file.
    if (process.platform !== "win32") expect(mode).toBe(0);
  });
});
