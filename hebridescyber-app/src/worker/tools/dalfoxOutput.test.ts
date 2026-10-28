import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseDalfoxOutput } from "./dalfoxOutput";

const fixture = (name: string) => readFileSync(join(__dirname, "fixtures", "dalfox", name), "utf8");

describe("dalfox output (captured real v3.2.4 run)", () => {
  it("reads a confirmed reflected XSS finding from the real positive run", () => {
    const result = parseDalfoxOutput(fixture("reflected.json"));
    expect(result).not.toBeNull();
    expect(result?.unreachable).toBe(false);
    expect(result?.findings).toEqual([
      {
        param: "q",
        severity: "high",
        payload: "<svg onload=alert(1) class=dlx1bce23b4>",
        evidence: "DOM verification successful for param q (DOM marker)",
        cwe: "CWE-79",
      },
    ]);
  });

  it("reads zero findings from the real clean run, not an error", () => {
    const result = parseDalfoxOutput(fixture("clean.json"));
    expect(result).toEqual({ findings: [], unreachable: false });
  });

  it("flags a target dalfox never reached as unreachable, never clean", () => {
    const result = parseDalfoxOutput(fixture("unreachable.json"));
    expect(result).toEqual({ findings: [], unreachable: true });
  });

  it("returns null for output that isn't dalfox's JSON shape", () => {
    expect(parseDalfoxOutput("not json")).toBeNull();
    expect(parseDalfoxOutput(JSON.stringify({ meta: {} }))).toBeNull(); // no `findings` array
  });

  it("ignores a finding whose type is not the confirmed-vulnerable \"V\"", () => {
    const raw = JSON.stringify({
      findings: [{ type: "G", param: "x", severity: "high", payload: "p", evidence: "e" }],
      meta: { target_summary: [{ status: "findings" }] },
    });
    expect(parseDalfoxOutput(raw)).toEqual({ findings: [], unreachable: false });
  });
});
