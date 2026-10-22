import { describe, it, expect } from "vitest";
import { buildCsp, generateNonce } from "./csp";
import { buildHeaderAnalysis } from "./scanners/headers";

describe("csp", () => {
  it("generates a distinct nonce per call", () => {
    expect(generateNonce()).not.toBe(generateNonce());
  });

  it("puts the nonce and strict-dynamic in script-src, with no unsafe-inline or unsafe-eval in production", () => {
    const script = buildCsp("abc123", false).split("; ").find((d) => d.startsWith("script-src"))!;
    expect(script).toContain("'nonce-abc123'");
    expect(script).toContain("'strict-dynamic'");
    expect(script).not.toContain("'unsafe-inline'");
    expect(script).not.toContain("'unsafe-eval'");
  });

  it("allows unsafe-eval only in development", () => {
    expect(buildCsp("n", true)).toContain("'unsafe-eval'");
    expect(buildCsp("n", false)).not.toContain("'unsafe-eval'");
  });

  it("scores an A under our own scanner's CSP grader — the product must pass its own check", () => {
    const res = new Response(null, { headers: { "content-security-policy": buildCsp("abc123", false) } });
    const { csp } = buildHeaderAnalysis(res);
    expect(csp.issues).toEqual([]);
    expect(csp.grade).toBe("A");
  });
});
