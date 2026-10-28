import { describe, expect, it } from "vitest";
import { analyseTokens, describeTokenIssues, MIN_TOKEN_SAMPLES } from "./tokenEntropy";

/** Deterministic PRNG so the "random" fixtures never flake. */
function rng(seed: number) {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomTokens(count: number, length: number, alphabet: string, seed = 1): string[] {
  const r = rng(seed);
  return Array.from({ length: count }, () => Array.from({ length }, () => alphabet[Math.floor(r() * alphabet.length)]).join(""));
}

const HEX = "0123456789abcdef";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

describe("analyseTokens", () => {
  it("does not judge a sample that is too small", () => {
    expect(analyseTokens(randomTokens(MIN_TOKEN_SAMPLES - 1, 32, HEX))).toEqual({ enough: false, samples: MIN_TOKEN_SAMPLES - 1 });
    expect(analyseTokens([])).toEqual({ enough: false, samples: 0 });
  });

  it("ignores empty tokens when counting samples", () => {
    expect(analyseTokens(["", "", ...randomTokens(MIN_TOKEN_SAMPLES - 1, 32, HEX)])).toMatchObject({ enough: false, samples: MIN_TOKEN_SAMPLES - 1 });
  });

  it("finds nothing wrong with long random hex", () => {
    const a = analyseTokens(randomTokens(12, 32, HEX));
    expect(a).toMatchObject({ enough: true, unique: 12, alphabetSize: 16, issues: [] });
    expect(a.enough && a.estimatedBits).toBeGreaterThan(100);
  });

  it("finds nothing wrong with a long random base64url token", () => {
    const a = analyseTokens(randomTokens(12, 43, B64, 7));
    expect(a.enough && a.issues).toEqual([]);
    expect(a.enough && a.alphabetSize).toBe(64);
  });

  it("flags a short random token as low entropy", () => {
    const a = analyseTokens(randomTokens(12, 12, HEX));
    expect(a.enough && a.issues).toContain("low-entropy");
    expect(a.enough && a.estimatedBits).toBeLessThan(64);
  });

  it("flags a tiny token as very low entropy", () => {
    const a = analyseTokens(randomTokens(12, 6, HEX));
    expect(a.enough && a.issues).toContain("very-low-entropy");
  });

  it("flags a counter as sequential, in decimal and hex, ascending or descending", () => {
    const dec = Array.from({ length: 10 }, (_, i) => String(48210 + i * 3));
    expect(analyseTokens(dec)).toMatchObject({ enough: true, issues: expect.arrayContaining(["sequential"]) });
    const hex = Array.from({ length: 10 }, (_, i) => (0xabc000 + i).toString(16));
    expect(analyseTokens(hex)).toMatchObject({ issues: expect.arrayContaining(["sequential"]) });
    expect(analyseTokens([...dec].reverse())).toMatchObject({ issues: expect.arrayContaining(["sequential"]) });
  });

  it("does not call large random numbers sequential", () => {
    const nums = randomTokens(12, 18, "0123456789", 3);
    expect(analyseTokens(nums).enough && (analyseTokens(nums) as { issues: string[] }).issues).not.toContain("sequential");
  });

  it("flags the same value handed to different sessions", () => {
    const tokens = [...randomTokens(6, 32, HEX), ...Array(6).fill("a".repeat(32))];
    const a = analyseTokens(tokens);
    expect(a.enough && a.issues).toContain("duplicates");
    expect(a.enough && a.unique).toBe(7);
  });

  it("flags tokens that are mostly the same characters", () => {
    const tokens = Array.from({ length: 10 }, (_, i) => `sess-0000-0000-0000-000${i}-aaaa`);
    const a = analyseTokens(tokens);
    expect(a.enough && a.issues).toContain("constant-positions");
  });

  it("tolerates a shared prefix without calling the whole token constant", () => {
    const tokens = randomTokens(12, 40, HEX, 9).map((t) => `v1.${t}`);
    const a = analyseTokens(tokens);
    expect(a.enough && a.issues).toEqual([]);
  });

  it("never includes a token value in its result", () => {
    const tokens = randomTokens(12, 12, HEX, 5);
    const json = JSON.stringify(analyseTokens(tokens));
    for (const t of tokens) expect(json).not.toContain(t);
  });
});

describe("describeTokenIssues", () => {
  it("is null for a clean or too-small analysis", () => {
    expect(describeTokenIssues("sid", analyseTokens(randomTokens(12, 32, HEX)))).toBeNull();
    expect(describeTokenIssues("sid", analyseTokens([]))).toBeNull();
  });

  it("names the cookie and the problems, and says it is an estimate", () => {
    const dec = Array.from({ length: 10 }, (_, i) => String(1000 + i));
    const text = describeTokenIssues("PHPSESSID", analyseTokens(dec))!;
    expect(text).toContain('"PHPSESSID"');
    expect(text).toContain("count up in small steps");
    expect(text).toContain("statistical estimate");
  });

  it("reports duplicates and the size estimate", () => {
    const text = describeTokenIssues("sid", analyseTokens([...randomTokens(6, 8, HEX), ...Array(6).fill("deadbeef")]))!;
    expect(text).toMatch(/\d of 12 fresh sessions/);
    expect(text).toContain("bits");
  });
});
