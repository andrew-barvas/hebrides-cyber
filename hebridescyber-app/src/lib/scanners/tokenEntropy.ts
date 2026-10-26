// Statistical checks on a sample of session tokens: the scanner-side analogue of
// a manual tester's "sequencer". Pure (no network, no clock), so it is unit
// testable on synthetic token sets; sessionCheck.ts does the sampling.
//
// What it can and cannot say. A sample of ~12 anonymous tokens can show that a
// token is obviously predictable (a counter, a short or tiny-alphabet value, the
// same value handed to everyone) and can estimate its size. It cannot prove a
// token is unpredictable, so "no issues" means "nothing obviously wrong", and a
// sample too small to judge returns `enough: false` rather than a clean bill.
//
// It never returns token values, only measurements, so nothing a finding or
// log carries can be replayed.

export const MIN_TOKEN_SAMPLES = 8;
/** Below this estimated size a token is guessable in practice. */
export const WEAK_BITS = 64;
/** Below this it is guessable almost immediately. */
export const VERY_WEAK_BITS = 40;

export type TokenIssue = "duplicates" | "sequential" | "low-entropy" | "very-low-entropy" | "constant-positions";

export type TokenAnalysis =
  | { enough: false; samples: number }
  | {
      enough: true;
      samples: number;
      unique: number;
      minLength: number;
      /** Size of the alphabet the tokens appear to use (10, 16, 36, 62, 64 or the observed count). */
      alphabetSize: number;
      /** Pooled Shannon entropy per character, in bits, capped by the alphabet. */
      bitsPerChar: number;
      /** bitsPerChar x the shortest token length: a deliberately conservative size estimate. */
      estimatedBits: number;
      issues: TokenIssue[];
    };

function shannonBitsPerChar(tokens: string[]): number {
  const counts = new Map<string, number>();
  let total = 0;
  for (const t of tokens) {
    for (const ch of t) {
      counts.set(ch, (counts.get(ch) ?? 0) + 1);
      total++;
    }
  }
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / total;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** The smallest standard alphabet that contains every observed character. */
function alphabetSizeFor(tokens: string[]): number {
  const seen = new Set<string>(tokens.join(""));
  const all = (re: RegExp) => [...seen].every((c) => re.test(c));
  if (all(/[0-9]/)) return 10;
  if (all(/[0-9a-f]/) || all(/[0-9A-F]/)) return 16;
  if (all(/[0-9a-z]/) || all(/[0-9A-Z]/)) return 36;
  if (all(/[0-9a-zA-Z]/)) return 62;
  if (all(/[0-9a-zA-Z_-]/) || all(/[0-9a-zA-Z+/=]/)) return 64;
  return Math.max(2, seen.size);
}

/** True when the tokens read as one integer (decimal or hex) that grows by small steps. */
function looksSequential(tokens: string[]): boolean {
  const parsed: bigint[] = [];
  for (const t of tokens) {
    const decimal = /^\d{1,30}$/.test(t);
    const hex = /^[0-9a-f]{1,24}$/i.test(t);
    if (!decimal && !hex) return false;
    try {
      parsed.push(decimal ? BigInt(t) : BigInt("0x" + t));
    } catch {
      return false;
    }
  }
  const sorted = [...parsed].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const asArrived = parsed.every((v, i) => i === 0 || v > parsed[i - 1]) || parsed.every((v, i) => i === 0 || v < parsed[i - 1]);
  const span = sorted[sorted.length - 1] - sorted[0];
  // Counting up (or down) by small steps: a few thousand per token at most.
  return asArrived && span / BigInt(Math.max(1, tokens.length - 1)) < BigInt(5000);
}

/** Share of character positions that hold the same character in every token. */
function constantPositionShare(tokens: string[], length: number): number {
  let constant = 0;
  for (let i = 0; i < length; i++) {
    const first = tokens[0][i];
    if (tokens.every((t) => t[i] === first)) constant++;
  }
  return constant / length;
}

export function analyseTokens(tokens: string[]): TokenAnalysis {
  const clean = tokens.filter((t) => t.length > 0);
  if (clean.length < MIN_TOKEN_SAMPLES) return { enough: false, samples: clean.length };

  const unique = new Set(clean).size;
  const minLength = Math.min(...clean.map((t) => t.length));
  const alphabetSize = alphabetSizeFor(clean);
  const maxBitsPerChar = Math.log2(alphabetSize);
  const bitsPerChar = Math.min(shannonBitsPerChar(clean), maxBitsPerChar);
  const estimatedBits = Math.round(bitsPerChar * minLength * 10) / 10;

  const issues: TokenIssue[] = [];
  if (unique < clean.length) issues.push("duplicates");
  if (unique > 1 && looksSequential(clean)) issues.push("sequential");
  // Shared prefixes are normal (a version tag); most positions never changing is not.
  if (unique > 1 && minLength >= 8 && constantPositionShare(clean, minLength) > 0.6) issues.push("constant-positions");
  if (estimatedBits < VERY_WEAK_BITS) issues.push("very-low-entropy");
  else if (estimatedBits < WEAK_BITS) issues.push("low-entropy");

  return { enough: true, samples: clean.length, unique, minLength, alphabetSize, bitsPerChar: Math.round(bitsPerChar * 100) / 100, estimatedBits, issues };
}

/** Human-readable summary of an analysis with issues, or null when nothing was wrong or the sample was too small. */
export function describeTokenIssues(cookieName: string, a: TokenAnalysis): string | null {
  if (!a.enough || a.issues.length === 0) return null;
  const parts: string[] = [];
  if (a.issues.includes("duplicates")) parts.push(`${a.samples - a.unique} of ${a.samples} fresh sessions were handed a value already issued`);
  if (a.issues.includes("sequential")) parts.push("the values count up in small steps, so the next one can be guessed");
  if (a.issues.includes("constant-positions")) parts.push("most characters are identical in every token");
  if (a.issues.includes("very-low-entropy") || a.issues.includes("low-entropy")) {
    parts.push(`the estimated size is about ${a.estimatedBits} bits (${a.minLength} characters from a ${a.alphabetSize}-symbol alphabet); 64 bits is a floor and 128 is the usual target`);
  }
  return `The "${cookieName}" session cookie looks predictable across ${a.samples} fresh sessions: ${parts.join("; ")}. This is a statistical estimate from a small sample, not a proof of exploitability.`;
}
