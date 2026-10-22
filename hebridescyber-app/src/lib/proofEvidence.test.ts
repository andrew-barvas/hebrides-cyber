import { describe, expect, it } from "vitest";
import { aiTriageView, confirmedProof } from "./proofEvidence";

describe("confirmedProof", () => {
  it("returns the proof only when confirmed", () => {
    expect(confirmedProof({ metadata: { proofOfExploit: { confirmed: true, evidence: "e", request: "GET /" } } })).toMatchObject({ evidence: "e", request: "GET /" });
    expect(confirmedProof({ metadata: { proofOfExploit: { confirmed: false } } })).toBeNull();
    expect(confirmedProof({})).toBeNull();
  });
});

describe("aiTriageView", () => {
  it("returns each valid verdict", () => {
    for (const verdict of ["confirmed", "not_confirmed", "inconclusive"] as const) {
      expect(aiTriageView({ metadata: { aiTriage: { verdict, reasoning: "r" } } })?.verdict).toBe(verdict);
    }
  });
  it("returns null for a missing or invalid record", () => {
    expect(aiTriageView({})).toBeNull();
    expect(aiTriageView({ metadata: { aiTriage: { verdict: "yes" } } })).toBeNull();
    expect(aiTriageView({ metadata: { aiTriage: "confirmed" } })).toBeNull();
  });
  it("defaults reasoning to an empty string", () => {
    expect(aiTriageView({ metadata: { aiTriage: { verdict: "confirmed" } } })?.reasoning).toBe("");
  });
});
