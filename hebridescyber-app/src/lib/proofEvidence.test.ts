import { describe, it, expect } from "vitest";
import { aiTriageView, aiVerifiedTitle, confirmedProof } from "./proofEvidence";

describe("confirmedProof", () => {
  it("returns the evidence when confirmed", () => {
    expect(confirmedProof({ metadata: { proofOfExploit: { confirmed: true, evidence: "e", request: "GET /x", validatedAt: "t" } } })).toEqual({ evidence: "e", request: "GET /x", validatedAt: "t" });
  });
  it("supplies default wording when a confirmed proof has no evidence text", () => {
    expect(confirmedProof({ metadata: { proofOfExploit: { confirmed: true } } })?.evidence).toMatch(/Reproduced/);
  });
  it("is null when unconfirmed, absent or the finding has no metadata", () => {
    expect(confirmedProof({ metadata: { proofOfExploit: { confirmed: false } } })).toBeNull();
    expect(confirmedProof({ metadata: {} })).toBeNull();
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

describe("aiVerifiedTitle", () => {
  it("quotes the evidence and shows only the first request line", () => {
    expect(aiVerifiedTitle({ verdict: "confirmed", reasoning: "", evidence: "X=1", request: ["GET /a", "Origin: b"].join(String.fromCharCode(10)) })).toBe(
      "AI-assisted check: the server's response showed this: \"X=1\" (GET /a)",
    );
  });
  it("omits missing parts", () => {
    expect(aiVerifiedTitle({ verdict: "confirmed", reasoning: "" })).toBe("AI-assisted check: the server's response showed this");
  });
});
