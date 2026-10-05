import { describe, it, expect } from "vitest";
import { confirmedProof } from "./proofEvidence";

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
