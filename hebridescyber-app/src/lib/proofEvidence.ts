// Reads the result of proofOfExploit.ts off a finding. Kept separate (pure, no
// Node imports) so client components and report builders can use it.
export type ProofEvidence = { evidence: string; request?: string; validatedAt?: string };

/** The recorded proof when a re-check reproduced the issue, else null. Absence never means "disproved". */
export function confirmedProof(finding: { metadata?: Record<string, unknown> }): ProofEvidence | null {
  const proof = finding.metadata?.proofOfExploit as { confirmed?: boolean; evidence?: string; request?: string; validatedAt?: string } | undefined;
  if (!proof?.confirmed) return null;
  return { evidence: proof.evidence ?? "Reproduced by a follow-up check.", request: proof.request, validatedAt: proof.validatedAt };
}

export type AiTriageView = {
  verdict: "confirmed" | "not_confirmed" | "inconclusive";
  evidence?: string;
  request?: string;
  reasoning: string;
};

/**
 * What the AI triage step recorded (aiTriage.ts), or null. "not_confirmed" and
 * "inconclusive" are returned as-is so the UI can show them, but neither is
 * evidence a finding is fixed or absent; only the scanner's own re-checks are.
 */
export function aiTriageView(finding: { metadata?: Record<string, unknown> }): AiTriageView | null {
  const t = finding.metadata?.aiTriage as Partial<AiTriageView> | undefined;
  if (!t || (t.verdict !== "confirmed" && t.verdict !== "not_confirmed" && t.verdict !== "inconclusive")) return null;
  return { verdict: t.verdict, evidence: t.evidence, request: t.request, reasoning: typeof t.reasoning === "string" ? t.reasoning : "" };
}

/** Tooltip for the "AI-verified" badge: what the model quoted, and the request line that produced it. */
export function aiVerifiedTitle(view: AiTriageView): string {
  const requestLine = view.request?.split(/\r?\n/)[0];
  return `AI-assisted check: the server's response showed this${view.evidence ? `: "${view.evidence}"` : ""}${requestLine ? ` (${requestLine})` : ""}`;
}
