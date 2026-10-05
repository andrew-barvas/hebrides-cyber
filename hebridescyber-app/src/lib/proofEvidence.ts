// Reads the result of proofOfExploit.ts off a finding. Kept separate (pure, no
// Node imports) so client components and report builders can use it.
export type ProofEvidence = { evidence: string; request?: string; validatedAt?: string };

/** The recorded proof when a re-check reproduced the issue, else null. Absence never means "disproved". */
export function confirmedProof(finding: { metadata?: Record<string, unknown> }): ProofEvidence | null {
  const proof = finding.metadata?.proofOfExploit as { confirmed?: boolean; evidence?: string; request?: string; validatedAt?: string } | undefined;
  if (!proof?.confirmed) return null;
  return { evidence: proof.evidence ?? "Reproduced by a follow-up check.", request: proof.request, validatedAt: proof.validatedAt };
}
