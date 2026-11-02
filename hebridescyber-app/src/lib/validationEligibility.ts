// The client-safe half of "request validation": which findings offer it and
// the note length. Kept apart from validationRequests.ts, which imports the
// server-only email module and must not be bundled into the browser.
import type { Finding } from "./scanners";
import { confirmedProof } from "./proofEvidence";

export const NOTE_MAX = 1000;

/** The findings worth offering a human test for: serious, or already shown to reproduce. */
export function worthValidating(finding: Pick<Finding, "checkId" | "severity" | "metadata">): boolean {
  return Boolean(finding.checkId) && (finding.severity === "critical" || finding.severity === "high" || Boolean(confirmedProof(finding)));
}
