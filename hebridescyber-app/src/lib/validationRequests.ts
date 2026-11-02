// "Request validation" on a finding: what we record and what the operator is
// emailed. The snapshot is what the customer saw when they asked, so the later
// conversation does not depend on a rescan having kept the same wording.
import type { Finding } from "./scanners";
import { confirmedProof } from "./proofEvidence";
import { escapeHtml } from "./email";
import { NOTE_MAX } from "./validationEligibility";

export { NOTE_MAX };

const DETAIL_MAX = 1500;
const EVIDENCE_MAX = 600;

export type ValidationSnapshot = {
  checkId: string;
  severity: Finding["severity"];
  title: string;
  detail: string;
  cveIds: string[];
  confirmedExploitable: boolean;
  /** The captured evidence line, already redacted when the scan stored it. */
  evidence: string | null;
};

const clip = (s: string, max: number) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

export function buildValidationSnapshot(finding: Finding): ValidationSnapshot {
  const proof = confirmedProof(finding);
  return {
    checkId: finding.checkId ?? "",
    severity: finding.severity,
    title: clip(finding.title, 500),
    detail: clip(finding.detail ?? "", DETAIL_MAX),
    cveIds: (finding.cveIds ?? []).slice(0, 20),
    confirmedExploitable: Boolean(proof),
    evidence: proof ? clip(proof.evidence, EVIDENCE_MAX) : null,
  };
}

export function operatorEmail(input: { requesterEmail: string | null; host: string; snapshot: ValidationSnapshot; note: string | null; requestId: string }) {
  const { snapshot: s } = input;
  return {
    subject: `Validation request: ${s.severity} on ${input.host}`,
    html: [
      `<p><strong>Customer:</strong> ${escapeHtml(input.requesterEmail ?? "unknown")}</p>`,
      `<p><strong>Site:</strong> ${escapeHtml(input.host)}</p>`,
      `<p><strong>Finding:</strong> ${escapeHtml(s.title)} (${escapeHtml(s.severity)}${s.confirmedExploitable ? ", confirmed exploitable by the scanner" : ""})</p>`,
      `<p><strong>Check:</strong> ${escapeHtml(s.checkId)}</p>`,
      s.cveIds.length ? `<p><strong>CVEs:</strong> ${escapeHtml(s.cveIds.join(", "))}</p>` : "",
      s.evidence ? `<p><strong>Evidence:</strong> ${escapeHtml(s.evidence)}</p>` : "",
      input.note ? `<p><strong>Their note:</strong><br>${escapeHtml(input.note).replace(/\n/g, "<br>")}</p>` : "",
      `<p>Request id ${escapeHtml(input.requestId)}. No testing has happened. Scope, written authorisation and the engagement contract come first.</p>`,
    ].join(""),
  };
}
