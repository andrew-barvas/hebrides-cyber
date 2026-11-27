// Client-safe types for the security questionnaire autopilot (migration 087).
// Kept apart from the server modules so the review page can import them
// without pulling in exceljs or the Supabase admin client.

/** Where a piece of evidence came from. Every drafted answer cites at least one, or says it has none. */
export type EvidenceSource =
  | "scan"
  | "email_auth"
  | "m365"
  | "workspace"
  | "ce_self_assessment"
  | "device_agent"
  | "document"
  | "security_profile"
  | "previous_answer";

export type EvidenceCitation = {
  source: EvidenceSource;
  /** What it is, in a few words: "Website scan of example.co.uk". */
  label: string;
  /** What it showed. */
  detail: string;
  /** ISO date (YYYY-MM-DD) the evidence is from, or null when it has none. */
  date: string | null;
};

/**
 * high   our own checks saw it (or saw the gap) recently
 * medium the customer declared it, or a document they uploaded supports it
 * low    only partly evidenced; the customer should check the wording
 * none   no evidence: "Needs your answer"
 */
export type Confidence = "high" | "medium" | "low" | "none";

/**
 * draft         drafted from evidence, waiting for review
 * needs_answer  no evidence; the customer must answer it
 * accepted      a person accepted it (possibly edited): the only final state
 * rejected      a person rejected the draft; left blank in the export
 */
export type AnswerStatus = "draft" | "needs_answer" | "accepted" | "rejected";

export const ANSWER_STATUSES: readonly AnswerStatus[] = ["draft", "needs_answer", "accepted", "rejected"];

export const NEEDS_YOUR_ANSWER = "Needs your answer";

export type DraftAnswer = {
  topic: string | null;
  answer: string;
  evidence: EvidenceCitation[];
  confidence: Confidence;
  status: "draft" | "needs_answer";
  /** Why the draft is what it is, for the review screen (not exported). */
  note: string | null;
  reusedFrom: string | null;
};

export const SOURCE_LABELS: Record<EvidenceSource, string> = {
  scan: "Website scan",
  email_auth: "Email authentication (DNS)",
  m365: "Microsoft 365 check",
  workspace: "Google Workspace check",
  ce_self_assessment: "Your Cyber Essentials self-assessment",
  device_agent: "Device agent",
  document: "Your uploaded document",
  security_profile: "Public security profile",
  previous_answer: "Your earlier accepted answer",
};

export const CONFIDENCE_LABELS: Record<Confidence, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  none: "No evidence",
};

/** The Status column of the export, and the badge on the review screen. */
export function statusLabel(status: AnswerStatus, edited: boolean): string {
  if (status === "accepted") return edited ? "Accepted (edited)" : "Accepted";
  if (status === "rejected") return "Rejected";
  if (status === "needs_answer") return NEEDS_YOUR_ANSWER;
  return "Draft, not reviewed";
}

/** Pure: one evidence citation as a single line, "Website scan (2026-11-20): …". */
export function citationLine(c: EvidenceCitation): string {
  return `${c.label}${c.date ? ` (${c.date})` : ""}: ${c.detail}`;
}

/** Shown on the review page and written into every export. */
export const DRAFT_DISCLAIMER =
  "Draft answers prepared by Hebrides Cyber from your scan results and the evidence you hold with us. They are not a certification or an audit opinion. Check every answer before you send it.";
