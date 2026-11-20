// Client-safe pieces of the profile documents feature (trustDocuments.ts
// re-exports them): the kinds an owner can pick, their labels, and the size
// formatter. Kept apart so browser code never imports node:crypto.

export const DOCUMENT_KINDS = ["cyber_essentials", "insurance", "policy", "penetration_test", "other"] as const;
export type DocumentKind = (typeof DOCUMENT_KINDS)[number];

export const KIND_LABELS: Record<DocumentKind, string> = {
  cyber_essentials: "Cyber Essentials certificate",
  insurance: "Insurance certificate",
  policy: "Security policy",
  penetration_test: "Penetration test summary",
  other: "Document",
};

/** Pure. "1.2 MB" / "340 KB". */
export function formatSize(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}
