// The request/response that produced a finding (SPRINT-PLAN H4), recorded so a
// customer can see *why* we reported it rather than taking the title on trust.
//
// Bounded and redacted at capture time, because it is stored with the scan
// result and shown in the dashboard, share links and exports:
// - Response headers are an allowlist: no Set-Cookie, auth, or anything we
//   don't name. Request headers aren't recorded at all (ours carry nothing).
// - The body excerpt is capped (EXCERPT_MAX) *after* redaction, and every
//   `key=value` / `key: value` value, token-shaped string, password hash,
//   private-key block, credential-in-URL and email address is masked. The
//   finding still shows which keys were exposed (that is the proof) without
//   copying their secrets into our database.
// Stored inside scan_results.results, so it is deleted with the scan.
//
// Pure, no Node imports, so client components and report builders can use it.

export type FindingEvidence = {
  request: { method: "GET"; url: string };
  response: {
    status: number;
    /** Allowlisted headers only (see SAFE_HEADERS). */
    headers: Record<string, string>;
    /** Redacted, capped body text. Absent when the check never read the body. */
    bodyExcerpt?: string;
    /** True when bodyExcerpt was cut at EXCERPT_MAX. */
    truncated?: boolean;
  };
  /** The text that satisfied the check (redacted), when the check matched on content. */
  matched?: string;
  capturedAt: string;
};

export const EXCERPT_MAX = 400;
const MATCHED_MAX = 160;
const SAFE_HEADERS = ["content-type", "content-length", "server", "last-modified", "x-powered-by"] as const;
export const REDACTED = "[redacted]";

const REDACTIONS: Array<[RegExp, string | ((m: string, ...g: string[]) => string)]> = [
  // PEM private keys, whole block.
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, REDACTED],
  // user:password@host in connection strings and URLs.
  [/([a-z][a-z0-9+.-]*:\/\/)[^\s:/@]+:[^\s@/]+@/gi, `$1${REDACTED}@`],
  // JWTs.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g, REDACTED],
  // AWS access key ids.
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, REDACTED],
  // Crypt-style password hashes ($2y$…, $apr1$…, $6$…) and {SHA} hashes.
  [/\$[0-9a-z]{1,4}\$[^\s:]+/gi, REDACTED],
  [/\{SHA\}[A-Za-z0-9+/=]+/g, REDACTED],
  // Bearer tokens.
  [/\b(Bearer)\s+[A-Za-z0-9._~+/-]+=*/gi, `$1 ${REDACTED}`],
  // key=value / key: value on a line — keep the key, drop the value.
  [/^(\s*(?:export\s+)?["']?[A-Za-z0-9_.-]+["']?\s*[=:]\s*)(?!\s*$)(.+)$/gm, `$1${REDACTED}`],
  // Email addresses (log lines, configs).
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, REDACTED],
  // Any remaining long token-shaped run (base64/hex keys).
  [/\b[A-Za-z0-9+/_-]{32,}={0,2}/g, REDACTED],
];

/** Mask secrets in text taken from a scanned site. Idempotent. */
export function redactEvidenceText(text: string): string {
  let out = text;
  for (const [pattern, replacement] of REDACTIONS) {
    out = out.replace(pattern, replacement as string);
  }
  return out;
}

function cap(text: string, max: number): { text: string; truncated: boolean } {
  return text.length > max ? { text: text.slice(0, max), truncated: true } : { text, truncated: false };
}

/**
 * Build evidence for a single GET a check made. `body` is the raw response
 * text when the check read it; pass undefined when it didn't.
 */
export function buildHttpEvidence(input: {
  url: string;
  status: number;
  headers: Headers | Record<string, string>;
  body?: string;
  matched?: string;
  now?: Date;
}): FindingEvidence {
  const headers: Record<string, string> = {};
  const get = (name: string) =>
    input.headers instanceof Headers ? input.headers.get(name) : (input.headers[name] ?? input.headers[name.toLowerCase()] ?? null);
  for (const name of SAFE_HEADERS) {
    const value = get(name);
    if (value) headers[name] = value.slice(0, 200);
  }

  const response: FindingEvidence["response"] = { status: input.status, headers };
  if (input.body !== undefined) {
    const { text, truncated } = cap(redactEvidenceText(input.body.replace(/\r\n/g, "\n")).trim(), EXCERPT_MAX);
    response.bodyExcerpt = text;
    if (truncated) response.truncated = true;
  }

  const evidence: FindingEvidence = {
    request: { method: "GET", url: input.url },
    response,
    capturedAt: (input.now ?? new Date()).toISOString(),
  };
  if (input.matched) evidence.matched = cap(redactEvidenceText(input.matched), MATCHED_MAX).text;
  return evidence;
}

/** One line for CSV and plain-text reports: "GET <url> → 200 (content-type); matched: …". */
export function evidenceSummary(e: FindingEvidence | undefined): string {
  if (!e) return "";
  const type = e.response.headers["content-type"];
  return `${e.request.method} ${e.request.url} → ${e.response.status}${type ? ` (${type})` : ""}${e.matched ? `; matched: ${e.matched}` : ""}`;
}

/** Narrow an unknown stored value (old scans, JSON) to evidence, or undefined. */
export function readEvidence(value: unknown): FindingEvidence | undefined {
  const v = value as Partial<FindingEvidence> | undefined;
  if (!v || typeof v !== "object" || !v.request || !v.response || typeof v.response.status !== "number" || typeof v.request.url !== "string") {
    return undefined;
  }
  return v as FindingEvidence;
}
