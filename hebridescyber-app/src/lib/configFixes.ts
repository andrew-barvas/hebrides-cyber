// Config-remediation fixes — the third kind of "fix it" PR (alongside the
// SECURITY-FIXES.md recommendations PR and the dependency-bump PR in
// src/pages/api/generate-fix-pr.ts). Where the dependency-bump PR edits
// package.json, this one edits a repo's *security-header* configuration so a
// missing header the scan saw on the live site gets added at the source a
// human then reviews and merges.
//
// Everything here is pure (file contents in, edited contents out) so it is
// unit-testable with no GitHub calls — the same split as the dependency-bump
// plan builder. The GitHub plumbing that fetches and commits lives in the API
// route; this module never touches the network.
//
// Scope, decided deliberately and kept narrow:
//   - Only the NO-REGRET headers below. Adding any of them to a response
//     cannot break a working site, so they are safe to write into a config a
//     human reviews. Content-Security-Policy is excluded (generating a CSP
//     that doesn't break the site needs per-site knowledge we don't have),
//     and so are cookie flags (a cookie's Secure/HttpOnly flag is set by the
//     application at runtime, not by a static header rule — a header file
//     can't fix it). Both stay as remediation text.
//   - Only header configs we can edit deterministically: the structured
//     platform files (Azure Static Web Apps, Vercel, Netlify) as data, and a
//     Next.js config only in the confident, common shapes where injecting a
//     headers() block is safe. Anything else is skipped with a reason rather
//     than risking a broken edit.

/**
 * The headers this feature is willing to add automatically. `name` is the
 * lowercase form the scan's OWASP analysis uses (for the missing-check);
 * `label` is the canonical casing written into a config file; `value` is a
 * conservative default (HSTS without `preload`, X-Frame-Options SAMEORIGIN
 * rather than DENY) chosen not to break a site that a reviewer then accepts.
 */
export const REMEDIABLE_HEADERS = [
  { name: "strict-transport-security", label: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
  { name: "x-content-type-options", label: "X-Content-Type-Options", value: "nosniff" },
  { name: "x-frame-options", label: "X-Frame-Options", value: "SAMEORIGIN" },
  { name: "referrer-policy", label: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
] as const;

export type DesiredHeader = { name: string; label: string; value: string };

/**
 * The remediable headers the live site is missing, read from the scan's
 * structured header analysis (`results.headers.owasp.headers`) — never from a
 * finding's `detail` text, which would be string-matching the finding
 * (CLAUDE.md's "never re-derive which fix applies from a finding's title").
 */
export function missingRemediableHeaders(owaspHeaders: Array<{ name: string; present: boolean }>): DesiredHeader[] {
  const missing = new Set(owaspHeaders.filter((h) => !h.present).map((h) => h.name.toLowerCase()));
  return REMEDIABLE_HEADERS.filter((h) => missing.has(h.name)).map((h) => ({ name: h.name, label: h.label, value: h.value }));
}

export type ConfigFixResult =
  /** The file was understood and at least one header was added. */
  | { status: "edited"; updated: string; applied: string[] }
  /** Understood, but every desired header is already present — nothing to do. */
  | { status: "noop" }
  /** Understood the file type, but can't edit it safely — reason explains why. */
  | { status: "skip"; reason: string };

/** The newline a file already uses, so an edit doesn't flip CRLF↔LF. */
function detectNewline(raw: string): string {
  return raw.includes("\r\n") ? "\r\n" : "\n";
}

/** The indent a JSON/JS file already uses, so re-serialised JSON matches it. */
function detectIndent(raw: string): string | number {
  const tab = /\n\t/.test(raw);
  if (tab) return "\t";
  const m = raw.match(/\n( +)\S/);
  return m ? m[1].length : 2;
}

/** JSON.stringify but preserving the file's indent and trailing newline. */
function serialiseJson(value: unknown, raw: string): string {
  const out = JSON.stringify(value, null, detectIndent(raw));
  const normalised = detectNewline(raw) === "\r\n" ? out.replace(/\n/g, "\r\n") : out;
  return raw.endsWith("\n") || raw.endsWith("\r\n") ? normalised + detectNewline(raw) : normalised;
}

// ---------------------------------------------------------------------------
// Azure Static Web Apps — staticwebapp.config.json's `globalHeaders` is a flat
// { "Header-Name": "value" } object. The safest and clearest file to edit.
// ---------------------------------------------------------------------------
export function editStaticWebAppConfig(raw: string, desired: DesiredHeader[]): ConfigFixResult {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { status: "skip", reason: "staticwebapp.config.json is not valid JSON" };
  }
  const globalHeaders = (parsed.globalHeaders && typeof parsed.globalHeaders === "object" ? { ...(parsed.globalHeaders as Record<string, string>) } : {}) as Record<string, string>;
  const existing = new Set(Object.keys(globalHeaders).map((k) => k.toLowerCase()));
  const applied: string[] = [];
  for (const h of desired) {
    if (existing.has(h.name)) continue;
    globalHeaders[h.label] = h.value;
    applied.push(h.label);
  }
  if (applied.length === 0) return { status: "noop" };
  return { status: "edited", updated: serialiseJson({ ...parsed, globalHeaders }, raw), applied };
}

// ---------------------------------------------------------------------------
// Vercel — vercel.json's `headers` is an array of
// { source, headers: [{ key, value }] }. We merge into the first catch-all
// entry if one exists, else add one.
// ---------------------------------------------------------------------------
type VercelHeaderEntry = { source: string; headers: Array<{ key: string; value: string }> };
const VERCEL_CATCH_ALL = new Set(["/(.*)", "/:path*", "/(.*)/", "/:path*/"]);

export function editVercelJson(raw: string, desired: DesiredHeader[]): ConfigFixResult {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { status: "skip", reason: "vercel.json is not valid JSON" };
  }
  const headers: VercelHeaderEntry[] = Array.isArray(parsed.headers) ? (parsed.headers as VercelHeaderEntry[]).map((e) => ({ source: e.source, headers: [...(e.headers ?? [])] })) : [];
  let entry = headers.find((e) => VERCEL_CATCH_ALL.has(e.source));
  const applied: string[] = [];
  const isNewEntry = !entry;
  if (!entry) entry = { source: "/(.*)", headers: [] };
  const existing = new Set(entry.headers.map((h) => h.key.toLowerCase()));
  for (const h of desired) {
    if (existing.has(h.name)) continue;
    entry.headers.push({ key: h.label, value: h.value });
    applied.push(h.label);
  }
  if (applied.length === 0) return { status: "noop" };
  if (isNewEntry) headers.push(entry);
  return { status: "edited", updated: serialiseJson({ ...parsed, headers }, raw), applied };
}

// ---------------------------------------------------------------------------
// Netlify — netlify.toml uses `[[headers]]` blocks with a `[headers.values]`
// table. Rather than parse TOML, we append one new block for the headers not
// already named anywhere in the file (a conservative duplicate-guard), which
// Netlify merges with any existing block. Appending is always valid TOML.
// ---------------------------------------------------------------------------
export function editNetlifyToml(raw: string, desired: DesiredHeader[]): ConfigFixResult {
  const lower = raw.toLowerCase();
  const toAdd = desired.filter((h) => !lower.includes(h.name));
  if (toAdd.length === 0) return { status: "noop" };
  const nl = detectNewline(raw);
  const block = [
    "",
    "# Added by Hebrides Cyber — security headers missing from the live site.",
    "[[headers]]",
    '  for = "/*"',
    "  [headers.values]",
    ...toAdd.map((h) => `    ${h.label} = "${h.value}"`),
  ].join(nl);
  const base = raw.endsWith(nl) ? raw.slice(0, -nl.length) : raw;
  return { status: "edited", updated: base + nl + block + nl, applied: toAdd.map((h) => h.label) };
}

// ---------------------------------------------------------------------------
// Next.js — next.config.{mjs,js,ts}. This is code, not data, so we only act in
// the confident case: the file has NO existing header handling, and its config
// object is one of the common literal shapes. We inject an `async headers()`
// method at the top of that object. Any other shape, or an existing headers()
// / headers:, is skipped with a reason — we never rewrite someone's config
// logic and risk a broken merge.
// ---------------------------------------------------------------------------
const NEXT_CONFIG_OBJECT_OPENERS = [
  /(\bexport\s+default\s*)\{/, // export default { ... }
  /(\bmodule\.exports\s*=\s*)\{/, // module.exports = { ... }
  /(\b(?:const|let|var)\s+\w+\s*(?::\s*[^=]+)?=\s*)\{/, // const nextConfig = { ... }
];

export function editNextConfig(raw: string, desired: DesiredHeader[]): ConfigFixResult {
  if (desired.length === 0) return { status: "noop" };
  if (/\bheaders\s*(\(|:)/.test(raw)) {
    return { status: "skip", reason: "next.config already defines headers(); add the missing headers there" };
  }
  let match: RegExpMatchArray | null = null;
  for (const re of NEXT_CONFIG_OBJECT_OPENERS) {
    match = raw.match(re);
    if (match && match.index !== undefined) break;
    match = null;
  }
  if (!match || match.index === undefined) {
    return { status: "skip", reason: "could not locate the Next.js config object to edit safely" };
  }
  const nl = detectNewline(raw);
  const insertAt = match.index + match[0].length; // just after the object's opening brace
  const headerList = desired.map((h) => `        { key: "${h.label}", value: "${h.value}" },`).join(nl);
  const block = [
    "",
    "  // Added by Hebrides Cyber — security headers missing from the live site.",
    "  async headers() {",
    "    return [",
    "      {",
    '        source: "/(.*)",',
    "        headers: [",
    headerList,
    "        ],",
    "      },",
    "    ];",
    "  },",
  ].join(nl);
  const updated = raw.slice(0, insertAt) + block + raw.slice(insertAt);
  return { status: "edited", updated, applied: desired.map((h) => h.label) };
}

/** A repo-relative config path and the editor that understands it, in the
 *  priority order the PR route tries them: safe structured data first, the
 *  Next.js code config last. */
export const CONFIG_TARGETS: Array<{ path: string; edit: (raw: string, desired: DesiredHeader[]) => ConfigFixResult }> = [
  { path: "staticwebapp.config.json", edit: editStaticWebAppConfig },
  { path: "vercel.json", edit: editVercelJson },
  { path: "netlify.toml", edit: editNetlifyToml },
  { path: "next.config.mjs", edit: editNextConfig },
  { path: "next.config.js", edit: editNextConfig },
  { path: "next.config.ts", edit: editNextConfig },
];
