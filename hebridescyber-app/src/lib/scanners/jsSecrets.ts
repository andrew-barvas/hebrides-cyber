// Live-site JavaScript secret / endpoint scanning (base suite, passive).
//
// Reads only what any visitor's browser already receives — the page's HTML and
// its same-origin script bodies — and looks for two things nothing else in the
// suite covers:
//   1. high-confidence API keys/tokens shipped to the client (AWS, Google,
//      Stripe, Slack, SendGrid, GitHub, …);
//   2. internal/API endpoints hard-coded into the frontend.
//
// What this deliberately does NOT do (owned elsewhere — never double-report):
//   - Supabase project URLs / anon+service keys, and the tables/buckets behind
//     them — backendExposure.ts;
//   - Firebase config and its RTDB/Storage/Firestore — firebaseExposure.ts;
//   - JWTs the target issues — jwtAnalysis.ts (extended);
//   - framework signing keys (Rails, ASP.NET ViewState, …) — badsecrets.ts.
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md):
// - A false "secret" is worse than a miss, so only high-confidence provider
//   prefixes are flagged — each pattern matches a shape legitimate code doesn't
//   coincidentally produce. Low-confidence/generic "secret"-named variables are
//   NOT flagged.
// - The matched value is never stored raw: findings carry a redacted preview
//   plus a SHA-256 fingerprint (same precedent as jwtAnalysis.ts/badsecrets.ts),
//   so a rotation shows as a change without the key ever landing in the DB.
// - Fetch failure → "error"; no scripts/HTML to read → "not_applicable".
// - Every outbound request carries AbortSignal.timeout().

import { createHash } from "node:crypto";
import type { Finding } from "./index";
import { extractScriptTags } from "./webapp";
import * as FIX from "./remediationText";

export type JsSecretProvider =
  | "aws-access-key"
  | "google-api-key"
  | "stripe-secret-key"
  | "slack-token"
  | "sendgrid-key"
  | "github-token"
  | "openai-key"
  | "mailgun-key"
  | "twilio-key"
  | "private-key-block";

export type JsSecretHit = {
  provider: JsSecretProvider;
  /** Redacted preview — first/last few chars only, never the raw value. */
  preview: string;
  /** SHA-256 of the matched value (first 12 hex) — a rotation changes this. */
  fingerprint: string;
  /** Which source (page URL or script URL) it was found in. */
  foundIn: string;
};

export type JsEndpointHit = {
  /** The host of the discovered internal/API URL. */
  host: string;
  /** Redacted sample URL. */
  sample: string;
};

export type JsSecretsResult =
  | { status: "checked"; secrets: JsSecretHit[]; endpoints: JsEndpointHit[] }
  | { status: "not_applicable" }
  | { status: "error"; note: string };

const PAGE_TIMEOUT_MS = 10_000;
const SCRIPT_TIMEOUT_MS = 10_000;
const MAX_SCRIPTS = 12;
const MAX_SCRIPT_CHARS = 2_000_000;
const MAX_SECRETS = 20;
const MAX_ENDPOINTS = 15;

type Source = { label: string; text: string };

type SecretPattern = {
  provider: JsSecretProvider;
  re: RegExp;
  severity: Finding["severity"];
  /** Human label for the finding title. */
  label: string;
};

// Each pattern is a shape legitimate code doesn't produce by accident. Severity
// is by blast radius: a live secret key that grants account access is critical;
// a browser-API key meant to be public but worth noting is low/medium.
const SECRET_PATTERNS: SecretPattern[] = [
  // AWS long-term access key id. AKIA/ASIA + 16 base32 chars.
  { provider: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "high", label: "AWS access key ID" },
  // Google API key. AIza + 35 url-safe chars.
  { provider: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "medium", label: "Google API key" },
  // Stripe LIVE secret/restricted key — never belongs in client code.
  { provider: "stripe-secret-key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b/g, severity: "critical", label: "Stripe live secret key" },
  // Slack token (bot/user/legacy/app).
  { provider: "slack-token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: "high", label: "Slack token" },
  // SendGrid API key.
  { provider: "sendgrid-key", re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/g, severity: "high", label: "SendGrid API key" },
  // GitHub personal-access / app / OAuth tokens.
  { provider: "github-token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g, severity: "high", label: "GitHub token" },
  // OpenAI secret key.
  { provider: "openai-key", re: /\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}\b/g, severity: "high", label: "OpenAI API key" },
  // Mailgun key.
  { provider: "mailgun-key", re: /\bkey-[0-9a-f]{32}\b/g, severity: "medium", label: "Mailgun API key" },
  // Twilio Account SID + a live key marker.
  { provider: "twilio-key", re: /\bSK[0-9a-f]{32}\b/g, severity: "high", label: "Twilio API key" },
  // A private-key PEM block in client code — always wrong.
  { provider: "private-key-block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: "critical", label: "Private key block" },
];

// Internal/API endpoints hard-coded in the frontend. Only hosts that read as
// internal or API surfaces — never ordinary CDNs/analytics (those are
// scriptInventory.ts's job and would be noise here).
const ENDPOINT_RE = /https?:\/\/((?:api|internal|admin|staging|dev|test|gateway|backend|svc|service)[0-9a-z._-]*\.[a-z0-9.-]+\.[a-z]{2,})(?:[/:?][^\s"'`<>]*)?/gi;
// Private/RFC1918/localhost hosts referenced from the client are also worth noting.
const PRIVATE_HOST_RE = /https?:\/\/((?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?)/gi;

/** First/last chars only — enough to recognise, never the whole value. */
export function redact(value: string): string {
  const flat = value.replace(/\s+/g, "");
  if (flat.length <= 10) return `${flat.slice(0, 2)}…`;
  return `${flat.slice(0, 6)}…${flat.slice(-4)}`;
}

/** SHA-256 of the value, first 12 hex — a rotation changes it; the raw value is never stored. */
export function secretFingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

/**
 * Pure: every high-confidence secret and internal endpoint in the given
 * sources. Supabase/Firebase/JWT material is skipped — those are owned by
 * backendExposure.ts / firebaseExposure.ts / jwtAnalysis.ts, so a shared value
 * (e.g. a Supabase anon JWT, which also looks like `eyJ…`) is never
 * double-reported here. De-duplicated by (provider, fingerprint).
 */
export function discoverJsSecrets(sources: Source[]): { secrets: JsSecretHit[]; endpoints: JsEndpointHit[] } {
  const secrets = new Map<string, JsSecretHit>();
  const endpoints = new Map<string, JsEndpointHit>();

  for (const { label, text } of sources) {
    for (const pattern of SECRET_PATTERNS) {
      pattern.re.lastIndex = 0;
      for (const m of text.matchAll(pattern.re)) {
        const value = m[0];
        const fingerprint = secretFingerprint(value);
        const key = `${pattern.provider}:${fingerprint}`;
        if (!secrets.has(key)) {
          secrets.set(key, { provider: pattern.provider, preview: redact(value), fingerprint, foundIn: label });
        }
      }
    }
    for (const re of [ENDPOINT_RE, PRIVATE_HOST_RE]) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        const host = m[1].toLowerCase();
        if (!endpoints.has(host)) endpoints.set(host, { host, sample: m[0].slice(0, 120) });
      }
    }
  }

  return {
    secrets: [...secrets.values()].slice(0, MAX_SECRETS),
    endpoints: [...endpoints.values()].slice(0, MAX_ENDPOINTS),
  };
}

const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;

async function fetchText(url: string, timeoutMs: number, maxChars: number): Promise<{ ok: boolean; status: number; text: string }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: "follow" });
  const text = res.ok ? (await res.text()).slice(0, maxChars) : "";
  if (!res.ok) await res.body?.cancel();
  return { ok: res.ok, status: res.status, text };
}

export async function checkJsSecrets(targetUrl: string): Promise<JsSecretsResult> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return { status: "error", note: "The target is not a valid web address." };
  }

  let page: { ok: boolean; status: number; text: string };
  try {
    page = await fetchText(targetUrl, PAGE_TIMEOUT_MS, MAX_SCRIPT_CHARS);
  } catch (err) {
    return { status: "error", note: `Could not read the page: ${(err as Error).message}` };
  }
  if (!page.ok) return { status: "error", note: `The page returned HTTP ${page.status}, so its scripts were not read.` };

  // HTML plus up to MAX_SCRIPTS same-origin script bodies — the same bounded
  // loop backendExposure.ts uses (SRI protects a third party, not the site's
  // own origin; secrets we care about are in the site's own code).
  const sources: Source[] = [{ label: targetUrl, text: page.text }];
  const scriptUrls: string[] = [];
  for (const tag of extractScriptTags(page.text)) {
    try {
      const u = new URL(tag.src, targetUrl);
      if (u.origin === origin && !scriptUrls.includes(u.href)) scriptUrls.push(u.href);
    } catch {
      // not a URL
    }
  }
  // Also pick up inline <script src>-less bodies via the raw HTML (already in
  // sources[0]) and any additional same-origin srcs the HTML names.
  for (const m of page.text.matchAll(SCRIPT_SRC_RE)) {
    try {
      const u = new URL(m[1], targetUrl);
      if (u.origin === origin && !scriptUrls.includes(u.href)) scriptUrls.push(u.href);
    } catch {
      // not a URL
    }
  }

  if (scriptUrls.length === 0 && page.text.trim().length === 0) return { status: "not_applicable" };

  for (const url of scriptUrls.slice(0, MAX_SCRIPTS)) {
    try {
      const s = await fetchText(url, SCRIPT_TIMEOUT_MS, MAX_SCRIPT_CHARS);
      if (s.ok) sources.push({ label: url, text: s.text });
    } catch {
      // a script we couldn't read just contributes nothing
    }
  }

  const { secrets, endpoints } = discoverJsSecrets(sources);
  if (secrets.length === 0 && endpoints.length === 0) {
    // We read the page and scripts and found nothing high-confidence — a
    // genuine, evidenced clean result for this check.
    return { status: "checked", secrets: [], endpoints: [] };
  }
  return { status: "checked", secrets, endpoints };
}

const SECRET_LABELS: Record<JsSecretProvider, { label: string; severity: Finding["severity"] }> = Object.fromEntries(
  SECRET_PATTERNS.map((p) => [p.provider, { label: p.label, severity: p.severity }])
) as Record<JsSecretProvider, { label: string; severity: Finding["severity"] }>;

/** Pure: findings from a JsSecretsResult. */
export function buildJsSecretsFindings(result: JsSecretsResult | undefined): Finding[] {
  if (!result || result.status !== "checked") return [];
  const findings: Finding[] = [];
  for (const s of result.secrets) {
    const meta = SECRET_LABELS[s.provider];
    findings.push({
      checkId: `js-secrets.exposed-key:${s.provider}`,
      severity: meta.severity,
      title: `${meta.label} exposed in client-side code`,
      detail: `A string matching a ${meta.label} (${s.preview}, fingerprint ${s.fingerprint}) is delivered to every visitor in ${s.foundIn}. Anything shipped to the browser is public — a live secret key here must be treated as compromised and rotated. We matched a pattern and store only a fingerprint, never the value, so confirm it is a real credential before acting.`,
      remediation: FIX.JS_SECRET_EXPOSED,
    });
  }
  for (const e of result.endpoints) {
    findings.push({
      checkId: `js-secrets.exposed-endpoint:${e.host}`,
      severity: "info",
      title: `Internal or API endpoint referenced in client-side code: ${e.host}`,
      detail: `The frontend references ${e.sample}. Internal, staging or admin endpoints hard-coded into client code tell an attacker where to look next, and private/localhost hosts suggest a debug build shipped to production. Confirm this endpoint is meant to be publicly known.`,
      remediation: FIX.JS_ENDPOINT_EXPOSED,
    });
  }
  return findings;
}
