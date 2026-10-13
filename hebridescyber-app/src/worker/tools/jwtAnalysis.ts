// JWT (JSON Web Token) security analysis — no external binary, no forging or
// replay. Decodes JSON Web Tokens the target itself issues (in Set-Cookie
// headers, the response body, or the request/response URL) and reports on
// their own header/payload fields. Deliberately stops short of forging a
// token and replaying it against the server to see if it's accepted —
// docs/NEXT-STEPS.md already lists "JWT forging" as an attack, not scanning,
// out of scope for this product. Every check here is either pure decoding
// (a JWT's header and payload are base64url, never encrypted, so reading
// them needs no secret) or a local, offline signature recomputation against
// a short curated list of common weak secrets — zero extra requests sent to
// the target, and never a forged token sent anywhere.
import { createHash, createHmac } from "node:crypto";

export type JwtFinding = {
  type: "none-algorithm" | "no-expiration" | "weak-secret" | "sent-over-http" | "exposed-in-url";
  detail: string;
  url: string;
};

export type JwtAnalysisResult =
  | { status: "completed"; findings: JwtFinding[] }
  | { status: "not_applicable"; findings: []; note: string }
  | { status: "error"; note: string };

const FETCH_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 2_000_000;

// A JWT is three base64url segments joined by dots; the header segment
// always starts "eyJ" (base64 of `{"` ), which keeps this from matching
// arbitrary base64-looking text.
// No trailing \b: the signature segment can be empty (alg:none) or end in a
// non-word character, which fails a trailing boundary when followed by
// punctuation like a closing quote.
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

/**
 * Secrets found, in order, across public "top weak JWT secrets" wordlists
 * (jwt_tool, c-jwt-cracker) and framework tutorial defaults a developer can
 * copy into production without changing — most famously "your-256-bit-secret",
 * jwt.io's own playground default. Naming the matched secret in a finding is
 * remediation information for the target's own owner, not an attack — no
 * request is ever sent anywhere with it.
 */
export const COMMON_WEAK_JWT_SECRETS: readonly string[] = [
  "secret", "Secret", "SECRET", "your-256-bit-secret", "changeme", "change-me",
  "jwt_secret", "jwtsecret", "jwt-secret", "jwtSecret", "mysecretkey", "my-secret-key",
  "secretkey", "secret-key", "super-secret-key", "supersecret", "superSecret",
  "password", "123456", "test", "testsecret", "default", "key", "private-key",
  "signing-key", "signingkey", "shhhh", "qwerty", "admin",
] as const;

type JwtHeader = { alg?: unknown; typ?: unknown };
type JwtPayload = { exp?: unknown; [key: string]: unknown };
type DecodedJwt = { header: JwtHeader; payload: JwtPayload; headerSegment: string; payloadSegment: string; signatureSegment: string };

function base64UrlDecode(segment: string): string {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(segment.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

/** Decodes a JWT's header and payload; returns null for anything that isn't actually a well-formed JWT. */
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  try {
    const header = JSON.parse(base64UrlDecode(headerSegment)) as JwtHeader;
    const payload = JSON.parse(base64UrlDecode(payloadSegment)) as JwtPayload;
    if (typeof header !== "object" || header === null) return null;
    if (typeof payload !== "object" || payload === null) return null;
    return { header, payload, headerSegment, payloadSegment, signatureSegment };
  } catch {
    return null;
  }
}

/** All distinct JWT-shaped strings in a block of text, deduplicated. */
export function extractJwts(text: string): string[] {
  const matches = text.match(JWT_PATTERN) ?? [];
  return [...new Set(matches)];
}

const HMAC_DIGEST_FOR_ALG: Record<string, string> = { hs256: "sha256", hs384: "sha384", hs512: "sha512" };

/** Recomputes the HMAC locally and compares — never sends the candidate anywhere. Null if alg isn't HMAC-based. */
export function findWeakJwtSecret(decoded: DecodedJwt): string | null {
  const alg = typeof decoded.header.alg === "string" ? decoded.header.alg.toLowerCase() : "";
  const digest = HMAC_DIGEST_FOR_ALG[alg];
  if (!digest || !decoded.signatureSegment) return null;
  const signingInput = `${decoded.headerSegment}.${decoded.payloadSegment}`;
  for (const secret of COMMON_WEAK_JWT_SECRETS) {
    const candidate = createHmac(digest, secret).update(signingInput).digest("base64url");
    if (candidate === decoded.signatureSegment) return secret;
  }
  return null;
}

/** A short, non-reversible, per-token identity for the checkId — never the raw token. */
export function jwtFingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 12);
}

function isNoneAlgorithm(decoded: DecodedJwt): boolean {
  const alg = typeof decoded.header.alg === "string" ? decoded.header.alg.toLowerCase() : "";
  return alg === "none" || decoded.signatureSegment === "";
}

function hasNoExpiration(decoded: DecodedJwt): boolean {
  return decoded.payload.exp === undefined;
}

type TokenSighting = { token: string; decoded: DecodedJwt; surfaces: Set<"cookie" | "body" | "url"> };

function collectSightings(cookieValues: string[], body: string, urls: string[]): TokenSighting[] {
  const bySurface: Array<{ surface: "cookie" | "body" | "url"; text: string }> = [
    ...cookieValues.map((text) => ({ surface: "cookie" as const, text })),
    { surface: "body" as const, text: body },
    ...urls.map((text) => ({ surface: "url" as const, text })),
  ];

  const byToken = new Map<string, TokenSighting>();
  for (const { surface, text } of bySurface) {
    for (const token of extractJwts(text)) {
      const existing = byToken.get(token);
      if (existing) {
        existing.surfaces.add(surface);
        continue;
      }
      const decoded = decodeJwt(token);
      if (!decoded) continue; // matched the regex but isn't really a JWT
      byToken.set(token, { token, decoded, surfaces: new Set([surface]) });
    }
  }
  return [...byToken.values()];
}

export function analyseSightings(sightings: TokenSighting[], targetUrl: string): JwtFinding[] {
  const findings: JwtFinding[] = [];
  const isHttps = targetUrl.toLowerCase().startsWith("https://");
  let anyTokenSeen = false;

  for (const { token, decoded, surfaces } of sightings) {
    anyTokenSeen = true;
    const fingerprint = jwtFingerprint(token);
    const url = `${targetUrl}#${fingerprint}`;

    if (isNoneAlgorithm(decoded)) {
      findings.push({
        type: "none-algorithm",
        detail: `A JWT issued by this site (header: ${JSON.stringify(decoded.header)}) uses the "none" algorithm or has no signature at all — anyone can edit its claims without invalidating it.`,
        url,
      });
    }

    if (hasNoExpiration(decoded)) {
      findings.push({
        type: "no-expiration",
        detail: `A JWT issued by this site has no "exp" (expiration) claim, so once issued it never expires and a leaked copy stays valid indefinitely.`,
        url,
      });
    }

    const weakSecret = findWeakJwtSecret(decoded);
    if (weakSecret) {
      findings.push({
        type: "weak-secret",
        detail: `A JWT issued by this site is signed with a common, publicly known weak secret ("${weakSecret}"), found by recomputing its signature locally against a short list of known-weak secrets — no request was sent anywhere. Anyone who finds this secret can forge valid tokens as any user.`,
        url,
      });
    }

    if (surfaces.has("url")) {
      findings.push({
        type: "exposed-in-url",
        detail: `A JWT appears in a URL (query string or path) rather than only a header/cookie. URLs are logged by servers, proxies and browser history, so a token placed there can leak long after the request completes.`,
        url,
      });
    }
  }

  if (anyTokenSeen && !isHttps) {
    findings.push({
      type: "sent-over-http",
      detail: `A JWT was observed on a plain HTTP response from ${targetUrl}. Without TLS, the token travels in clear text and can be captured by anyone on the network path.`,
      url: targetUrl,
    });
  }

  return findings;
}

/** Never throws. No findings is a genuinely clean "completed" result, not an error. */
export async function runJwtAnalysis(targetUrl: string): Promise<JwtAnalysisResult> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { status: "not_applicable", findings: [], note: "Invalid target URL." };
  }

  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    const cookieValues = (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0] ?? "");
    const body = (await res.text()).slice(0, MAX_BODY_BYTES);
    const urls = [parsed.search, parsed.hash, res.url];

    const sightings = collectSightings(cookieValues, body, urls);
    return { status: "completed", findings: analyseSightings(sightings, targetUrl) };
  } catch (err) {
    return { status: "error", note: `JWT analysis failed: ${(err as Error).message}` };
  }
}
