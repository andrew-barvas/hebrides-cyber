// HTTP security headers scanner.
// Checks the full OWASP Secure Headers Project list, parses CSP for
// dangerous directives, analyses cookie flags, and flags CORS wildcards
// and information-disclosure headers.
import { buildHttpEvidence, SECURITY_HEADERS, type FindingEvidence } from "../findingEvidence";

export type HeadersResult =
  | {
      status: "checked";
      /** The response the analysis judged (redacted security headers, no body, no cookies). Absent on scans before 2026-10-31. */
      evidence?: FindingEvidence;
      httpStatus: number;
      owasp: OwaspHeaderAnalysis;
      csp: CspAnalysis;
      cookies: CookieAnalysis[];
      cors: CorsAnalysis;
      infoDisclosure: InfoDisclosureAnalysis;
      smugglingSurface: SmugglingSurfaceAnalysis;
    }
  | { status: "error"; note: string };

// ---- OWASP Secure Headers Project checklist --------------------------------

type OwaspHeader = {
  name: string;
  present: boolean;
  value: string | null;
  recommendation?: string;
};

type OwaspHeaderAnalysis = {
  headers: OwaspHeader[];
  missingCount: number;
  score: number; // 0-100 based on headers present
};

const OWASP_HEADERS: Array<{ name: string; recommendation: string }> = [
  { name: "strict-transport-security", recommendation: "max-age=31536000; includeSubDomains; preload" },
  { name: "content-security-policy", recommendation: "Define explicit allow-lists; avoid 'unsafe-inline'/'unsafe-eval'" },
  { name: "x-frame-options", recommendation: "DENY (or SAMEORIGIN if framing needed on same origin)" },
  { name: "x-content-type-options", recommendation: "nosniff" },
  { name: "referrer-policy", recommendation: "strict-origin-when-cross-origin" },
  { name: "permissions-policy", recommendation: "Disable unused features: camera=(), microphone=(), geolocation=()" },
  { name: "cross-origin-embedder-policy", recommendation: "require-corp" },
  { name: "cross-origin-opener-policy", recommendation: "same-origin" },
  { name: "cross-origin-resource-policy", recommendation: "same-origin" },
  { name: "cache-control", recommendation: "no-store for authenticated pages" },
];

// ---- CSP parser ------------------------------------------------------------

type CspAnalysis = {
  present: boolean;
  value: string | null;
  issues: string[];
  grade: "A" | "B" | "C" | "F";
};

// Parse a policy into directive → source-expression tokens. Per CSP, a
// repeated directive is ignored after its first occurrence, so first wins.
// Directive names are case-insensitive; source expressions (nonces, hashes)
// are not, so only the directive name is lower-cased.
function parseCspDirectives(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1));
  }
  return directives;
}

const HASH_RE = /^'sha(?:256|384|512)-/i;
const NONCE_RE = /^'nonce-/i;

/**
 * Grades a CSP on what actually stops XSS, not a pattern blacklist.
 *
 * Two tiers of weakness, each naming the exact directive/token that triggers
 * it (evidence discipline — never "looks weak"):
 *   - SERIOUS (the policy fails at its primary job of stopping script
 *     injection): 'unsafe-inline' in the effective script directive NOT
 *     mitigated by a nonce/hash/'strict-dynamic' on that same directive (a
 *     modern policy that keeps 'unsafe-inline' only as a fallback for old
 *     browsers is fully credited, since any supporting browser ignores it);
 *     'unsafe-eval'; a wildcard source; a 'data:' script source; or no
 *     script restriction at all.
 *   - GAP (hardening the policy still owes): no base-uri (base-tag injection),
 *     no frame-ancestors (clickjacking), no form-action (form hijacking) —
 *     none of which fall back to default-src — or an object-src that isn't
 *     'none'.
 *
 * Grade: no serious weakness → A (no gaps) / B (1–2 gaps) / C (3+ gaps); any
 * serious weakness → F when there are 2+ of them or 4+ issues total, else C.
 * summariseResults maps F → headers.csp-absent and C → headers.csp-weak, so
 * B and A stay silent.
 */
function analyseCsp(value: string | null): CspAnalysis {
  if (!value) {
    return { present: false, value: null, issues: ["Content-Security-Policy header is missing"], grade: "F" };
  }

  const directives = parseCspDirectives(value);
  const serious: string[] = [];
  const gaps: string[] = [];

  // The directive that governs <script> execution: script-src, else the
  // default-src fallback. object-src/base-uri/etc. are handled separately.
  const scriptSrc = directives.get("script-src");
  const effectiveName = scriptSrc ? "script-src" : directives.has("default-src") ? "default-src" : null;
  const effective = scriptSrc ?? directives.get("default-src");

  if (!effective) {
    serious.push("No default-src or script-src directive — script sources are unrestricted");
  } else {
    const mitigated = effective.some((t) => NONCE_RE.test(t) || HASH_RE.test(t) || t.toLowerCase() === "'strict-dynamic'");
    if (effective.some((t) => t.toLowerCase() === "'unsafe-inline'") && !mitigated) {
      serious.push(
        `'unsafe-inline' in ${effectiveName} is not mitigated by a nonce, hash or 'strict-dynamic' — inline scripts execute, defeating most XSS protection`
      );
    }
    if (effective.some((t) => t.toLowerCase() === "'unsafe-eval'")) {
      serious.push(`'unsafe-eval' in ${effectiveName} allows eval()-family string-to-code execution`);
    }
    const wildcard = effective.find((t) => t === "*" || t.includes("*"));
    if (wildcard) {
      serious.push(`Wildcard source '${wildcard}' in ${effectiveName} allows scripts from any matching origin`);
    }
    if (effective.some((t) => t.toLowerCase() === "data:")) {
      serious.push(`'data:' scheme in ${effectiveName} can be abused to execute an attacker-controlled script`);
    }
  }

  // object-src: only flagged when explicitly declared as something other than
  // 'none' (an absent object-src is covered by default-src). Matches the old
  // check's intent — a correctly locked-down "object-src 'none'" is silent.
  const objectSrc = directives.get("object-src");
  if (objectSrc && objectSrc[0]?.toLowerCase() !== "'none'") {
    gaps.push(`object-src is '${objectSrc.join(" ") || "(empty)"}' not 'none' — allows <object>/<embed> plugin injection`);
  }

  // These three have no default-src fallback, so absence is a real gap.
  if (!directives.has("base-uri")) {
    gaps.push("No base-uri directive — an injected <base> tag can rewrite where every relative URL (including scripts) resolves to");
  }
  if (!directives.has("frame-ancestors")) {
    gaps.push("No frame-ancestors directive — the page can be framed by any site (clickjacking)");
  }
  if (!directives.has("form-action")) {
    gaps.push("No form-action directive — a form can be pointed at an attacker's endpoint (credential/data hijacking)");
  }

  const s = serious.length;
  const g = gaps.length;
  let grade: CspAnalysis["grade"];
  if (s === 0) {
    grade = g === 0 ? "A" : g <= 2 ? "B" : "C";
  } else {
    grade = s >= 2 || s + g >= 4 ? "F" : "C";
  }

  return { present: true, value, issues: [...serious, ...gaps], grade };
}

// ---- Cookie analysis -------------------------------------------------------

type CookieAnalysis = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  hasHostPrefix: boolean; // __Host- prefix enforces Secure + Path=/
  hasSecurePrefix: boolean; // __Secure- prefix enforces Secure
  issues: string[];
};

// Azure Static Web Apps / App Service set these session-affinity cookies at
// the infrastructure layer. The app cannot configure them, so flagging them
// as insecure would mislead customers about actionable issues. Lowercase,
// compared against the lowercased cookie name — "ARRAffinity" is
// a-r-r-a-f-f…, a single "a" before the "ff".
export const PLATFORM_COOKIES = new Set(["arraffinity", "arraffinitysamesite"]);

function analyseCookies(setCookieHeaders: string[]): CookieAnalysis[] {
  return setCookieHeaders
    .filter((raw) => {
      const cookieName = raw.split(";")[0]?.split("=")[0]?.trim().toLowerCase() ?? "";
      return !PLATFORM_COOKIES.has(cookieName);
    })
    .map((raw) => {
      const parts = raw.split(";").map((p) => p.trim());
      const namePart = parts[0] ?? "";
      const name = namePart.split("=")[0].trim();
      const attrs = parts.slice(1).map((p) => p.toLowerCase());

      const secure = attrs.includes("secure");
      const httpOnly = attrs.includes("httponly");
      const sameSiteAttr = attrs.find((a) => a.startsWith("samesite="));
      const sameSite = sameSiteAttr ? sameSiteAttr.replace("samesite=", "") : null;
      const hasHostPrefix = name.startsWith("__Host-");
      const hasSecurePrefix = name.startsWith("__Secure-");

      const issues: string[] = [];
      if (!secure) issues.push("Missing Secure flag — cookie sent over HTTP");
      if (!httpOnly) issues.push("Missing HttpOnly flag — accessible via document.cookie");
      // SameSite=None; Secure is a valid cross-site cookie per RFC 6265bis —
      // only flag when None is set WITHOUT Secure, or when SameSite is absent entirely.
      if (!sameSite || (sameSite === "none" && !secure)) issues.push("SameSite not set to Strict/Lax — CSRF risk");

      return { name, secure, httpOnly, sameSite, hasHostPrefix, hasSecurePrefix, issues };
    });
}

// ---- CORS analysis ---------------------------------------------------------

type CorsAnalysis = {
  wildcardOrigin: boolean;
  allowCredentialsWithWildcard: boolean;
  value: string | null;
  issues: string[];
};

function analyseCors(acao: string | null, acac: string | null): CorsAnalysis {
  const issues: string[] = [];
  const wildcardOrigin = acao === "*";
  const allowCredentialsWithWildcard = wildcardOrigin && acac?.toLowerCase() === "true";

  if (wildcardOrigin) issues.push("Access-Control-Allow-Origin: * allows any site to read responses");
  if (allowCredentialsWithWildcard) {
    issues.push("Wildcard CORS with credentials — browsers block this but it signals misconfiguration");
  }

  return { wildcardOrigin, allowCredentialsWithWildcard, value: acao, issues };
}

// ---- Information disclosure ------------------------------------------------

type InfoDisclosureAnalysis = {
  serverHeader: string | null;
  poweredByHeader: string | null;
  generatorHeader: string | null;
  issues: string[];
};

function analyseInfoDisclosure(headers: Headers): InfoDisclosureAnalysis {
  const server = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  const generator = headers.get("x-generator");
  const issues: string[] = [];

  if (server && /[\d.]/.test(server)) {
    issues.push(`Server header reveals version: "${server}" — remove or obscure the version string`);
  }
  if (poweredBy) {
    issues.push(`X-Powered-By header reveals tech stack: "${poweredBy}" — remove this header`);
  }
  if (generator) {
    issues.push(`X-Generator header reveals CMS/framework: "${generator}" — remove this header`);
  }

  return { serverHeader: server, poweredByHeader: poweredBy, generatorHeader: generator, issues };
}

// ---- HTTP request smuggling surface ----------------------------------------
//
// Passive signal only — never a raw/malformed request. RFC 7230 §3.3.3 says
// a response (or request) carrying BOTH Content-Length and Transfer-Encoding
// is itself a framing ambiguity a compliant recipient must resolve by
// rejecting the message or ignoring Content-Length; in practice this is
// exactly the condition a front-end/back-end pair disagreeing on message
// length (CL.TE/TE.CL request smuggling) needs to exist somewhere in the
// chain. This observes the single response this module already fetches —
// it proves risk surface, never exploitability, and genuinely probing for a
// real desync would mean sending deliberately ambiguous framing bytes that
// can corrupt a shared front-end/back-end connection pool serving other,
// non-consenting tenants of the same infrastructure — out of scope for any
// profile this product offers (see docs/USER-GUIDE.md §6).

type SmugglingSurfaceAnalysis = {
  contentLength: string | null;
  transferEncoding: string | null;
  issues: string[];
};

function analyseSmugglingSurface(headers: Headers): SmugglingSurfaceAnalysis {
  const contentLength = headers.get("content-length");
  const transferEncoding = headers.get("transfer-encoding");
  const issues: string[] = [];

  if (contentLength !== null && transferEncoding !== null) {
    issues.push(
      `Response carries both Content-Length (${contentLength}) and Transfer-Encoding (${transferEncoding}) — RFC 7230 §3.3.3 treats this as a framing ambiguity, the condition request smuggling (CL.TE/TE.CL) exploits when a front-end and back-end disagree on which header to trust.`
    );
  }

  return { contentLength, transferEncoding, issues };
}

// ---- Main ------------------------------------------------------------------

/**
 * The full header/CSP/cookie/CORS/info-disclosure analysis, given a
 * already-fetched Response. Extracted so src/lib/scanners/authenticatedCheck.ts
 * (Sprint 3's authenticated header/cookie recheck) can run the exact same
 * analysis against a request carrying a customer-supplied session
 * cookie/credential, without duplicating any of this logic — the only thing
 * that differs between an unauthenticated and an authenticated check is
 * which request produced the Response, never how the response is analysed.
 */
export type HeaderAnalysisBundle = {
  httpStatus: number;
  owasp: OwaspHeaderAnalysis;
  csp: CspAnalysis;
  cookies: CookieAnalysis[];
  cors: CorsAnalysis;
  infoDisclosure: InfoDisclosureAnalysis;
  smugglingSurface: SmugglingSurfaceAnalysis;
};

export function buildHeaderAnalysis(res: Response): HeaderAnalysisBundle {
  const owaspHeaders: OwaspHeader[] = OWASP_HEADERS.map(({ name, recommendation }) => ({
    name,
    present: res.headers.has(name),
    value: res.headers.get(name),
    recommendation,
  }));
  const missingCount = owaspHeaders.filter((h) => !h.present).length;
  const score = Math.round(((OWASP_HEADERS.length - missingCount) / OWASP_HEADERS.length) * 100);

  // Collect all Set-Cookie headers — fetch() merges them, so split on comma
  // sequences that look like separate cookies (heuristic: new name= after ;).
  const rawSetCookie = res.headers.get("set-cookie") ?? "";
  const setCookieHeaders = rawSetCookie ? rawSetCookie.split(/,(?=[^;]+=)/) : [];

  return {
    httpStatus: res.status,
    owasp: { headers: owaspHeaders, missingCount, score },
    csp: analyseCsp(res.headers.get("content-security-policy")),
    cookies: analyseCookies(setCookieHeaders),
    cors: analyseCors(res.headers.get("access-control-allow-origin"), res.headers.get("access-control-allow-credentials")),
    infoDisclosure: analyseInfoDisclosure(res.headers),
    smugglingSurface: analyseSmugglingSurface(res.headers),
  };
}

export async function checkHeaders(targetUrl: string): Promise<HeadersResult> {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(10_000) });
    // res.url is the page after redirects, which is the one whose headers were judged.
    const evidence = buildHttpEvidence({ url: res.url || targetUrl, status: res.status, headers: res.headers, extraHeaders: SECURITY_HEADERS });
    return { status: "checked", evidence, ...buildHeaderAnalysis(res) };
  } catch (err) {
    return { status: "error", note: `Header check failed: ${(err as Error).message}` };
  }
}
