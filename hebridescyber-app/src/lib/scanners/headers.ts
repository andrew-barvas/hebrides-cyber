// HTTP security headers scanner.
// Checks the full OWASP Secure Headers Project list, parses CSP for
// dangerous directives, analyses cookie flags, and flags CORS wildcards
// and information-disclosure headers.
export type HeadersResult =
  | {
      status: "checked";
      httpStatus: number;
      owasp: OwaspHeaderAnalysis;
      csp: CspAnalysis;
      cookies: CookieAnalysis[];
      cors: CorsAnalysis;
      infoDisclosure: InfoDisclosureAnalysis;
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

const DANGEROUS_CSP_PATTERNS: Array<{ pattern: RegExp; issue: string }> = [
  { pattern: /'unsafe-inline'/i, issue: "'unsafe-inline' allows inline scripts/styles — XSS risk" },
  { pattern: /'unsafe-eval'/i, issue: "'unsafe-eval' allows eval() — code injection risk" },
  { pattern: /script-src[^;]*\*/i, issue: "Wildcard (*) in script-src allows scripts from any origin" },
  { pattern: /default-src[^;]*\*/i, issue: "Wildcard (*) in default-src negates most CSP protections" },
  { pattern: /script-src[^;]*data:/i, issue: "'data:' URIs in script-src can be abused for XSS" },
  { pattern: /object-src[^;']*(?!none)/i, issue: "Missing object-src 'none' allows Flash/plugin injection" },
];

function analyseCsp(value: string | null): CspAnalysis {
  if (!value) {
    return { present: false, value: null, issues: ["Content-Security-Policy header is missing"], grade: "F" };
  }
  const issues: string[] = [];
  for (const { pattern, issue } of DANGEROUS_CSP_PATTERNS) {
    if (pattern.test(value)) issues.push(issue);
  }
  if (!value.includes("default-src") && !value.includes("script-src")) {
    issues.push("No default-src or script-src directive — scripts are unrestricted");
  }
  const grade: CspAnalysis["grade"] = issues.length === 0 ? "A" : issues.length <= 1 ? "B" : issues.length <= 3 ? "C" : "F";
  return { present: true, value, issues, grade };
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

function analyseCookies(setCookieHeaders: string[]): CookieAnalysis[] {
  return setCookieHeaders.map((raw) => {
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
    if (!sameSite || sameSite === "none") issues.push("SameSite not set to Strict/Lax — CSRF risk");

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
  };
}

export async function checkHeaders(targetUrl: string): Promise<HeadersResult> {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(10_000) });
    return { status: "checked", ...buildHeaderAnalysis(res) };
  } catch (err) {
    return { status: "error", note: `Header check failed: ${(err as Error).message}` };
  }
}
