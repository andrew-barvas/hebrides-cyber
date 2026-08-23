// Authenticated header/cookie/CSP/CORS recheck — Sprint 3's "authenticated
// scanning, first slice." Every other check in this scanner suite is
// unauthenticated by necessity (it's scanning a customer's public site, not
// logged into anything); this module is the first one that re-runs part of
// that same passive analysis (buildHeaderAnalysis, exported from headers.ts
// specifically so this doesn't duplicate it) against a request carrying a
// customer-supplied session cookie or Basic Auth credential instead.
//
// DELIBERATELY SCOPED NARROW. This is not a crawl-behind-login engine, does
// not attempt IDOR/access-control testing, and does not handle multi-step
// auth (OAuth flows, MFA, CSRF-token login forms) — it fetches exactly one
// URL with one static credential attached and analyses the response headers/
// cookies the same way the passive suite already does for the logged-out
// page. The real value: a session cookie missing Secure/HttpOnly/SameSite is
// invisible to every other check in this suite, since none of them can ever
// see an authenticated Set-Cookie header in the first place.
//
// Requires a saved target_auth_credentials row (sql/migrations/
// 014_target_auth_credentials.sql, one per monitored_targets row, written
// only by src/pages/api/account/target-auth.ts). Only wired into the
// extended-tool suite (src/lib/scanExecution.ts's runExtendedTools) — same
// scheduled-scan-only scope every other credential-gated check in this
// codebase already has (repo_connections -> secretScan/dependencyManifest/
// dockerBaseImage). No credential connected is a clean "not_applicable"
// result, never an error finding. Never throws, matching every other
// scanner module's contract.
import { buildHeaderAnalysis, type HeaderAnalysisBundle } from "./headers";
import type { Finding } from "./index";
import * as FIX from "./remediationText";

export type AuthCredential =
  | { type: "cookie"; cookieValue: string }
  | { type: "basic"; username: string; password: string };

export type AuthenticatedCheckResult =
  | ({ status: "checked" } & HeaderAnalysisBundle)
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string };

const REQUEST_TIMEOUT_MS = 10_000;

function credentialHeaders(credential: AuthCredential): Record<string, string> {
  if (credential.type === "cookie") return { Cookie: credential.cookieValue };
  return { Authorization: `Basic ${Buffer.from(`${credential.username}:${credential.password}`).toString("base64")}` };
}

export async function checkAuthenticated(targetUrl: string, credential: AuthCredential | null): Promise<AuthenticatedCheckResult> {
  if (!credential) {
    return { status: "not_applicable", note: "No authentication credential connected for this target — see Account settings." };
  }

  try {
    const res = await fetch(targetUrl, {
      headers: credentialHeaders(credential),
      redirect: "follow",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    return { status: "checked", ...buildHeaderAnalysis(res) };
  } catch (err) {
    return { status: "error", note: `Authenticated header check failed: ${(err as Error).message}` };
  }
}

/**
 * Finding derivation, kept separate from src/lib/scanners/index.ts's
 * summariseResults() since this only ever runs inside runExtendedTools()
 * (scanExecution.ts), not the base suite. Every checkId is prefixed
 * "auth-check." so it's never confused with the identical-looking
 * unauthenticated "headers.*" findings this same analysis produces for the
 * logged-out page — the two describe genuinely different responses.
 *
 * Session cookie issues are the one place this deliberately grades more
 * severely than headers.ts's own analyseCookies would: a cookie observed
 * only after supplying real credentials is far more likely to be the actual
 * session identifier than any cookie set on the public, logged-out page.
 */
export function buildAuthenticatedFindings(result: AuthenticatedCheckResult): Finding[] {
  if (result.status !== "checked") return [];

  const findings: Finding[] = [];

  // Remediation is reused verbatim from remediationText.ts rather than
  // written fresh here — the fix for "add HSTS" or "set Secure/HttpOnly on
  // this cookie" is identical whether the header was observed on the public
  // page or the authenticated one; only which request surfaced it differs,
  // and that's already covered by the detail text.
  const missing = result.owasp.headers.filter((h) => !h.present).map((h) => h.name);
  if (missing.length > 0) {
    findings.push({
      checkId: "auth-check.missing-headers",
      severity: "medium",
      title: `Missing security headers on the authenticated page (${missing.length})`,
      detail: `${missing.join(", ")} — checked against a request using your saved authentication credential, not the public logged-out page.`,
      remediation: FIX.headerRemediation(missing),
    });
  }

  if (result.csp.grade === "F") {
    findings.push({
      checkId: "auth-check.csp-absent",
      severity: "high",
      title: "Content Security Policy absent on the authenticated page",
      detail: result.csp.issues.join("; "),
      remediation: FIX.CSP_MISSING,
    });
  }

  for (const cookie of result.cookies) {
    if (cookie.issues.length > 0) {
      findings.push({
        checkId: `auth-check.session-cookie-insecure:${cookie.name}`,
        severity: "high",
        title: `Cookie "${cookie.name}" set after authentication has insecure flags`,
        detail: `${cookie.issues.join("; ")} This cookie was only observed after authenticating, so it is more likely to be a real session identifier than anything visible on the logged-out page.`,
        remediation: FIX.COOKIE_FLAGS,
      });
    }
  }

  if (result.cors.wildcardOrigin) {
    findings.push({
      checkId: "auth-check.cors-wildcard",
      severity: "critical",
      title: "CORS wildcard origin on an authenticated response",
      detail: "Access-Control-Allow-Origin: * on a response returned to an authenticated request means any site can potentially read authenticated data.",
      remediation: FIX.CORS_WILDCARD,
    });
  }

  return findings;
}
