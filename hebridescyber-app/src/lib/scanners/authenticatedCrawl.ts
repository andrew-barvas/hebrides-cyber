// Signed-in crawl: the E-70 crawler run with the target's saved session cookie
// or Basic Auth credential (target_auth_credentials), so pages behind the login
// wall get the same page-level checks as public ones.
//
// Safety rules (docs/AUTHENTICATED-CRAWL.md):
// - Read-only: the crawler only ever issues GETs, and while signed in it also
//   skips links that can spend money or change account state (crawler.ts
//   AUTH_ACTION_URL_RE) on top of the logout/delete rules it always has.
// - The credential is only sent to the target's own host (the crawler never
//   follows a redirect off-site) and is never stored in or echoed by a result.
// - Evidence discipline: if the credential is not accepted (401/403, or the
//   start page lands on a login page) the result is "error", never an empty
//   "checked" — a crawl of the login page says nothing about the app behind it.
// - Results are namespaced `crawl.auth.*` so signed-in and anonymous findings
//   never merge or resolve each other.
import { checkCrawl, type CrawlResult } from "./crawler";
import { buildCrawlFindings } from "./crawlFindings";
import type { Finding } from "./index";

export type CrawlCredential = { type: "cookie"; cookieValue: string } | { type: "basic"; username: string; password: string };

const LOGIN_PATH_RE = /\/(?:log-?in|sign-?in|sso|auth(?:enticate)?|session|account\/login)(?:[/.?]|$)/i;

export function credentialHeaders(credential: CrawlCredential): Record<string, string> {
  if (credential.type === "cookie") return { Cookie: credential.cookieValue };
  return { Authorization: `Basic ${Buffer.from(`${credential.username}:${credential.password}`).toString("base64")}` };
}

/** Did the start request end on a login page it did not ask for? */
export function landedOnLoginWall(requested: string, finalUrl: string): boolean {
  const asked = new URL(requested);
  const landed = new URL(finalUrl);
  return landed.pathname !== asked.pathname && LOGIN_PATH_RE.test(landed.pathname) && !LOGIN_PATH_RE.test(asked.pathname);
}

export async function checkAuthenticatedCrawl(targetUrl: string, credential: CrawlCredential, options: { maxPages?: number; budgetMs?: number } = {}): Promise<CrawlResult> {
  const crawl = await checkCrawl(targetUrl, { ...options, credentialHeaders: credentialHeaders(credential) });
  if (crawl.status === "error") {
    return { status: "error", note: `Signed-in crawl could not run: ${crawl.note}` };
  }
  if (landedOnLoginWall(targetUrl, crawl.startUrl)) {
    return { status: "error", note: "The saved credential was not accepted (the site redirected to its login page), so the signed-in pages were not crawled. Reconnect it in Account settings." };
  }
  return crawl;
}

/** Findings for a signed-in crawl, in the crawl.auth.* namespace. */
export function buildAuthenticatedCrawlFindings(crawl: CrawlResult | undefined): Finding[] {
  return buildCrawlFindings(crawl, { includeStart: true }).map((f) => ({
    ...f,
    checkId: f.checkId?.replace(/^crawl\./, "crawl.auth."),
    title: `${f.title} (signed in)`,
  }));
}
