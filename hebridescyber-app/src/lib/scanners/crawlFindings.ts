// Findings from the crawler's per-page results (crawler.ts). Pure.
//
// Aggregation rule: a gap that is the same everywhere is ONE finding that
// lists the affected pages, never one per page — a missing header on 40 pages
// is one thing to fix. Findings that belong to one page get
// `crawl.<check>:<path>`, capped at MAX_PAGE_FINDINGS pages (crawl order).
//
// The start page is left out of the checks the base suite already runs on it
// (headers, cookies, mixed content, SRI) so one problem isn't scored twice;
// headers are reported as a *gap* — sent by the start page, absent on inner
// pages — because when the start page lacks one too, headers.* already says so.
import type { Finding } from "./index";
import type { CrawlResult, CrawledPage } from "./crawler";
import * as FIX from "./remediationText";

export const MAX_PAGE_FINDINGS = 10;
const MAX_LISTED_PAGES = 10;

const HEADER_SEVERITY: Record<string, Finding["severity"]> = {
  "strict-transport-security": "medium",
  "content-security-policy": "medium",
  "x-content-type-options": "medium",
  "x-frame-options": "low",
  "referrer-policy": "low",
};

/** Path + query, shortened — what a finding shows and keys on. */
export function pagePath(url: string): string {
  const u = new URL(url); // crawled URLs are always absolute
  const p = `${u.pathname}${u.search}`;
  return p.length > 120 ? `${p.slice(0, 120)}…` : p;
}

function listPages(pages: CrawledPage[]): string {
  const shown = pages.slice(0, MAX_LISTED_PAGES).map((p) => pagePath(p.url));
  const more = pages.length - shown.length;
  return `${shown.join(", ")}${more > 0 ? ` (and ${more} more)` : ""}`;
}

export function buildCrawlFindings(crawl: CrawlResult | undefined): Finding[] {
  if (!crawl || (crawl.status !== "checked" && crawl.status !== "partial")) return [];
  const findings: Finding[] = [];
  const [start, ...inner] = crawl.pages;
  if (!start) return findings;
  const analysed = inner.filter((p) => p.checks);

  // Headers the start page sends but inner pages don't.
  // The start page must be a 2xx page for "it sends this header" to mean anything.
  if (start.status >= 200 && start.status < 300 && start.checks) {
    for (const header of Object.keys(HEADER_SEVERITY)) {
      if (start.checks.missingHeaders.includes(header)) continue;
      const lacking = analysed.filter((p) => p.status >= 200 && p.status < 300 && p.checks!.missingHeaders.includes(header));
      if (lacking.length === 0) continue;
      findings.push({
        checkId: `crawl.header-gap:${header}`,
        severity: HEADER_SEVERITY[header],
        title: `Security header "${header}" missing on ${lacking.length} page${lacking.length === 1 ? "" : "s"}`,
        detail: `The home page sends ${header}, but ${lacking.length} of the ${inner.length} other pages we visited don't: ${listPages(lacking)}. Visitors landing on those pages aren't protected.`,
        remediation: FIX.crawlHeaderGapRemediation(header),
      });
    }
  }

  // Cookies first set by an inner page (the start page's are checked by headers.*).
  const startCookieNames = new Set((start.checks?.cookies ?? []).map((c) => c.name));
  const cookies = new Map<string, { issues: string[]; pages: CrawledPage[] }>();
  for (const page of analysed) {
    for (const c of page.checks!.cookies) {
      if (startCookieNames.has(c.name) || c.issues.length === 0) continue;
      const entry = cookies.get(c.name) ?? { issues: c.issues, pages: [] };
      entry.pages.push(page);
      cookies.set(c.name, entry);
    }
  }
  for (const [name, { issues, pages }] of cookies) {
    findings.push({
      checkId: `crawl.cookie-flags:${name}`,
      severity: "medium",
      title: `Cookie "${name}" has insecure flags`,
      detail: `${issues.join("; ")}. Set on ${listPages(pages)}.`,
      remediation: FIX.CRAWL_COOKIE_FLAGS,
    });
  }

  // One finding per page, capped.
  const perPage = (
    check: string,
    pick: (p: CrawledPage) => boolean,
    build: (p: CrawledPage) => Omit<Finding, "checkId">,
    pages: CrawledPage[] = crawl.pages
  ) => {
    for (const page of pages.filter(pick).slice(0, MAX_PAGE_FINDINGS)) {
      findings.push({ checkId: `crawl.${check}:${pagePath(page.url)}`, ...build(page) });
    }
  };

  perPage(
    "mixed-content",
    (p) => (p.checks?.mixedContent.length ?? 0) > 0,
    (p) => {
      const refs = p.checks!.mixedContent;
      const active = refs.some((r) => r.active);
      return {
        severity: active ? "high" : "medium",
        title: `Mixed content on ${pagePath(p.url)}`,
        detail: `This HTTPS page loads ${active ? "scripts, styles or frames" : "images or media"} over unencrypted HTTP: ${refs.slice(0, 3).map((r) => r.url).join(", ")}. ${active ? "Browsers block these, so part of the page is broken, and any that load can be tampered with in transit." : "They can be read or replaced by anyone on the network path."}`,
        remediation: FIX.CRAWL_MIXED_CONTENT,
      };
    },
    inner
  );

  perPage(
    "insecure-form",
    (p) => (p.checks?.insecureForms.length ?? 0) > 0,
    (p) => ({
      severity: "high",
      title: `Unencrypted form or password field on ${pagePath(p.url)}`,
      detail: `${p.checks!.insecureForms.join("; ")}. Anything a visitor types here, passwords included, can be read by anyone on the network path.`,
      remediation: FIX.CRAWL_INSECURE_FORM,
    })
  );

  perPage(
    "error-disclosure",
    (p) => (p.checks?.errorDisclosure.length ?? 0) > 0,
    (p) => ({
      severity: "low",
      title: `Error page reveals internal details at ${pagePath(p.url)}`,
      detail: `This page returned HTTP ${p.status} and its body shows: ${p.checks!.errorDisclosure.join("; ")}. Configure custom error pages to avoid information leakage.`,
      remediation: FIX.CRAWL_ERROR_DISCLOSURE,
    })
  );

  // Cross-origin resources without SRI on inner pages, minus what the start
  // page already reports (webapp.missing-sri).
  const startUnprotected = new Set((start.checks?.unprotectedResources ?? []).map((r) => r.url));
  const sri = new Map<string, { kind: "script" | "stylesheet"; pages: CrawledPage[] }>();
  for (const page of analysed) {
    for (const r of page.checks!.unprotectedResources) {
      if (startUnprotected.has(r.url)) continue;
      const entry = sri.get(r.url) ?? { kind: r.kind, pages: [] };
      entry.pages.push(page);
      sri.set(r.url, entry);
    }
  }
  if (sri.size > 0) {
    const entries = [...sri.entries()].slice(0, MAX_LISTED_PAGES);
    const scripts = entries.some(([, e]) => e.kind === "script");
    findings.push({
      checkId: "crawl.missing-sri",
      severity: scripts ? "medium" : "low",
      title: `${sri.size} cross-origin resource${sri.size === 1 ? "" : "s"} on inner pages loaded without Subresource Integrity`,
      detail: `${entries.map(([url, e]) => `${url} (${e.kind}, on ${listPages(e.pages)})`).join("; ")}${sri.size > entries.length ? `; and ${sri.size - entries.length} more` : ""}. If one of those origins is compromised it can serve modified code with no way for the browser to notice.`,
      remediation: FIX.crawlSriRemediation(),
    });
  }

  return findings;
}
