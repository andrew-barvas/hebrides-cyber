// Site crawler (E-70). Most checks look only at the page that was scanned, so
// a header gap, a mixed-content image or a stack trace on /login or /checkout
// was invisible. This walks the site breadth-first and runs the page-level
// checks on every page it reaches; crawlFindings.ts turns the per-page
// results into findings.
//
// Safety rules — this runs against customers' production sites:
// - Read-only GETs. Forms are recorded, never submitted. Links that look like
//   logout/delete/unsubscribe/add-to-cart actions are never followed.
// - Same site only (the scanned host, www/apex treated as one). Redirects are
//   followed by hand, up to 3 hops, and only while they stay on the site.
// - robots.txt is honoured (the "*" group, longest match wins). robots.txt
//   that can't be read at all (5xx, network) means "don't crawl": only the
//   start page is visited and the result is "partial".
// - Hard caps: pages, depth, concurrency, per-request timeout and a total
//   time budget; query strings and numeric path segments are normalised so a
//   calendar or an endless /item/N list can't consume the page budget.
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md): the crawl never reports
// "checked" for something it didn't fully look at.
// - Start page unreadable or an error status (a WAF blocking the scanner,
//   say) → "error": nothing was crawled, and an empty result would mark
//   every page finding from the last scan as fixed.
// - Page cap or time budget hit, rate limiting (429/503), many failed
//   requests, or unreadable robots.txt → "partial". findingLifecycle.ts
//   treats "partial" like "error" for resolving findings, so a page the crawl
//   didn't reach this time is not read as a page that got fixed.
import { buildHeaderAnalysis } from "./headers";
import { extractScriptTags, DISCLOSURE_PATTERNS, type ScriptTag } from "./webapp";
import { detectPaymentPage } from "./scriptInventory";

/**
 * Sent on every crawler request so site owners can recognise us in their logs
 * and address us in robots.txt. A group for this token in robots.txt takes
 * precedence over the "*" group.
 */
export const CRAWLER_AGENT_TOKEN = "hebridescyber";
export const CRAWLER_USER_AGENT = `HebridesCyberScanner/1.0 (+https://www.hebridescyber.co.uk/what-we-check)`;

export const CRAWL_LIMITS = {
  maxPages: 50,
  maxDepth: 3,
  concurrency: 4,
  budgetMs: 45_000,
  requestTimeoutMs: 8_000,
  /** Largest HTML body read, in characters. */
  maxBodyChars: 1_000_000,
  maxRedirects: 3,
  maxSitemapUrls: 200,
  /** Pages allowed per URL "shape" (/post/:n), so numbered lists can't flood. */
  maxPerShape: 5,
  maxQueryParams: 3,
};

/** Security headers whose absence on an inner page is reported when the start page sends them. */
export const TRACKED_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
] as const;

export type MixedContentRef = { url: string; active: boolean };
export type CrawlResource = { kind: "script" | "stylesheet"; url: string };

export type PageChecks = {
  /** Tracked security headers absent from this (2xx HTML) page's response. */
  missingHeaders: string[];
  /** Cookies this page sets, with their flag problems (possibly none). */
  cookies: { name: string; issues: string[] }[];
  /** http:// subresources on an https page. */
  mixedContent: MixedContentRef[];
  /** Why a form or password field on this page is sent unencrypted. */
  insecureForms: string[];
  /** Framework error strings in the body of an error (>= 400) page. */
  errorDisclosure: string[];
  /** Cross-origin scripts/stylesheets without a Subresource Integrity hash. */
  unprotectedResources: CrawlResource[];
  /** Third-party-candidate script tags (resolved, deduplicated, capped). */
  scripts: ScriptTag[];
  /** Payment-page evidence on this page (card inputs, checkout forms/address). */
  paymentSignals: string[];
  formCount: number;
};

export type CrawledPage = {
  url: string;
  status: number;
  contentType: string | null;
  title: string | null;
  depth: number;
  /** Absent for pages that weren't analysed (non-HTML, off-site redirect). */
  checks?: PageChecks;
};

export type CrawlResult =
  | {
      status: "checked" | "partial";
      startUrl: string;
      pages: CrawledPage[];
      /** More pages were found than the page cap or time budget allowed. */
      truncated: boolean;
      /** Why the crawl is "partial", when it is. */
      note?: string;
    }
  | { status: "error"; note: string };

// ---- URL handling ---------------------------------------------------------------

const TRACKING_PARAM_RE = /^(?:utm_.*|fbclid|gclid|msclkid|mc_[a-z]+|_ga|ref|sessionid|phpsessid|sid)$/i;
const BINARY_EXT_RE = /\.(?:pdf|zip|gz|tgz|tar|rar|7z|jpe?g|png|gif|svg|webp|ico|avif|bmp|mp[34]|mov|avi|webm|woff2?|ttf|eot|otf|css|js|mjs|map|json|xml|txt|docx?|xlsx?|pptx?|csv|exe|dmg|iso|apk|rss|atom)$/i;
// Links that act rather than navigate. A GET to these can log the user out,
// delete data or empty a cart on a badly-built site, so they are never followed.
const ACTION_URL_RE = /(?:log-?out|sign-?out|log-?off|delete|remove|destroy|unsubscribe|revoke|deactivate|cancel|add[-_]?to[-_]?(?:cart|basket)|empty[-_]?cart|clear[-_]?cart|reset[-_]?password)/i;

// Extra links never followed while signed in: a GET to these can spend money,
// change account state or hand out secrets on a badly-built app.
const AUTH_ACTION_URL_RE = /(?:billing|payment|checkout|purchase|subscribe|upgrade|invite|transfer|api[-_]?keys?|tokens?|secrets?|export|download|impersonate|close[-_]?account|disconnect|confirm|approve|reject)/i;

const hostKey = (host: string) => host.toLowerCase().replace(/^www\./, "");

/** Same site: same host (www and apex are one) and port; http or https. */
export function isSameSite(url: URL, start: URL): boolean {
  return (
    hostKey(url.hostname) === hostKey(start.hostname) &&
    // URL drops a scheme's default port, so http://x:80 and https://x both read "".
    url.port === start.port
  );
}

/**
 * A crawlable absolute URL, or null: strips the fragment and tracking
 * parameters, sorts what's left, and drops the query entirely when it has more
 * than a few parameters (faceted-search and calendar traps).
 */
export function normaliseUrl(raw: string, base: string): URL | null {
  let url: URL;
  try {
    url = new URL(raw.trim(), base);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  url.hash = "";
  url.username = "";
  url.password = "";
  const params = [...url.searchParams.entries()].filter(([k]) => !TRACKING_PARAM_RE.test(k));
  params.sort(([a], [b]) => a.localeCompare(b));
  url.search = "";
  if (params.length > 0 && params.length <= CRAWL_LIMITS.maxQueryParams) {
    for (const [k, v] of params) url.searchParams.append(k, v);
  }
  return url;
}

/** Identity for de-duplication: scheme and www are ignored. */
export function urlKey(url: URL): string {
  return `${hostKey(url.hostname)}${url.port ? `:${url.port}` : ""}${url.pathname}${url.search}`;
}

/** URL "shape" for the per-shape cap: numeric/hex/uuid path segments collapse. */
export function urlShape(url: URL): string {
  const path = url.pathname
    .split("/")
    .map((seg) => (/^\d+$/.test(seg) || /^[0-9a-f]{8,}$/i.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(seg) ? ":x" : seg))
    .join("/");
  const keys = [...url.searchParams.keys()].join("&");
  return keys ? `${path}?${keys}` : path;
}

/** Why a URL must not be fetched, or null. */
export function skipReason(url: URL, authenticated = false): string | null {
  if (BINARY_EXT_RE.test(url.pathname)) return "not a page";
  if (ACTION_URL_RE.test(url.pathname) || ACTION_URL_RE.test(url.search)) return "action link";
  if (authenticated && (AUTH_ACTION_URL_RE.test(url.pathname) || AUTH_ACTION_URL_RE.test(url.search))) return "action link";
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length > 6) return "too deep";
  // /a/b/a/b/a/b — a relative-link loop.
  for (let i = 0; i + 5 < segments.length; i++) {
    if (segments[i] === segments[i + 2] && segments[i + 2] === segments[i + 4] && segments[i + 1] === segments[i + 3]) return "loop";
  }
  return null;
}

// ---- robots.txt -------------------------------------------------------------------

export type RobotsRules = {
  /** May our crawler fetch this path (+ query)? */
  allows: (pathAndQuery: string) => boolean;
  sitemaps: string[];
};

function ruleToRegex(rule: string): RegExp {
  const anchored = rule.endsWith("$");
  const body = (anchored ? rule.slice(0, -1) : rule).replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${body}${anchored ? "$" : ""}`);
}

/**
 * Pure: the Allow/Disallow rules that apply to us — the group naming our
 * agent token if there is one, otherwise the "*" group (longest match wins,
 * Allow on a tie).
 */
export function parseRobots(text: string): RobotsRules {
  const sitemaps: string[] = [];
  type Group = { agents: string[]; rules: { allow: boolean; pattern: string }[] };
  const groups: Group[] = [];
  let current: Group | null = null;
  let lastWasAgent = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (field === "sitemap") {
      if (value) sitemaps.push(value);
    } else if (field === "user-agent") {
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [] };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
      continue;
    } else if ((field === "allow" || field === "disallow") && current) {
      if (value) current.rules.push({ allow: field === "allow", pattern: value });
    }
    lastWasAgent = false;
  }

  const named = groups.filter((g) => g.agents.some((a) => a.startsWith(CRAWLER_AGENT_TOKEN)));
  const rules = (named.length > 0 ? named : groups.filter((g) => g.agents.includes("*"))).flatMap((g) => g.rules);
  const compiled = rules.map((r) => ({ allow: r.allow, length: r.pattern.length, re: ruleToRegex(r.pattern) }));

  return {
    sitemaps,
    allows(pathAndQuery) {
      let best: { allow: boolean; length: number } | null = null;
      for (const r of compiled) {
        if (!r.re.test(pathAndQuery)) continue;
        if (!best || r.length > best.length || (r.length === best.length && r.allow)) best = r;
      }
      return best ? best.allow : true;
    },
  };
}

// ---- HTML reading -------------------------------------------------------------------

/** The captured value of a regex whose alternatives each capture one group. */
const pick = (m: RegExpMatchArray): string => m.slice(1).find((g) => g !== undefined) as string;

const decodeEntities = (s: string) => s.replace(/&amp;/gi, "&").replace(/&#38;/g, "&").replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'");

const LINK_RE = /<(?:a|area)\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
const BASE_RE = /<base\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/i;
const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;
const FORM_RE = /<form\b[^>]*>/gi;
const FORM_ACTION_RE = /\baction\s*=\s*(?:"([^"]*)"|'([^']*)')/i;
const PASSWORD_INPUT_RE = /<input\b[^>]*\btype\s*=\s*["']?password/i;
const SUBRESOURCE_TAG_RE = /<(script|img|iframe|source|audio|video|embed|link)\b[^>]*>/gi;
const SRC_RE = /\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)')/i;
const REL_STYLESHEET_RE = /\brel\s*=\s*["']?[^"'>]*stylesheet/i;
const INTEGRITY_RE = /\bintegrity\s*=\s*["'][^"']+["']/i;

export function extractTitle(html: string): string | null {
  const m = html.match(TITLE_RE)?.[1];
  if (!m) return null;
  const t = decodeEntities(m).replace(/\s+/g, " ").trim();
  return t ? t.slice(0, 120) : null;
}

/** Raw hrefs of every `<a>`/`<area>` (decoded), plus the page's <base href>. */
export function extractLinks(html: string): { base: string | null; hrefs: string[] } {
  const base = html.match(BASE_RE);
  const hrefs: string[] = [];
  for (const m of html.matchAll(LINK_RE)) {
    const href = decodeEntities(pick(m)).trim();
    if (href && !href.startsWith("#") && !/^(?:javascript|mailto|tel|data|sms):/i.test(href)) hrefs.push(href);
  }
  return { base: base ? decodeEntities(pick(base)) : null, hrefs };
}

const MAX_LISTED = 5;

/** Pure: every page-level check on one fetched page. */
export function analysePage(args: { url: URL; status: number; res: Response; html: string }): PageChecks {
  const { url, status, res, html } = args;
  const isHttps = url.protocol === "https:";
  const checks: PageChecks = {
    missingHeaders: [],
    cookies: [],
    mixedContent: [],
    insecureForms: [],
    errorDisclosure: [],
    unprotectedResources: [],
    scripts: [],
    paymentSignals: [],
    formCount: 0,
  };

  // Headers and cookies — only a successful page speaks for the site's own
  // configuration; an error page may come from a proxy or the framework.
  if (status >= 200 && status < 300) {
    const analysis = buildHeaderAnalysis(res);
    const present = new Set(analysis.owasp.headers.filter((h) => h.present).map((h) => h.name));
    // CSP frame-ancestors supersedes X-Frame-Options.
    if (/frame-ancestors/i.test(res.headers.get("content-security-policy") ?? "")) present.add("x-frame-options");
    checks.missingHeaders = TRACKED_HEADERS.filter((h) => !present.has(h) && !(h === "strict-transport-security" && !isHttps));
    checks.cookies = analysis.cookies.map((c) => ({ name: c.name, issues: c.issues }));
  }

  // Mixed content and unprotected third-party resources.
  const seenMixed = new Set<string>();
  for (const m of html.matchAll(SUBRESOURCE_TAG_RE)) {
    const tag = m[0];
    const kind = m[1].toLowerCase();
    if (kind === "link" && !REL_STYLESHEET_RE.test(tag)) continue;
    const raw = tag.match(SRC_RE);
    const ref = raw ? decodeEntities(pick(raw)).trim() : "";
    if (!ref) continue;
    let resolved: URL;
    try {
      resolved = new URL(ref, url);
    } catch {
      continue;
    }
    if (isHttps && resolved.protocol === "http:" && !seenMixed.has(resolved.href) && checks.mixedContent.length < MAX_LISTED) {
      seenMixed.add(resolved.href);
      checks.mixedContent.push({ url: resolved.href, active: kind === "script" || kind === "iframe" || kind === "link" || kind === "embed" });
    }
    const crossOrigin = resolved.origin !== url.origin;
    const resKind = kind === "script" ? "script" : kind === "link" ? "stylesheet" : null;
    if (resKind && crossOrigin && !INTEGRITY_RE.test(tag) && checks.unprotectedResources.length < MAX_LISTED) {
      if (!checks.unprotectedResources.some((r) => r.url === resolved.href)) checks.unprotectedResources.push({ kind: resKind, url: resolved.href });
    }
  }

  // Script tags for the third-party inventory, resolved against this page.
  const seenScripts = new Set<string>();
  for (const tag of extractScriptTags(html)) {
    let resolved: URL;
    try {
      resolved = new URL(decodeEntities(tag.src), url);
    } catch {
      continue;
    }
    if ((resolved.protocol !== "https:" && resolved.protocol !== "http:") || seenScripts.has(resolved.href) || checks.scripts.length >= 40) continue;
    seenScripts.add(resolved.href);
    checks.scripts.push({ src: resolved.href, hasIntegrity: tag.hasIntegrity });
  }
  checks.paymentSignals = detectPaymentPage(html, url.href, []).signals;

  // Forms: recorded, never submitted.
  const forms = html.match(FORM_RE) ?? [];
  checks.formCount = forms.length;
  for (const tag of forms) {
    const m = tag.match(FORM_ACTION_RE);
    const action = m ? decodeEntities(pick(m)).trim() : "";
    if (!action) continue;
    try {
      const target = new URL(action, url);
      if (isHttps && target.protocol === "http:") checks.insecureForms.push(`a form posts to ${target.origin}${target.pathname} over unencrypted HTTP`);
    } catch {
      // unparseable action — nothing to evidence
    }
  }
  if (!isHttps && PASSWORD_INPUT_RE.test(html)) checks.insecureForms.push("a password field is on a page served over unencrypted HTTP");
  checks.insecureForms = [...new Set(checks.insecureForms)].slice(0, MAX_LISTED);

  // Error disclosure — only on real error pages (404/5xx), where a framework's
  // own error output is evidence. Matching the same patterns on a 200 page
  // would flag blog posts that quote a stack trace.
  if (status >= 400) {
    checks.errorDisclosure = DISCLOSURE_PATTERNS.filter(({ re }) => re.test(html)).map(({ label }) => label);
  }

  return checks;
}

// ---- Fetching ----------------------------------------------------------------------

type Fetched =
  | { kind: "page"; page: CrawledPage; html: string | null; finalUrl: URL }
  | { kind: "failed" }
  /** Redirected to a page the crawl already has. */
  | { kind: "duplicate" };

async function fetchPage(start: URL, first: URL, depth: number, seenKeys: Set<string>, extraHeaders: Record<string, string> = {}): Promise<Fetched> {
  let url = first;
  for (let hop = 0; hop <= CRAWL_LIMITS.maxRedirects; hop++) {
    let res: Response;
    try {
      res = await fetch(url.href, {
        redirect: "manual",
        signal: AbortSignal.timeout(CRAWL_LIMITS.requestTimeoutMs),
        // Only same-site URLs are ever fetched (redirects off-site are recorded, not followed),
        // so a credential in extraHeaders never leaves the target.
        headers: { accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", "user-agent": CRAWLER_USER_AGENT, ...extraHeaders },
      });
    } catch {
      return { kind: "failed" };
    }

    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      await res.body?.cancel();
      const next = normaliseUrl(location, url.href);
      if (!next || !isSameSite(next, start)) {
        // Leaves the site: recorded, not followed.
        return { kind: "page", page: { url: url.href, status: res.status, contentType: null, title: null, depth }, html: null, finalUrl: url };
      }
      // http→https or apex→www keeps the same key; a different path
      // (/ → /home) must not be crawled twice.
      const key = urlKey(next);
      if (key !== urlKey(url)) {
        if (seenKeys.has(key)) return { kind: "duplicate" };
        seenKeys.add(key);
      }
      url = next;
      continue;
    }

    const contentType = res.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? null;
    const isHtml = contentType === "text/html" || contentType === "application/xhtml+xml";
    if (!isHtml) {
      await res.body?.cancel();
      return { kind: "page", page: { url: url.href, status: res.status, contentType, title: null, depth }, html: null, finalUrl: url };
    }

    let html: string;
    try {
      html = (await res.text()).slice(0, CRAWL_LIMITS.maxBodyChars);
    } catch {
      return { kind: "failed" };
    }
    const page: CrawledPage = { url: url.href, status: res.status, contentType, title: extractTitle(html), depth };
    page.checks = analysePage({ url, status: res.status, res, html });
    return { kind: "page", page, html, finalUrl: url };
  }
  return { kind: "failed" }; // redirect loop
}

async function fetchText(url: string, maxChars: number): Promise<{ status: number; text: string } | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(CRAWL_LIMITS.requestTimeoutMs), redirect: "follow", headers: { "user-agent": CRAWLER_USER_AGENT } });
    const text = res.ok ? (await res.text()).slice(0, maxChars) : "";
    if (!res.ok) await res.body?.cancel();
    return { status: res.status, text };
  } catch {
    return null;
  }
}

const LOC_RE = /<loc>\s*([^<]+?)\s*<\/loc>/gi;

/** Page URLs listed in a sitemap (one level of sitemap index followed). */
async function readSitemaps(start: URL, sitemapUrls: string[]): Promise<URL[]> {
  const out: URL[] = [];
  const queue = sitemapUrls.slice(0, 3);
  let fetched = 0;
  while (queue.length > 0 && fetched < 4 && out.length < CRAWL_LIMITS.maxSitemapUrls) {
    const sm = queue.shift() as string;
    fetched++;
    const body = await fetchText(sm, 2_000_000);
    if (!body || body.status >= 400) continue;
    const locs = [...body.text.matchAll(LOC_RE)].map((m) => decodeEntities(m[1]));
    if (/<sitemapindex/i.test(body.text)) {
      for (const loc of locs.slice(0, 3)) {
        const u = normaliseUrl(loc, sm);
        if (u && isSameSite(u, start)) queue.push(u.href);
      }
      continue;
    }
    for (const loc of locs) {
      const u = normaliseUrl(loc, sm);
      if (u && isSameSite(u, start)) out.push(u);
      if (out.length >= CRAWL_LIMITS.maxSitemapUrls) break;
    }
  }
  return out;
}

// ---- Next.js route discovery ------------------------------------------------------
// A Next.js (pages router) site lists every page in /_next/static/<buildId>/_buildManifest.js
// as `sortedPages:["/","/about",...]`, including pages nothing links to. Reading it
// finds routes the link crawl can't. Static routes only: dynamic segments ("/post/[id]"),
// Next internals ("/_app") and API routes have no page to check.

const NEXT_MANIFEST_RE = /src\s*=\s*["']([^"']*\/_next\/static\/[A-Za-z0-9_-]{4,64}\/_buildManifest\.js)["']/;
// A list of quoted strings: a route like "/blog/[slug]" contains "]" so the list can't end at the first one.
const SORTED_PAGES_RE = /sortedPages\s*:\s*\[((?:\s*"(?:[^"\\]|\\.)*"\s*,?)*)\s*\]/;

/** The build manifest URL named in a page's HTML, if it is a same-site Next.js page. */
export function nextBuildManifestUrl(html: string, page: URL, start: URL): URL | null {
  const m = NEXT_MANIFEST_RE.exec(html);
  if (!m) return null;
  const url = normaliseUrl(m[1], page.href);
  return url && isSameSite(url, start) ? url : null;
}

/** Static page routes from a build manifest's `sortedPages` list. */
export function parseNextPages(js: string): string[] {
  const list = SORTED_PAGES_RE.exec(js)?.[1];
  if (!list) return [];
  const routes: string[] = [];
  for (const m of list.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    const route = m[1];
    if (!route.startsWith("/") || route === "/" || route.includes("[") || route.startsWith("/_") || route.startsWith("/api/") || route === "/404" || route === "/500") continue;
    routes.push(route);
    if (routes.length >= CRAWL_LIMITS.maxSitemapUrls) break;
  }
  return routes;
}

async function readNextRoutes(start: URL, html: string, page: URL): Promise<URL[]> {
  const manifest = nextBuildManifestUrl(html, page, start);
  if (!manifest) return [];
  const body = await fetchText(manifest.href, 500_000);
  if (!body || body.status >= 400) return [];
  return parseNextPages(body.text)
    .map((route) => normaliseUrl(route, start.origin))
    .filter((u): u is URL => u !== null);
}

function resolveBase(base: string | null, page: URL): string {
  try {
    return base ? new URL(base, page).href : page.href;
  } catch {
    return page.href;
  }
}

// ---- Crawl ---------------------------------------------------------------------------

export type CrawlOptions = {
  /** Same-site paths to seed at depth 1 (e.g. Wayback URLs that still resolve). */
  seedPaths?: string[];
  maxPages?: number;
  maxDepth?: number;
  concurrency?: number;
  budgetMs?: number;
  /**
   * Credential headers (Cookie / Authorization) sent with every page request to
   * the target. Switches on the stricter signed-in link rules (AUTH_ACTION_URL_RE).
   * robots.txt and sitemaps are always fetched anonymously.
   */
  credentialHeaders?: Record<string, string>;
  /**
   * Visit the start page plus exactly these URLs, and nothing else: no links,
   * sitemaps or seeds are followed. Every safety rule (same site, robots.txt,
   * action links, per-shape cap, page cap) still applies. Used to run the page
   * checks on URLs another discoverer (katana) found.
   */
  onlyUrls?: string[];
};

/** The action-link pattern, for tools that crawl on their own (katana's -cos). */
export const ACTION_URL_PATTERN = `(?i)${ACTION_URL_RE.source}`;

export async function checkCrawl(targetUrl: string, options: CrawlOptions = {}): Promise<CrawlResult> {
  const maxPages = options.maxPages ?? CRAWL_LIMITS.maxPages;
  const fixedList = options.onlyUrls !== undefined;
  const maxDepth = fixedList ? 1 : (options.maxDepth ?? CRAWL_LIMITS.maxDepth);
  const concurrency = options.concurrency ?? CRAWL_LIMITS.concurrency;
  const budgetMs = options.budgetMs ?? CRAWL_LIMITS.budgetMs;
  const deadline = Date.now() + budgetMs;

  const parsedStart = normaliseUrl(targetUrl, targetUrl);
  if (!parsedStart) return { status: "error", note: "The target is not a valid web address." };
  const startUrl: URL = parsedStart;

  const notes: string[] = [];
  const credentialHeaders = options.credentialHeaders ?? {};
  const authenticated = Object.keys(credentialHeaders).length > 0;

  // robots.txt first: it decides whether we may go beyond the start page.
  let rules: RobotsRules = { allows: () => true, sitemaps: [] };
  let robotsUnreadable = false;
  const robots = await fetchText(`${startUrl.origin}/robots.txt`, 200_000);
  if (!robots || robots.status >= 500) {
    robotsUnreadable = true;
    notes.push("robots.txt couldn't be read, so only the start page was visited.");
  } else if (robots.status < 400) {
    rules = parseRobots(robots.text);
  }

  const seenKeys = new Set<string>([urlKey(startUrl)]);
  const shapeCounts = new Map<string, number>([[urlShape(startUrl), 1]]);
  const queue: { url: URL; depth: number }[] = [];

  const enqueue = (candidate: URL | null, depth: number): void => {
    if (!candidate || depth > maxDepth || !isSameSite(candidate, startUrl)) return;
    const key = urlKey(candidate);
    if (seenKeys.has(key) || skipReason(candidate, authenticated) || !rules.allows(candidate.pathname + candidate.search)) return;
    const shape = urlShape(candidate);
    if ((shapeCounts.get(shape) ?? 0) >= CRAWL_LIMITS.maxPerShape) return;
    seenKeys.add(key);
    shapeCounts.set(shape, (shapeCounts.get(shape) ?? 0) + 1);
    queue.push({ url: candidate, depth });
  };

  // Start page: if it can't be read as the site's page, nothing else is trustworthy.
  const first = await fetchPage(startUrl, startUrl, 0, seenKeys, credentialHeaders);
  if (first.kind !== "page") return { status: "error", note: "The start page couldn't be fetched, so the site wasn't crawled." };
  if (first.page.status >= 400) {
    return { status: "error", note: `The start page returned HTTP ${first.page.status} (a firewall may be blocking the scanner), so the site wasn't crawled.` };
  }

  const results: (CrawledPage | undefined)[] = [first.page];
  let throttled = false;
  let failures = 0;
  let attempted = 1;

  if (!robotsUnreadable && fixedList) {
    for (const u of options.onlyUrls ?? []) enqueue(normaliseUrl(u, startUrl.origin), 1);
  } else if (!robotsUnreadable) {
    if (first.html) {
      const { base, hrefs } = extractLinks(first.html);
      for (const href of hrefs) enqueue(normaliseUrl(href, resolveBase(base, first.finalUrl)), 1);
    }
    const sitemapUrls = rules.sitemaps.length > 0 ? rules.sitemaps : [`${startUrl.origin}/sitemap.xml`];
    for (const u of await readSitemaps(startUrl, sitemapUrls)) enqueue(u, 1);
    if (first.html) for (const u of await readNextRoutes(startUrl, first.html, first.finalUrl)) enqueue(u, 1);
    for (const p of options.seedPaths ?? []) enqueue(normaliseUrl(p, startUrl.origin), 1);
  }

  let cursor = 0;
  let inFlight = 0;
  async function worker(): Promise<void> {
    while (true) {
      if (Date.now() >= deadline || results.length >= maxPages) return;
      const item = queue[cursor];
      if (!item) {
        // Queue momentarily empty: a page still being fetched may add links.
        if (inFlight === 0) return;
        await new Promise((resolve) => setTimeout(resolve, 5));
        continue;
      }
      cursor++;
      const slot = results.length;
      results.push(undefined);
      attempted++;
      inFlight++;
      try {
        const fetched = await fetchPage(startUrl, item.url, item.depth, seenKeys, credentialHeaders);
        if (fetched.kind === "duplicate") {
          attempted--;
          continue;
        }
        if (fetched.kind === "failed") {
          failures++;
          continue;
        }
        if (fetched.page.status === 429 || fetched.page.status === 503) throttled = true;
        results[slot] = fetched.page;
        if (fetched.html && fetched.page.status < 400 && item.depth < maxDepth) {
          const { base, hrefs } = extractLinks(fetched.html);
          const baseHref = resolveBase(base, fetched.finalUrl);
          for (const href of hrefs) enqueue(normaliseUrl(href, baseHref), item.depth + 1);
        }
      } finally {
        inFlight--;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, () => worker()));

  const pages = results.filter((p): p is CrawledPage => p !== undefined);
  const truncated = cursor < queue.length;
  const timedOut = Date.now() >= deadline && truncated;
  if (truncated) {
    notes.push(timedOut ? "The crawl's time budget ran out before every page was visited." : `The crawl stopped at its ${maxPages}-page limit; more pages exist.`);
  }
  if (throttled) notes.push("The site rate-limited the crawler (HTTP 429/503), so some pages weren't read.");
  if (failures > 0 && failures / attempted > 0.3) notes.push(`${failures} of ${attempted} page requests failed.`);

  return {
    status: notes.length > 0 ? "partial" : "checked",
    startUrl: first.finalUrl.href,
    pages,
    truncated,
    ...(notes.length > 0 ? { note: notes.join(" ") } : {}),
  };
}
