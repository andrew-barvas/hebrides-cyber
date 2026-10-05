// Third-party script inventory — PCI DSS v4.0.1 requirements 6.4.3 (every
// script on a payment page inventoried, authorised and justified) and
// 11.6.1 (unauthorised changes to those scripts detected).
//
// Lists every external origin the scanned page loads JavaScript from, from
// two sources:
// - the raw HTML's <script src> tags (webapp.ts's extractScriptTags, so both
//   checks read tags the same way), which also says which tags carry a
//   Subresource Integrity hash;
// - what the headless browser saw (playwright.ts's `scripts`): every script
//   the page's main frame requested, and every <script src> element in the
//   settled DOM. Tag managers inject most third-party scripts at runtime,
//   where the HTML can't show them.
//
// Same-origin scripts and those on the site's own registrable domain
// (registrableDomain.ts: cdn.example.co.uk on www.example.co.uk) are first
// party and not listed.
//
// Evidence discipline:
// - Neither source readable → "error", never an empty "checked": an empty
//   list would mark every origin from the last scan as removed.
// - HTML only (the browser failed) → "partial". Scripts added at runtime may
//   be missing, so an origin absent from a partial inventory is not evidence
//   it was removed; findingLifecycle.ts treats "partial" like "error" for
//   resolving findings.
// - A page that loaded with an error status is not the page, so neither
//   source counts.
//
// The finding per origin (`script-inventory.unreviewed:<origin>`, built in
// summariseResults) stays open while the origin is present. Customers
// authorise an origin by accepting that finding with a justification; the
// New/Fixed comparison between scans (findingsDiff.ts) is the change signal.
import { extractScriptTags } from "./webapp";
import { registrableDomain, isWithinDomain } from "./registrableDomain";
import type { PlaywrightResult, RuntimeScripts } from "./playwright";
import type { CrawlResult } from "./crawler";

export const MAX_ORIGINS = 50;
export const MAX_SAMPLE_URLS = 5;
const MAX_URL_LENGTH = 300;
const MAX_PAYMENT_SIGNALS = 5;
const PAGE_FETCH_TIMEOUT_MS = 10_000;

/** Over the script tags seen for an origin: all / some / none carry an
 *  integrity attribute; "unknown" when its scripts were only seen as network
 *  requests (loaded by another script, no tag to inspect). */
export type ScriptIntegrity = "all" | "some" | "none" | "unknown";
export type ScriptFoundBy = "html" | "runtime" | "both";

export type ScriptOrigin = {
  origin: string;
  /** Up to MAX_SAMPLE_URLS of its script URLs, sorted. */
  sampleUrls: string[];
  /** Distinct script URLs seen from this origin. */
  scriptCount: number;
  integrity: ScriptIntegrity;
  foundBy: ScriptFoundBy;
  /** Set when the origin is a known payment provider's script host. */
  paymentProvider?: string;
  /** Crawled pages with payment signals that load this origin (paths, up to 3). */
  paymentPages?: string[];
};

export type PaymentPageSignals = {
  /** Any signal at all. */
  detected: boolean;
  /** Human-readable evidence, e.g. `Stripe script from js.stripe.com`. */
  signals: string[];
};

export type ScriptInventoryResult =
  | {
      /** "checked": the browser saw the page. "partial": only the raw HTML
       *  could be read, so runtime-injected scripts may be missing. */
      status: "checked" | "partial";
      pageUrl: string;
      /** Third-party origins, sorted, at most MAX_ORIGINS. */
      origins: ScriptOrigin[];
      totalOrigins: number;
      truncated: boolean;
      /** Which sources were read. */
      sources: { html: boolean; runtime: boolean };
      paymentPage: PaymentPageSignals;
      /** What was missing this scan, when something was. */
      note?: string;
    }
  | { status: "error"; note: string };

// ---- Payment-page heuristics -------------------------------------------------
//
// Evidence-based only: each signal is something concrete in the page, named
// in the finding so the customer can judge it.
// 1. A payment provider's script host (below) — Stripe.js, PayPal's JS SDK,
//    Square's Web Payments SDK and similar.
// 2. A card input in the HTML: autocomplete="cc-number"/"cc-csc"/"cc-exp…",
//    or a name/id like "cardnumber", "card_number", "cc-num", "cvv", "cvc".
// 3. A form whose action points at a checkout or payment endpoint.
// 4. The scanned address itself is a /checkout, /payment or /pay page.
// Card fields rendered client-side by a single-page app aren't in the HTML;
// on such sites the provider-script signal is the one that fires.

type PaymentSdk = { provider: string; matches: (url: URL) => boolean };

const PAYMENT_SDKS: PaymentSdk[] = [
  { provider: "Stripe", matches: (u) => u.hostname === "js.stripe.com" },
  {
    provider: "PayPal",
    matches: (u) =>
      ((u.hostname === "www.paypal.com" || u.hostname === "www.sandbox.paypal.com") && u.pathname.startsWith("/sdk/js")) ||
      u.hostname === "www.paypalobjects.com",
  },
  {
    provider: "Square",
    matches: (u) => isWithinDomain(u.hostname, "squarecdn.com") || isWithinDomain(u.hostname, "squareup.com") || isWithinDomain(u.hostname, "squareupsandbox.com"),
  },
  { provider: "Braintree", matches: (u) => u.hostname === "js.braintreegateway.com" },
  { provider: "Adyen", matches: (u) => /^checkoutshopper-[a-z0-9-]+\.adyen\.com$/.test(u.hostname) },
  { provider: "Checkout.com", matches: (u) => u.hostname === "cdn.checkout.com" },
  { provider: "Authorize.Net", matches: (u) => u.hostname === "js.authorize.net" || u.hostname === "jstest.authorize.net" },
  { provider: "Mollie", matches: (u) => u.hostname === "js.mollie.com" },
  { provider: "Google Pay", matches: (u) => u.hostname === "pay.google.com" },
  { provider: "Klarna", matches: (u) => u.hostname === "js.klarna.com" || isWithinDomain(u.hostname, "klarnacdn.net") },
];

export function paymentProviderFor(url: URL): string | undefined {
  return PAYMENT_SDKS.find((sdk) => sdk.matches(url))?.provider;
}

const INPUT_TAG_RE = /<input\b[^>]*>/gi;
const FORM_TAG_RE = /<form\b[^>]*>/gi;
const AUTOCOMPLETE_ATTR_RE = /\bautocomplete=["']([^"']*)["']/i;
const NAME_ATTR_RE = /\sname=["']([^"']*)["']/i;
const ID_ATTR_RE = /\sid=["']([^"']*)["']/i;
const ACTION_ATTR_RE = /\baction=["']([^"']*)["']/i;
const CARD_AUTOCOMPLETE_RE = /\bcc-(?:number|csc|exp(?:-month|-year)?)\b/i;
const CARD_FIELD_NAME_RE = /card[-_]?num|cc[-_]?num|credit[-_]?card|\bcvv2?\b|\bcvc\b|card[-_]?(?:cvv|cvc)/i;
const CHECKOUT_ACTION_RE = /checkout|payment|\/pay(?:[/?#]|$)|webscr/i;
const CHECKOUT_PATH_RE = /\/(?:checkout|payment|pay)(?:[/?#]|$)/i;

const clip = (s: string, max: number) => (s.length > max ? `${s.slice(0, max)}…` : s);

/** Pure: payment-page signals from the HTML (may be null), the page URL and
 *  the inventory's third-party origins. */
export function detectPaymentPage(html: string | null, pageUrl: string, origins: ScriptOrigin[]): PaymentPageSignals {
  const signals: string[] = [];

  for (const entry of origins) {
    if (entry.paymentProvider) signals.push(`${entry.paymentProvider} script from ${new URL(entry.origin).host}`);
  }

  if (html) {
    for (const tag of html.match(INPUT_TAG_RE) ?? []) {
      const autocomplete = tag.match(AUTOCOMPLETE_ATTR_RE)?.[1] ?? "";
      if (CARD_AUTOCOMPLETE_RE.test(autocomplete)) {
        signals.push(`a card input field (autocomplete="${clip(autocomplete, 40)}")`);
        break;
      }
      const name = tag.match(NAME_ATTR_RE)?.[1] ?? tag.match(ID_ATTR_RE)?.[1] ?? "";
      if (CARD_FIELD_NAME_RE.test(name)) {
        signals.push(`a card input field named "${clip(name, 40)}"`);
        break;
      }
    }
    for (const tag of html.match(FORM_TAG_RE) ?? []) {
      const action = tag.match(ACTION_ATTR_RE)?.[1] ?? "";
      if (CHECKOUT_ACTION_RE.test(action)) {
        signals.push(`a form that submits to "${clip(action, 80)}"`);
        break;
      }
    }
  }

  try {
    const path = new URL(pageUrl).pathname;
    if (CHECKOUT_PATH_RE.test(path)) signals.push(`the page address (${clip(path, 80)})`);
  } catch {
    // unparseable page URL — no signal
  }

  const capped = signals.slice(0, MAX_PAYMENT_SIGNALS);
  return { detected: capped.length > 0, signals: capped };
}

// ---- Inventory ---------------------------------------------------------------

/** Pure: is `url` first party for a page reached via `pageUrls` (the scanned
 *  URL and wherever it redirected)? */
export function firstPartyMatcher(pageUrls: string[]): (url: URL) => boolean {
  const origins = new Set<string>();
  const domains = new Set<string>();
  for (const raw of pageUrls) {
    try {
      const u = new URL(raw);
      origins.add(u.origin);
      domains.add(registrableDomain(u.hostname) ?? u.hostname.toLowerCase());
    } catch {
      // not a URL — contributes nothing
    }
  }
  return (url) => origins.has(url.origin) || [...domains].some((d) => isWithinDomain(url.hostname, d));
}

type Accumulator = {
  urls: Set<string>;
  html: boolean;
  runtime: boolean;
  /** "<url>|<hasIntegrity>" per distinct tag seen. */
  tags: Set<string>;
  paymentProvider?: string;
  paymentPages: Set<string>;
};

export type InventoryInput = {
  /** The URL the scan was asked to check. */
  targetUrl: string;
  /** The raw HTML and the URL it was served from (after redirects), or null
   *  if it couldn't be read. */
  html: { body: string; url: string } | null;
  /** What the browser saw, or null if it couldn't load the page. */
  runtime: { finalUrl: string; scripts: RuntimeScripts } | null;
  /** Other pages of the site (from the crawler), already resolved to absolute
   *  script URLs, with any payment-page evidence found on each. */
  crawledPages?: { url: string; scripts: { src: string; hasIntegrity: boolean }[]; paymentSignals: string[] }[];
};

/** Pure: the inventory from whatever sources were read. */
export function buildScriptInventory(input: InventoryInput): ScriptInventoryResult {
  const { targetUrl, html, runtime } = input;
  if (!html && !runtime) {
    return { status: "error", note: "Neither the page's HTML nor the headless browser could load the page, so its scripts couldn't be listed this scan." };
  }

  const pageUrl = runtime?.finalUrl ?? html?.url ?? targetUrl;
  const isFirstParty = firstPartyMatcher([targetUrl, html?.url ?? "", runtime?.finalUrl ?? ""].filter(Boolean));
  const byOrigin = new Map<string, Accumulator>();

  function record(raw: string, base: string, source: "html" | "runtime", integrity: boolean | null, paymentPage?: string) {
    let url: URL;
    try {
      url = new URL(raw, base);
    } catch {
      return;
    }
    if ((url.protocol !== "https:" && url.protocol !== "http:") || isFirstParty(url)) return;
    let entry = byOrigin.get(url.origin);
    if (!entry) {
      entry = { urls: new Set(), html: false, runtime: false, tags: new Set(), paymentPages: new Set() };
      byOrigin.set(url.origin, entry);
    }
    entry.urls.add(url.href);
    entry[source] = true;
    entry.paymentProvider ??= paymentProviderFor(url);
    if (integrity !== null) entry.tags.add(`${url.href}|${integrity}`);
    if (paymentPage) entry.paymentPages.add(paymentPage);
  }

  if (html) {
    for (const tag of extractScriptTags(html.body)) record(tag.src, html.url, "html", tag.hasIntegrity);
  }
  if (runtime) {
    for (const el of runtime.scripts.elements) record(el.src, runtime.finalUrl, "runtime", el.integrity);
    for (const url of runtime.scripts.requested) record(url, runtime.finalUrl, "runtime", null);
  }

  for (const page of input.crawledPages ?? []) {
    let path = page.url;
    try {
      const u = new URL(page.url);
      path = `${u.pathname}${u.search}`.slice(0, 80);
    } catch {
      // keep the raw string
    }
    for (const tag of page.scripts) record(tag.src, page.url, "html", tag.hasIntegrity, page.paymentSignals.length > 0 ? path : undefined);
  }

  const all: ScriptOrigin[] = [...byOrigin.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([origin, entry]) => {
      const tags = [...entry.tags];
      const withIntegrity = tags.filter((t) => t.endsWith("|true")).length;
      const integrity: ScriptIntegrity =
        tags.length === 0 ? "unknown" : withIntegrity === tags.length ? "all" : withIntegrity === 0 ? "none" : "some";
      return {
        origin,
        sampleUrls: [...entry.urls].sort().slice(0, MAX_SAMPLE_URLS).map((u) => clip(u, MAX_URL_LENGTH)),
        scriptCount: entry.urls.size,
        integrity,
        foundBy: entry.html && entry.runtime ? "both" : entry.html ? "html" : "runtime",
        ...(entry.paymentProvider ? { paymentProvider: entry.paymentProvider } : {}),
        ...(entry.paymentPages.size > 0 ? { paymentPages: [...entry.paymentPages].sort().slice(0, 3) } : {}),
      };
    });

  const origins = all.slice(0, MAX_ORIGINS);
  const notes: string[] = [];
  if (!runtime) {
    notes.push("The headless browser couldn't load the page this scan, so only scripts written into the page's HTML are listed — scripts added at runtime (by a tag manager, for example) may be missing.");
  }
  if (!html) {
    notes.push("The page's HTML couldn't be fetched directly, so scripts are listed from what the headless browser loaded, and card fields weren't looked for in the HTML.");
  }
  if (all.length > MAX_ORIGINS) notes.push(`This page loads scripts from ${all.length} third-party origins; the first ${MAX_ORIGINS} alphabetically are listed.`);

  return {
    status: runtime ? "checked" : "partial",
    pageUrl,
    origins,
    totalOrigins: all.length,
    truncated: all.length > MAX_ORIGINS,
    sources: { html: html !== null, runtime: runtime !== null },
    paymentPage: detectPaymentPage(html?.body ?? null, pageUrl, all),
    ...(notes.length > 0 ? { note: notes.join(" ") } : {}),
  };
}

/** What the browser saw, if it saw the real page. An error page's scripts
 *  aren't the site's, and scans stored before runtime capture have none. */
export function runtimeCapture(playwright: PlaywrightResult): InventoryInput["runtime"] {
  if (playwright.status !== "checked" || !playwright.loadedOk || !playwright.scripts) return null;
  return { finalUrl: playwright.finalUrl, scripts: playwright.scripts };
}

async function fetchHtml(targetUrl: string): Promise<InventoryInput["html"]> {
  try {
    const res = await fetch(targetUrl, { signal: AbortSignal.timeout(PAGE_FETCH_TIMEOUT_MS) });
    if (!res.ok) return null;
    return { body: await res.text(), url: res.url || targetUrl };
  } catch {
    return null;
  }
}

/** Crawled pages whose scripts count toward the inventory: pages after the
 *  start page that returned a real (non-error) page. A "partial" or missing
 *  crawl just contributes fewer pages. */
export function crawledPagesForInventory(crawl: CrawlResult | undefined): InventoryInput["crawledPages"] {
  if (!crawl || (crawl.status !== "checked" && crawl.status !== "partial")) return [];
  return crawl.pages
    .slice(1)
    .filter((p) => p.checks && p.status >= 200 && p.status < 300)
    .map((p) => ({ url: p.url, scripts: p.checks!.scripts, paymentSignals: p.checks!.paymentSignals }));
}

export async function checkScriptInventory(targetUrl: string, playwright: PlaywrightResult, crawl?: CrawlResult): Promise<ScriptInventoryResult> {
  const html = await fetchHtml(targetUrl);
  return buildScriptInventory({ targetUrl, html, runtime: runtimeCapture(playwright), crawledPages: crawledPagesForInventory(crawl) });
}

// ---- Finding text helpers ------------------------------------------------------

export function foundByPhrase(foundBy: ScriptFoundBy): string {
  if (foundBy === "both") return "written into the page's HTML and loaded by the browser";
  if (foundBy === "html") return "written into the page's HTML";
  return "added while the page ran — another script, such as a tag manager, loaded it";
}

export function integrityPhrase(integrity: ScriptIntegrity): string {
  switch (integrity) {
    case "all":
      return "Every script tag loading from it carries a Subresource Integrity hash, so the browser refuses a modified file.";
    case "some":
      return "Some, but not all, of the script tags loading from it carry a Subresource Integrity hash.";
    case "none":
      return "None of the script tags loading from it carry a Subresource Integrity hash, so the browser runs whatever that server sends.";
    default:
      return "Its scripts were loaded without a script tag we could inspect, so whether they are integrity-checked is unknown.";
  }
}
