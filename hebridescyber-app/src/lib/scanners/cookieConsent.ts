// Cookie-consent / tracker-before-consent check (base suite, passive) —
// PECR (UK Privacy and Electronic Communications Regulations) and GDPR.
//
// UK/EU SMBs and the agencies managing their sites are directly liable for
// analytics/marketing cookies set, or tracker requests fired, *before* the
// visitor consents. The single most common compliance finding for small
// business sites is "Google Analytics installed, no cookie banner at all".
//
// What this does (MVP, deliberately conservative):
//   Reads what the headless browser already saw on the initial page load with
//   NO consent interaction — (a) the cookies present, (b) the third-party
//   script origins — and flags ONLY high-confidence cases: a known-tracker
//   cookie or a request to a known-tracker host, fired with NO consent-
//   management platform (CMP) detected anywhere on the page.
//
// What this deliberately does NOT do: drive the consent banner to prove
// pre-consent firing. A page that loads a CMP (OneTrust, Cookiebot, …) is NOT
// flagged — we can't prove the tracker fired before the banner was answered
// without interacting with it, and a false "you're breaking GDPR" is
// expensive. That stronger check is a larger follow-up (see the PR).
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md):
// - not_applicable when no trackers are seen at all (nothing to consent to).
// - partial/error when the headless browser didn't run — findingLifecycle.ts
//   treats both as "not run" (like scriptInventory.ts), so a tracker isn't
//   marked "fixed" just because the browser failed this scan.
// - A page WITH a CMP produces no findings — present but silent, not an error.
import { ownerDomain, isWithinDomain } from "./registrableDomain";
import type { PlaywrightResult } from "./playwright";

export type TrackerEvidence =
  | { kind: "cookie"; name: string; detail: string }
  | { kind: "request"; host: string; detail: string };

export type CookieConsentResult =
  | {
      status: "checked";
      /** The known trackers observed firing with no CMP present. */
      trackers: TrackerEvidence[];
      /** A consent-management platform was detected on the page. When true,
       *  trackers is empty by construction — a CMP page is never flagged. */
      cmpDetected: boolean;
      /** The CMP vendor, when one was identified. */
      cmpVendor?: string;
    }
  | { status: "not_applicable"; note: string }
  | { status: "partial" | "error"; note: string };

// ---- Known-tracker signals ---------------------------------------------------
//
// Each entry is high-confidence: a cookie name or a host that only a specific
// analytics/marketing tracker sets. Deliberately a curated short-list, not an
// exhaustive blocklist — a false "tracker" would mean a false GDPR finding.

/** Cookie-name patterns a known tracker sets. Anchored/specific so an app's
 *  own `_gauge` or `fb_state` cookie doesn't match a GA/Meta pattern. */
export const TRACKER_COOKIE_PATTERNS: Array<{ re: RegExp; tracker: string }> = [
  { re: /^_ga$/, tracker: "Google Analytics" },
  { re: /^_ga_[A-Z0-9]+$/, tracker: "Google Analytics 4" },
  { re: /^_gid$/, tracker: "Google Analytics" },
  { re: /^_gat(?:_[A-Za-z0-9]+)?$/, tracker: "Google Analytics" },
  { re: /^__utm[abctz]$/, tracker: "Google Analytics (Urchin)" },
  { re: /^_gcl_(?:au|aw|dc)$/, tracker: "Google Ads conversion" },
  { re: /^_fbp$/, tracker: "Meta Pixel" },
  { re: /^_fbc$/, tracker: "Meta Pixel" },
  { re: /^fr$/, tracker: "Meta (Facebook) advertising" },
  { re: /^_hj[A-Za-z]+/, tracker: "Hotjar" },
  { re: /^_tt_enable_cookie$/, tracker: "TikTok Pixel" },
  { re: /^_ttp$/, tracker: "TikTok Pixel" },
  { re: /^_pin_unauth$/, tracker: "Pinterest Tag" },
  { re: /^_scid$/, tracker: "Snapchat Pixel" },
  { re: /^MUID$/, tracker: "Microsoft/Bing advertising" },
  { re: /^_uetsid$/, tracker: "Microsoft Advertising (UET)" },
  { re: /^_uetvid$/, tracker: "Microsoft Advertising (UET)" },
  { re: /^IDE$/, tracker: "Google DoubleClick advertising" },
  { re: /^test_cookie$/, tracker: "Google DoubleClick advertising" },
  { re: /^_clck$/, tracker: "Microsoft Clarity" },
  { re: /^_clsk$/, tracker: "Microsoft Clarity" },
];

/** Hostnames (matched by registrable domain) a known tracker loads from. */
export const TRACKER_HOSTS: Array<{ domain: string; tracker: string }> = [
  { domain: "google-analytics.com", tracker: "Google Analytics" },
  { domain: "googletagmanager.com", tracker: "Google Tag Manager" },
  { domain: "doubleclick.net", tracker: "Google DoubleClick advertising" },
  { domain: "googleadservices.com", tracker: "Google Ads" },
  { domain: "connect.facebook.net", tracker: "Meta Pixel" },
  { domain: "facebook.com", tracker: "Meta (Facebook)" },
  { domain: "analytics.tiktok.com", tracker: "TikTok Pixel" },
  { domain: "static.hotjar.com", tracker: "Hotjar" },
  { domain: "script.hotjar.com", tracker: "Hotjar" },
  { domain: "clarity.ms", tracker: "Microsoft Clarity" },
  { domain: "bat.bing.com", tracker: "Microsoft Advertising (UET)" },
  { domain: "snap.licdn.com", tracker: "LinkedIn Insight" },
  { domain: "sc-static.net", tracker: "Snapchat Pixel" },
  { domain: "ct.pinterest.com", tracker: "Pinterest Tag" },
  { domain: "cdn.mxpnl.com", tracker: "Mixpanel" },
  { domain: "cdn.segment.com", tracker: "Segment" },
];

// ---- Consent-management platform (CMP) signals --------------------------------
//
// Any marker — a CMP's script host, or a CMP global/DOM marker in the HTML —
// means a banner exists, so we stay silent (see module header). Matching the
// host OR the HTML marker is enough; both reduce false "no banner" claims.

/** Hostnames (by registrable domain) a known CMP loads its banner from. */
export const CMP_HOSTS: Array<{ domain: string; vendor: string }> = [
  { domain: "cookiebot.com", vendor: "Cookiebot" },
  { domain: "cookielaw.org", vendor: "OneTrust" },
  { domain: "onetrust.com", vendor: "OneTrust" },
  { domain: "osano.com", vendor: "Osano" },
  { domain: "cookieyes.com", vendor: "CookieYes" },
  { domain: "termly.io", vendor: "Termly" },
  { domain: "iubenda.com", vendor: "Iubenda" },
  { domain: "civiccomputing.com", vendor: "Civic Cookie Control" },
  { domain: "cookie-script.com", vendor: "CookieScript" },
  { domain: "usercentrics.eu", vendor: "Usercentrics" },
  { domain: "quantcast.mgr.consensu.org", vendor: "Quantcast Choice" },
  { domain: "klaro.org", vendor: "Klaro" },
  { domain: "complianz.io", vendor: "Complianz" },
];

/** Markers in the page HTML that a CMP is present (globals, container ids,
 *  class names a CMP injects). Case-insensitive. */
export const CMP_HTML_MARKERS: Array<{ re: RegExp; vendor: string }> = [
  { re: /\bCookiebot\b/, vendor: "Cookiebot" },
  { re: /\bOneTrust\b|optanon|onetrust-/i, vendor: "OneTrust" },
  { re: /\bOsano\b/, vendor: "Osano" },
  { re: /\bcookieyes\b/i, vendor: "CookieYes" },
  { re: /\btermly\b/i, vendor: "Termly" },
  { re: /\biubenda\b/i, vendor: "Iubenda" },
  { re: /\bCookieControl\b|civic-cookie/i, vendor: "Civic Cookie Control" },
  { re: /\bCookieScript\b|cookie-script/i, vendor: "CookieScript" },
  { re: /\bUsercentrics\b|\buc-banner\b/i, vendor: "Usercentrics" },
  { re: /\bklaro\b/i, vendor: "Klaro" },
  { re: /\bcmplz-|complianz\b/i, vendor: "Complianz" },
  { re: /__tcfapi\b/, vendor: "an IAB TCF consent framework" },
  { re: /\bcookieconsent\b/i, vendor: "a cookie-consent library" },
];

// ---- Classifier ---------------------------------------------------------------

/** Hosts (origins or bare hostnames) → registrable domains, lowercased. */
function hostOf(origin: string): string | null {
  try {
    return new URL(origin.includes("://") ? origin : `https://${origin}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export type CookieConsentInput = {
  /** Cookies present after the no-interaction load (names + domains). */
  cookies: Array<{ name: string; domain: string }>;
  /** Third-party script origins the page loaded (scriptInventory origins, or
   *  the raw runtime request/host list). */
  scriptHosts: string[];
  /** The page's own hostname, so a first-party cookie host isn't mistaken for
   *  a tracker and the owner's own domain is excluded from tracker-host checks. */
  pageHost: string;
  /** The page HTML, for CMP markers in markup (may be null). */
  html: string | null;
};

/** Pure: detect a CMP from the script hosts and the HTML. */
export function detectCmp(scriptHosts: string[], html: string | null): { detected: boolean; vendor?: string } {
  for (const host of scriptHosts) {
    const h = hostOf(host);
    if (!h) continue;
    const hit = CMP_HOSTS.find((c) => isWithinDomain(h, c.domain));
    if (hit) return { detected: true, vendor: hit.vendor };
  }
  if (html) {
    for (const marker of CMP_HTML_MARKERS) {
      if (marker.re.test(html)) return { detected: true, vendor: marker.vendor };
    }
  }
  return { detected: false };
}

/**
 * Pure: the cookie-consent verdict. Flags known trackers (by cookie name or
 * request host) ONLY when no CMP is present — a CMP page is silent by
 * construction. Returns not_applicable when no trackers are seen at all.
 */
export function classifyCookieConsent(input: CookieConsentInput): CookieConsentResult {
  const ownDomain = ownerDomain(input.pageHost) ?? input.pageHost.toLowerCase();

  // Known-tracker cookies. A first-party-domain cookie whose name matches a
  // tracker pattern still counts — GA/Meta set first-party cookies via their
  // snippet, which is exactly the PECR concern. (The name pattern is the
  // evidence; the domain only decides wording.)
  const trackerCookies: TrackerEvidence[] = [];
  const seenCookie = new Set<string>();
  for (const cookie of input.cookies) {
    const match = TRACKER_COOKIE_PATTERNS.find((p) => p.re.test(cookie.name));
    if (match && !seenCookie.has(cookie.name)) {
      seenCookie.add(cookie.name);
      trackerCookies.push({ kind: "cookie", name: cookie.name, detail: `${match.tracker} cookie "${cookie.name}"` });
    }
  }

  // Known-tracker request hosts (excluding the site's own domain).
  const trackerHosts: TrackerEvidence[] = [];
  const seenHost = new Set<string>();
  for (const raw of input.scriptHosts) {
    const h = hostOf(raw);
    if (!h || isWithinDomain(h, ownDomain)) continue;
    const match = TRACKER_HOSTS.find((t) => isWithinDomain(h, t.domain));
    if (match && !seenHost.has(match.domain)) {
      seenHost.add(match.domain);
      trackerHosts.push({ kind: "request", host: h, detail: `${match.tracker} loaded from ${h}` });
    }
  }

  const trackers = [...trackerCookies, ...trackerHosts];

  // No tracker signal at all → nothing to consent to.
  if (trackers.length === 0) {
    return { status: "not_applicable", note: "No known analytics or marketing trackers were observed on the initial page load." };
  }

  // Trackers present — but if a CMP is on the page we can't prove pre-consent
  // firing without driving the banner, so we don't flag it (see module header).
  const cmp = detectCmp(input.scriptHosts, input.html);
  if (cmp.detected) {
    return { status: "checked", trackers: [], cmpDetected: true, ...(cmp.vendor ? { cmpVendor: cmp.vendor } : {}) };
  }

  return { status: "checked", trackers, cmpDetected: false };
}

/**
 * Entry point: consumes the already-run Playwright pass (cookies + script
 * hosts) plus the page HTML. The browser not running is partial/error, which
 * lifecycle treats as "not run"; a page with no trackers is not_applicable.
 */
export function checkCookieConsent(
  playwright: PlaywrightResult,
  pageHost: string,
  html: string | null,
  extraScriptHosts: string[] = []
): CookieConsentResult {
  if (playwright.status !== "checked") {
    return { status: "error", note: "The headless browser did not run this scan, so cookies and tracker requests could not be observed." };
  }
  if (!playwright.loadedOk) {
    return { status: "partial", note: "The page did not load cleanly in the headless browser, so the cookie/tracker observation may be incomplete." };
  }
  // Cookies capture was added after this check's first scans; its absence means
  // the browser ran before capture existed — treat as partial (not "no
  // trackers"), so lifecycle doesn't resolve a real finding.
  if (!playwright.cookies) {
    return { status: "partial", note: "This scan's browser pass predates cookie capture, so cookie-based trackers could not be evaluated." };
  }

  const scriptHosts = [
    ...extraScriptHosts,
    ...(playwright.scripts?.requested ?? []),
    ...(playwright.scripts?.elements.map((e) => e.src) ?? []),
  ];

  return classifyCookieConsent({
    cookies: playwright.cookies,
    scriptHosts,
    pageHost,
    html,
  });
}

const HTML_FETCH_TIMEOUT_MS = 10_000;
const MAX_HTML_CHARS = 1_000_000;

/** One bounded HTML fetch for the CMP markers in markup, then the pure
 *  classifier. A fetch failure just means no HTML-based CMP marker — the
 *  script-host CMP detection still runs. Every outbound request is timed out. */
export async function runCookieConsent(targetUrl: string, playwright: PlaywrightResult): Promise<CookieConsentResult> {
  if (playwright.status !== "checked") {
    return { status: "error", note: "The headless browser did not run this scan, so cookies and tracker requests could not be observed." };
  }
  let pageHost: string;
  try {
    pageHost = new URL(playwright.finalUrl || targetUrl).hostname;
  } catch {
    pageHost = (() => {
      try {
        return new URL(targetUrl).hostname;
      } catch {
        return targetUrl;
      }
    })();
  }

  let html: string | null = null;
  try {
    const res = await fetch(playwright.finalUrl || targetUrl, { signal: AbortSignal.timeout(HTML_FETCH_TIMEOUT_MS), redirect: "follow" });
    if (res.ok) html = (await res.text()).slice(0, MAX_HTML_CHARS);
    else await res.body?.cancel();
  } catch {
    // No HTML marker available — host-based CMP detection still applies.
  }

  return checkCookieConsent(playwright, pageHost, html);
}
