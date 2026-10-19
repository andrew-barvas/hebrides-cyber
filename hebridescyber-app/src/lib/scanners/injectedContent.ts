// Injected-content and malware signals in a page's HTML. Pure: the crawler
// (crawler.ts analysePage) passes in each page it fetched, so this reads only
// what any visitor's browser already receives.
//
// What it is and isn't. Sites are rarely "infected" with something an antivirus
// engine fingerprints; the usual compromise is an attacker adding a little
// markup or script to the pages (a hidden iframe to an exploit kit, a packed
// script that redirects mobile visitors, a coin miner, a block of hidden spam
// links, or a defaced title). Those leave visible traces in the HTML, and this
// module looks for exactly those traces. It does not run any code, follow
// redirects or download anything, and it cannot see server-side files, so a
// clean result means "no such traces on the pages we visited", never "the
// server is clean".
//
// Precision first: a false "your site has malware" alert is expensive. Each
// rule needs a signal that legitimate sites don't produce:
//   - hidden iframe: cross-origin src AND an invisible style or a 0/1px size
//     (tracking pixels and consent widgets are visible or same-origin);
//   - obfuscated script: a long encoded payload handed to eval/Function or
//     document.write(unescape(...)) (ordinary minified code is not encoded);
//   - miner: a known miner library host or API name, not the word "mining";
//   - SEO spam: a hidden container holding several off-site links, or spam
//     vocabulary in hidden text (a visible pharmacy page is not injected);
//   - defacement: a title that begins "Hacked by …" and the like.
// Evidence shown to the owner is a short, trimmed excerpt of the offending tag.

export type InjectionRule = "hidden-iframe" | "obfuscated-script" | "cryptominer" | "seo-spam" | "defacement";

export type InjectionSignal = {
  rule: InjectionRule;
  /** Short, trimmed excerpt of what matched. Never more than EXCERPT_CHARS. */
  evidence: string;
};

export const EXCERPT_CHARS = 160;
/** Signals kept per page, per rule: enough to show, bounded for storage. */
const MAX_PER_RULE = 2;

const excerpt = (s: string): string => {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > EXCERPT_CHARS ? `${flat.slice(0, EXCERPT_CHARS - 1)}…` : flat;
};

// ---- Hidden iframes -------------------------------------------------------------

const IFRAME_RE = /<iframe\b[^>]*>/gi;
const ATTR = (name: string) => new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
const SRC_ATTR = ATTR("src");
const STYLE_ATTR = ATTR("style");
const WIDTH_ATTR = ATTR("width");
const HEIGHT_ATTR = ATTR("height");
const attr = (tag: string, re: RegExp): string => {
  const m = tag.match(re);
  return (m?.[1] ?? m?.[2] ?? m?.[3] ?? "").trim();
};

const INVISIBLE_STYLE_RE = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])|(?:left|top)\s*:\s*-\s*\d{3,}px|(?:width|height)\s*:\s*[01](?:px)?\s*(?:;|$|!)/i;
const TINY = (v: string): boolean => /^[01](?:px)?$/.test(v);

function hiddenIframes(html: string, pageUrl: URL): InjectionSignal[] {
  const out: InjectionSignal[] = [];
  for (const m of html.matchAll(IFRAME_RE)) {
    const tag = m[0];
    const src = attr(tag, SRC_ATTR);
    if (!src || /^(?:about:|javascript:|data:)/i.test(src)) continue;
    let target: URL;
    try {
      target = new URL(src, pageUrl);
    } catch {
      continue;
    }
    if (target.protocol !== "http:" && target.protocol !== "https:") continue;
    if (target.hostname.replace(/^www\./, "") === pageUrl.hostname.replace(/^www\./, "")) continue;
    const invisible = INVISIBLE_STYLE_RE.test(attr(tag, STYLE_ATTR)) || TINY(attr(tag, WIDTH_ATTR)) || TINY(attr(tag, HEIGHT_ATTR)) || /\bhidden\b/i.test(tag.replace(SRC_ATTR, ""));
    if (invisible) out.push({ rule: "hidden-iframe", evidence: excerpt(tag) });
    if (out.length >= MAX_PER_RULE) break;
  }
  return out;
}

// ---- Obfuscated script ----------------------------------------------------------

const INLINE_SCRIPT_RE = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
// A payload of at least 300 characters of encoded text handed to an executor.
const EVAL_ATOB_RE = /\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(\s*(?:"[A-Za-z0-9+/=%]{300,}"|'[A-Za-z0-9+/=%]{300,}')/;
const WRITE_UNESCAPE_RE = /document\.write\s*\(\s*unescape\s*\(\s*(?:"(?:%[0-9a-f]{2}){100,}|'(?:%[0-9a-f]{2}){100,})/i;
// Dean Edwards' packer output, which injected redirectors favour.
const PACKER_RE = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/;
const HEX_ESCAPE_RUN_RE = /(?:\\x[0-9a-f]{2}){60,}/i;
const FROMCHARCODE_RUN_RE = /String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){60,}/;

function obfuscatedScripts(html: string): InjectionSignal[] {
  const out: InjectionSignal[] = [];
  for (const m of html.matchAll(INLINE_SCRIPT_RE)) {
    const body = m[1];
    if (body.length < 200) continue;
    // Packed code is used by some legitimate minifiers, so the packer alone
    // counts only when it also carries a redirect or iframe write.
    // A packer's word dictionary is a '|'-separated list, so a redirect shows as |location|.
    const packed = PACKER_RE.test(body) && /\|(?:location|iframe|write|replace|href)\|/.test(body);
    if (EVAL_ATOB_RE.test(body) || WRITE_UNESCAPE_RE.test(body) || packed || HEX_ESCAPE_RUN_RE.test(body) || FROMCHARCODE_RUN_RE.test(body)) {
      out.push({ rule: "obfuscated-script", evidence: excerpt(body.slice(0, 400)) });
    }
    if (out.length >= MAX_PER_RULE) break;
  }
  return out;
}

// ---- Cryptominers ---------------------------------------------------------------

// Hosts and API names of in-browser Monero miners (CoinHive and its clones).
// Deliberately a list of names that only miners use.
const MINER_RE =
  /coinhive\.(?:com|min\.js)|coin-hive\.com|authedmine\.com|cryptoloot\.pro|crypto-loot\.com|webminepool\.com|minero\.cc|jsecoin\.com\/(?:server|load)|coinimp\.com|coin-have\.com|ppoi\.org|mataharirama\.xyz|lmodr\.biz|\bnew\s+CoinHive\.(?:Anonymous|User)\b|\bCryptoNoter\b|\bdeepMiner\b|miner\.start\s*\(\s*\{[^}]*threads/i;

function cryptominers(html: string): InjectionSignal[] {
  const m = html.match(MINER_RE);
  if (!m || m.index === undefined) return [];
  return [{ rule: "cryptominer", evidence: excerpt(html.slice(Math.max(0, m.index - 40), m.index + 120)) }];
}

// ---- SEO spam in hidden containers ----------------------------------------------

const HIDDEN_CONTAINER_RE =
  /<(div|span|p|ul|section|font)\b[^>]*style\s*=\s*(?:"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top|text-indent)\s*:\s*-\s*\d{4,}px|height\s*:\s*0(?:px)?\s*;[^"]*overflow\s*:\s*hidden)[^"]*"|'[^']*(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top|text-indent)\s*:\s*-\s*\d{4,}px)[^']*')[^>]*>([\s\S]{0,6000}?)<\/\1>/gi;
const ANCHOR_RE = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
const SPAM_TERMS_RE = /\b(?:viagra|cialis|levitra|kamagra|payday\s+loans?|online\s+casino|replica\s+(?:watches|rolex|handbags)|louis\s+vuitton\s+outlet|cheap\s+nfl\s+jerseys|buy\s+(?:essays?|followers))\b/i;

function seoSpam(html: string, pageUrl: URL): InjectionSignal[] {
  const out: InjectionSignal[] = [];
  const own = pageUrl.hostname.replace(/^www\./, "");
  for (const m of html.matchAll(HIDDEN_CONTAINER_RE)) {
    const inner = m[2];
    let external = 0;
    for (const a of inner.matchAll(ANCHOR_RE)) {
      try {
        const u = new URL(a[1] ?? a[2] ?? "", pageUrl);
        if ((u.protocol === "http:" || u.protocol === "https:") && u.hostname.replace(/^www\./, "") !== own) external++;
      } catch {
        // unparseable href: not evidence
      }
    }
    if (external >= 4 || (external >= 1 && SPAM_TERMS_RE.test(inner))) {
      out.push({ rule: "seo-spam", evidence: excerpt(`${external} off-site links in hidden text: ${inner.replace(/<[^>]+>/g, " ")}`) });
    }
    if (out.length >= MAX_PER_RULE) break;
  }
  return out;
}

// ---- Defacement -----------------------------------------------------------------

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;
// "Hacked by <handle>": the word after "by" must not be an ordinary one, so a
// title like "Hacked by design" or "Defaced by the elements" is left alone.
const DEFACED_TITLE_RE = /^\s*(?:(?:hacked|defaced|pwned|owned|h4cked|0wned)\s+by\s+(?!(?:design|default|accident|mistake|the|an?|us|you|our|your|hackers?|bots?|ai|a\s)\b)\S|this\s+(?:site|website)\s+(?:has\s+been|was)\s+(?:hacked|defaced)\b|you\s+(?:have\s+been|got)\s+(?:hacked|pwned)\b)/i;

function defacement(html: string): InjectionSignal[] {
  const title = html.match(TITLE_RE)?.[1] ?? "";
  return DEFACED_TITLE_RE.test(title) ? [{ rule: "defacement", evidence: excerpt(`Page title: ${title}`) }] : [];
}

/** Every injection signal on one page. `pageUrl` resolves relative links. */
export function detectInjectedContent(html: string, pageUrl: URL): InjectionSignal[] {
  return [...hiddenIframes(html, pageUrl), ...obfuscatedScripts(html), ...cryptominers(html), ...seoSpam(html, pageUrl), ...defacement(html)];
}
