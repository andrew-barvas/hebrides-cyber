// Reflected-XSS confirmation (proof of exploit, docs/SCANNER-CONVENTIONS.md).
//
// A scanner's "possible XSS" is only a lead. This sends ONE harmless probe in
// the parameter and reads the response the way a browser would, to decide
// whether the reflection can actually inject markup. Nothing here runs script:
// the probe is an inert custom element plus the two quote characters, e.g.
//   hcx3f9a1c2e"'<hc-xss-3f9a1c2e>
// and the verdict comes from WHERE it lands:
//   - plain page text, `<hc-xss-…>` still literal   -> confirmed (html-injection)
//   - inside a quoted attribute, the quote unescaped -> confirmed (attribute-breakout)
//   - HTML-encoded (&lt;…), or inside a comment / <script> / <style> / <textarea> /
//     <title> / <noscript>, or inside an attribute without breaking out -> not confirmed
// Reflection that reaches a <script> or comment is deliberately NOT called
// confirmed: it needs a context-specific payload we won't send.
//
// Safety: GET only, one request per check, same URL the finding names, no
// cookies, no script payloads. An unreadable or non-HTML response is "error" /
// "not_reflected", never a clean "safe".
import { randomBytes } from "node:crypto";

const REQUEST_TIMEOUT_MS = 8_000;
const MAX_BODY_CHARS = 1_000_000;

export type XssContext = "html-injection" | "attribute-breakout";

export type XssVerdict =
  | { status: "confirmed"; context: XssContext; probeUrl: string; evidence: string; csp: boolean }
  | { status: "not_confirmed"; probeUrl: string; reason: string }
  | { status: "not_reflected"; probeUrl: string }
  | { status: "error"; note: string };

export type Probe = { id: string; tag: string; value: string };

export function makeProbe(): Probe {
  const id = `hcx${randomBytes(4).toString("hex")}`;
  const tag = `hc-xss-${id.slice(3)}`;
  return { id, tag, value: `${id}"'<${tag}>` };
}

type Span = { start: number; end: number; kind: "comment" | "rawtext" | "tag" };

const RAW_TEXT_ELEMENTS = /^<(script|style|textarea|title|xmp|noscript|plaintext)(?=[\s/>])/i;

/** End index (exclusive) of the tag starting at `from`, honouring quoted attribute values. */
function tagEnd(html: string, from: number): number {
  let quote: string | null = null;
  for (let i = from + 1; i < html.length; i++) {
    const c = html[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === ">") {
      return i + 1;
    }
  }
  return html.length;
}

/** Everything in the document that is not plain text: comments, raw-text elements, tags. */
export function lexSpans(html: string): Span[] {
  const spans: Span[] = [];
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt === -1) break;
    if (html.startsWith("<!--", lt)) {
      const close = html.indexOf("-->", lt + 4);
      const end = close === -1 ? html.length : close + 3;
      spans.push({ start: lt, end, kind: "comment" });
      i = end;
      continue;
    }
    const raw = RAW_TEXT_ELEMENTS.exec(html.slice(lt, lt + 16));
    if (raw) {
      const openEnd = tagEnd(html, lt);
      const close = html.toLowerCase().indexOf(`</${raw[1].toLowerCase()}`, openEnd);
      const end = close === -1 ? html.length : close;
      spans.push({ start: lt, end: openEnd, kind: "tag" }, { start: openEnd, end, kind: "rawtext" });
      i = end;
      continue;
    }
    if (/^<[a-z/!?]/i.test(html.slice(lt, lt + 2))) {
      const end = tagEnd(html, lt);
      spans.push({ start: lt, end, kind: "tag" });
      i = end;
      continue;
    }
    i = lt + 1; // a bare "<" in text
  }
  return spans;
}

/** The quote character open at `idx` inside the tag starting at `tagStart`, or null. */
function openQuote(html: string, tagStart: number, idx: number): string | null {
  let quote: string | null = null;
  for (let i = tagStart + 1; i < idx; i++) {
    const c = html[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    }
  }
  return quote;
}

export type Reflection = { index: number; verdict: XssContext | "inert" | "encoded" };

/** Every place the probe id appears in `html`, and what a browser would do with it. */
export function classifyReflections(html: string, probe: Probe): Reflection[] {
  const spans = lexSpans(html);
  const out: Reflection[] = [];
  let from = 0;
  while (true) {
    const idx = html.indexOf(probe.id, from);
    if (idx === -1) break;
    from = idx + probe.id.length;
    const span = spans.find((s) => idx >= s.start && idx < s.end);
    if (!span) {
      out.push({ index: idx, verdict: html.startsWith(probe.value, idx) ? "html-injection" : "encoded" });
    } else if (span.kind === "tag") {
      const quote = openQuote(html, span.start, idx);
      const next = html[idx + probe.id.length];
      out.push({ index: idx, verdict: quote !== null && next === quote ? "attribute-breakout" : "inert" });
    } else {
      out.push({ index: idx, verdict: "inert" });
    }
  }
  return out;
}

/** The request URL with `param` set to the probe (other parameters kept). */
export function probeUrlFor(url: string, param: string, probe: Probe): string {
  const u = new URL(url);
  u.searchParams.set(param, probe.value);
  return u.href;
}

/** Optional second opinion from a real browser: does the injected element exist in the DOM? */
export type DomVerifier = (probeUrl: string, tag: string) => Promise<boolean>;

export async function confirmReflectedXss(url: string, param: string, options: { verifyDom?: DomVerifier } = {}): Promise<XssVerdict> {
  const probe = makeProbe();
  let probeUrl: string;
  try {
    probeUrl = probeUrlFor(url, param, probe);
  } catch {
    return { status: "error", note: "The finding's URL is not valid." };
  }

  let html: string;
  let csp: boolean;
  try {
    const res = await fetch(probeUrl, { redirect: "follow", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS), headers: { accept: "text/html" } });
    const type = res.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? "";
    if (type !== "text/html" && type !== "application/xhtml+xml") {
      await res.body?.cancel();
      return { status: "not_confirmed", probeUrl, reason: `The response is ${type || "untyped"}, which a browser does not render as a page.` };
    }
    html = (await res.text()).slice(0, MAX_BODY_CHARS);
    csp = res.headers.get("content-security-policy") !== null;
  } catch (err) {
    return { status: "error", note: `Probe request failed: ${(err as Error).message}` };
  }

  const reflections = classifyReflections(html, probe);
  if (reflections.length === 0) return { status: "not_reflected", probeUrl };

  const hit = reflections.find((r) => r.verdict === "html-injection" || r.verdict === "attribute-breakout");
  if (!hit) {
    const encoded = reflections.some((r) => r.verdict === "encoded");
    return { status: "not_confirmed", probeUrl, reason: encoded ? "The value is reflected HTML-encoded, so it cannot inject markup." : "The value is reflected only inside a comment, script, style, text-only element or an attribute it cannot break out of." };
  }
  const context = hit.verdict as XssContext;

  if (context === "html-injection" && options.verifyDom) {
    let inDom = false;
    try {
      inDom = await options.verifyDom(probeUrl, probe.tag);
    } catch {
      return { status: "error", note: "The browser check could not run, so the reflection was not confirmed." };
    }
    if (!inDom) return { status: "not_confirmed", probeUrl, reason: "The text is reflected unencoded, but the browser did not create the element (it sits where markup is not parsed)." };
  }

  const where = context === "html-injection" ? "in the page body with its angle brackets intact" : "inside a quoted attribute with the closing quote unescaped";
  return {
    status: "confirmed",
    context,
    probeUrl,
    csp,
    evidence: `A harmless marker sent in "${param}" came back ${where}. ${csp ? "A Content-Security-Policy header is present, which may limit what an attacker's script can do, but the injection itself is real." : "No Content-Security-Policy header limits what injected script could do."}`,
  };
}

/** Browser check used in production: loads the probe URL and looks for the injected element. */
export const playwrightDomVerifier: DomVerifier = async (probeUrl, tag) => {
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  try {
    const page = await browser.newPage({ javaScriptEnabled: false });
    await page.goto(probeUrl, { timeout: REQUEST_TIMEOUT_MS * 2, waitUntil: "domcontentloaded" });
    return (await page.locator(tag).count()) > 0;
  } finally {
    await browser.close();
  }
};
