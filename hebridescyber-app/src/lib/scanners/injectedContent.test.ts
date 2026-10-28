import { describe, it, expect } from "vitest";
import { detectInjectedContent, EXCERPT_CHARS } from "./injectedContent";

const PAGE = new URL("https://shop.example.com/products/");
const rules = (html: string) => detectInjectedContent(html, PAGE).map((s) => s.rule);
const page = (body: string, title = "Shop") => `<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`;

// Samples that look like real attack code are assembled at run time. Written
// out literally, antivirus engines (Windows Defender did) quarantine this test
// file as a packed-script threat, which stops the suite from loading on
// developer machines.
const j = (...parts: string[]) => parts.join("");
const EVAL = j("ev", "al(");
const PACKER_HEAD = j(EVAL, "func", "tion(p,a,c,k,e,d){return p}(");
const MINER_HOST = j("coin", "hive", ".com");
const MINER_API = j("new Coin", "Hive.Anonymous");

describe("hidden iframes", () => {
  it("flags a cross-origin iframe that is invisible or 1px", () => {
    expect(rules(page('<iframe src="https://evil.example.net/x.php" width="0" height="0"></iframe>'))).toEqual(["hidden-iframe"]);
    expect(rules(page('<iframe src="//evil.example.net/in" style="display:none"></iframe>'))).toEqual(["hidden-iframe"]);
    expect(rules(page('<iframe src="http://203.0.113.9/a" style="position:absolute;left:-9999px"></iframe>'))).toEqual(["hidden-iframe"]);
    expect(rules(page('<iframe src="https://evil.example.net/" width=1 height=1 frameborder=0></iframe>'))).toEqual(["hidden-iframe"]);
  });

  it("leaves visible, same-site and non-http iframes alone", () => {
    expect(rules(page('<iframe src="https://www.youtube.com/embed/abc" width="560" height="315"></iframe>'))).toEqual([]);
    expect(rules(page('<iframe src="/widgets/map" style="display:none"></iframe>'))).toEqual([]);
    expect(rules(page('<iframe src="https://www.shop.example.com/frame" width="0" height="0"></iframe>'))).toEqual([]);
    expect(rules(page('<iframe src="about:blank" style="display:none"></iframe>'))).toEqual([]);
    expect(rules(page('<iframe src="javascript:void(0)" width="0"></iframe>'))).toEqual([]);
    expect(rules(page('<iframe style="display:none" name="x"></iframe>'))).toEqual([]);
  });

  it("keeps a short excerpt of the tag, never the whole page", () => {
    const long = `<iframe src="https://evil.example.net/${"a".repeat(400)}" width="0" height="0"></iframe>`;
    const [signal] = detectInjectedContent(page(long), PAGE);
    expect(signal.evidence.length).toBeLessThanOrEqual(EXCERPT_CHARS);
    expect(signal.evidence).toContain("evil.example.net");
  });
});

describe("obfuscated script", () => {
  const blob = "QUJD".repeat(120); // 480 base64 characters

  it("flags long encoded payloads passed to an executor", () => {
    expect(rules(page(`<script>${EVAL}atob("${blob}"));</script>`))).toEqual(["obfuscated-script"]);
    expect(rules(page(`<script>${j("document.", "write")}(unescape('${"%3c%69%66".repeat(60)}'));/* ${"x".repeat(100)} */</script>`))).toEqual(["obfuscated-script"]);
    expect(rules(page(`<script>var _0x1="${"\\x61\\x62".repeat(40)}";${"//".repeat(60)}</script>`))).toEqual(["obfuscated-script"]);
    expect(rules(page(`<script>x(String.fromCharCode(${Array.from({ length: 70 }, (_, i) => 60 + (i % 40)).join(",")}));</script>`))).toEqual(["obfuscated-script"]);
  });

  it("flags packer output only when it carries a redirect or iframe write", () => {
    const pad = "x".repeat(200);
    const redirect = `${PACKER_HEAD}'0.1="2://3.4/5"',6,6,'window|location|http|evil|net|x'.split('|'),0,{})); ${pad}`;
    const benign = `${PACKER_HEAD}'0 1',2,2,'foo|bar'.split('|'),0,{})); ${pad}`;
    expect(rules(page(`<script>${redirect}</script>`))).toEqual(["obfuscated-script"]);
    expect(rules(page(`<script>${benign}</script>`))).toEqual([]);
  });

  it("does not flag ordinary minified code, short snippets, or external scripts", () => {
    const minified = `!function(e,t){var n=e.document,r=function(a){return a&&a.length?a.map(function(b){return b*2}):[]};${"var q=r([1,2,3]);".repeat(30)}}(window);`;
    expect(rules(page(`<script>${minified}</script>`))).toEqual([]);
    expect(rules(page(`<script>${EVAL}atob("QUJD"));</script>`))).toEqual([]);
    expect(rules(page(`<script src="/assets/${blob}.js"></script>`))).toEqual([]);
    expect(rules(page(`<script type="application/json">{"data":"${blob}"}</script>`))).toEqual([]);
  });
});

describe("cryptominers", () => {
  it("flags known miner hosts and APIs", () => {
    expect(rules(page(`<script src="https://${MINER_HOST}/lib/miner.min.js"></script>`))).toEqual(["cryptominer"]);
    expect(rules(page(`<script>var m = ${MINER_API}("KEY"); m.start();</script>`))).toEqual(["cryptominer"]);
    expect(rules(page(`<script src="https://${j("authed", "mine", ".com")}/lib/x.js"></script>`))).toEqual(["cryptominer"]);
    expect(rules(page(`<script src="https://${j("crypto", "-loot", ".com")}/lib/x.js"></script>`))).toEqual(["cryptominer"]);
  });

  it("does not flag the word mining or other scripts", () => {
    expect(rules(page("<h1>Data mining and crypto mining explained</h1><p>The old browser miners were shut down in 2019.</p>"))).toEqual([]);
    expect(rules(page('<script src="https://cdn.example.com/lib/app.min.js"></script>'))).toEqual([]);
  });
});

describe("SEO spam", () => {
  const links = (n: number) => Array.from({ length: n }, (_, i) => `<a href="https://spam${i}.example.org/p">cheap thing ${i}</a>`).join(" ");

  it("flags a hidden block of off-site links, or any off-site link with spam vocabulary", () => {
    expect(rules(page(`<div style="display:none">${links(5)}</div>`))).toEqual(["seo-spam"]);
    expect(rules(page(`<div style="position:absolute;left:-99999px">${links(4)}</div>`))).toEqual(["seo-spam"]);
    expect(rules(page('<div style="visibility:hidden">buy <a href="https://pills.example.org/">viagra online</a></div>'))).toEqual(["seo-spam"]);
  });

  it("leaves visible link lists, hidden menus and on-site links alone", () => {
    expect(rules(page(`<div>${links(8)}</div>`))).toEqual([]);
    expect(rules(page('<ul style="display:none"><li><a href="/a">A</a></li><li><a href="/b">B</a></li><li><a href="https://www.shop.example.com/c">C</a></li></ul>'))).toEqual([]);
    expect(rules(page(`<div style="display:none">${links(2)}</div>`))).toEqual([]);
    expect(rules(page("<p>Our pharmacy sells viagra with a prescription.</p>"))).toEqual([]);
  });
});

describe("defacement", () => {
  it("flags a title that announces the hack", () => {
    for (const title of ["Hacked by Cyber_Ghost", "  defaced by x0r", "This website has been hacked", "You got pwned"]) {
      expect(rules(page("<h1>hi</h1>", title)), title).toEqual(["defacement"]);
    }
  });

  it("does not flag articles about hacking", () => {
    for (const title of ["How we recovered after our site was hacked", "Hacked by design: a book review", "Security blog"]) {
      expect(rules(page("<h1>hi</h1>", title)), title).toEqual([]);
    }
  });
});

describe("clean pages", () => {
  it("reports nothing for an ordinary page", () => {
    const html = page(
      '<nav><a href="/">Home</a></nav><iframe src="https://www.youtube.com/embed/x" width="560" height="315"></iframe><script src="/app.js"></script><script>window.dataLayer=window.dataLayer||[];</script>'
    );
    expect(detectInjectedContent(html, PAGE)).toEqual([]);
    expect(detectInjectedContent("", PAGE)).toEqual([]);
  });
});
