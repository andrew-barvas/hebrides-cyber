import { describe, it, expect, vi, afterEach } from "vitest";
import { classifyReflections, confirmReflectedXss, lexSpans, makeProbe, playwrightDomVerifier, probeUrlFor } from "./xssConfirm";
import { validateExploit, enrichWithProofOfExploit, xssTarget } from "./proofOfExploit";
import type { Finding } from "./index";

const probe = { id: "hcxaaaa1111", tag: "hc-xss-aaaa1111", value: `hcxaaaa1111"'<hc-xss-aaaa1111>` };

describe("makeProbe / probeUrlFor", () => {
  it("makes an inert, unique probe and sets only the named parameter", () => {
    const a = makeProbe();
    expect(a.value).toBe(`${a.id}"'<${a.tag}>`);
    expect(a.tag).toMatch(/^hc-xss-[0-9a-f]{8}$/);
    expect(makeProbe().id).not.toBe(a.id);
    const u = new URL(probeUrlFor("https://x.test/s?q=old&keep=1", "q", probe));
    expect(u.searchParams.get("q")).toBe(probe.value);
    expect(u.searchParams.get("keep")).toBe("1");
  });
});

describe("lexSpans", () => {
  it("finds comments, raw-text elements and tags, including unterminated ones and quoted '>'", () => {
    const kinds = (h: string) => lexSpans(h).map((s) => s.kind);
    expect(kinds("a<!-- c -->b")).toEqual(["comment"]);
    expect(kinds("<!-- never closed")).toEqual(["comment"]);
    expect(kinds("<script>x</script>")).toEqual(["tag", "rawtext", "tag"]);
    expect(kinds("<textarea>x")).toEqual(["tag", "rawtext"]);
    expect(kinds('<a title="x>y">t</a>')).toEqual(["tag", "tag"]);
    expect(kinds("1 < 2 and 3 <")).toEqual([]);
    expect(kinds('<a title="never closed')).toEqual(["tag"]);
  });
});

describe("classifyReflections", () => {
  const v = (html: string) => classifyReflections(html, probe).map((r) => r.verdict);
  it("flags an unencoded probe in the page body", () => {
    expect(v(`<p>You searched ${probe.value}</p>`)).toEqual(["html-injection"]);
  });
  it("treats HTML-encoded reflection as safe", () => {
    expect(v(`<p>hcxaaaa1111&quot;&#39;&lt;hc-xss-aaaa1111&gt;</p>`)).toEqual(["encoded"]);
  });
  it("flags an attribute whose closing quote is not escaped, either quote style", () => {
    expect(v(`<input value="${probe.value}">`)).toEqual(["attribute-breakout"]);
    expect(v(`<input value='hcxaaaa1111'&quot;&lt;x'>`)).toEqual(["attribute-breakout"]);
  });
  it("does not flag an attribute where the quote is encoded", () => {
    expect(v(`<input value="hcxaaaa1111&quot;&#39;&lt;hc-xss-aaaa1111&gt;">`)).toEqual(["inert"]);
    expect(v(`<input value=hcxaaaa1111>`)).toEqual(["inert"]);
  });
  it("treats comments, script, style, textarea and title as inert", () => {
    for (const wrap of ["<!-- X -->", "<script>var a='X'</script>", "<style>/*X*/</style>", "<textarea>X</textarea>", "<title>X</title>"]) {
      expect(v(wrap.replace("X", probe.value))).toEqual(["inert"]);
    }
  });
  it("reports every reflection, and none when absent", () => {
    expect(v(`<title>${probe.value}</title><p>${probe.value}</p>`)).toEqual(["inert", "html-injection"]);
    expect(v("<p>nothing here</p>")).toEqual([]);
  });
});

function stubResponse(opts: { html?: (probeValue: string) => string; type?: string; csp?: string; fail?: boolean; textFails?: boolean }) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      if (opts.fail) throw new Error("network down");
      const value = new URL(input).searchParams.get("q") ?? "";
      const headers: Record<string, string> = { "content-type": opts.type ?? "text/html; charset=utf-8" };
      if (opts.csp) headers["content-security-policy"] = opts.csp;
      if (opts.textFails) return { headers: new Headers(headers), body: null, text: async () => { throw new Error("reset"); } } as unknown as Response;
      return new Response(opts.html ? opts.html(value) : "", { status: 200, headers });
    })
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("confirmReflectedXss", () => {
  const url = "https://x.test/search?q=hello";
  const escape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  it("confirms html injection, noting when there is no CSP", async () => {
    stubResponse({ html: (v) => `<p>Results for ${v}</p>` });
    const r = await confirmReflectedXss(url, "q");
    expect(r).toMatchObject({ status: "confirmed", context: "html-injection", csp: false });
    expect((r as { evidence: string }).evidence).toMatch(/No Content-Security-Policy/);
    expect((r as { probeUrl: string }).probeUrl).toContain("hc-xss-");
  });

  it("confirms attribute breakout and mentions a CSP when present", async () => {
    stubResponse({ html: (v) => `<input value="${v}">`, csp: "default-src 'self'" });
    const r = await confirmReflectedXss(url, "q");
    expect(r).toMatchObject({ status: "confirmed", context: "attribute-breakout", csp: true });
    expect((r as { evidence: string }).evidence).toMatch(/may limit/);
  });

  it("does not confirm encoded reflection (the must-not case)", async () => {
    stubResponse({ html: (v) => `<p>Results for ${escape(v)}</p>` });
    expect(await confirmReflectedXss(url, "q")).toMatchObject({ status: "not_confirmed", reason: expect.stringMatching(/encoded/) });
  });

  it("does not confirm reflection inside a comment or script", async () => {
    stubResponse({ html: (v) => `<!-- ${v} --><script>var q='${v}'</script>` });
    expect(await confirmReflectedXss(url, "q")).toMatchObject({ status: "not_confirmed", reason: expect.stringMatching(/comment, script/) });
  });

  it("is not_reflected when the value does not appear", async () => {
    stubResponse({ html: () => "<p>static</p>" });
    expect((await confirmReflectedXss(url, "q")).status).toBe("not_reflected");
  });

  it("does not confirm a non-HTML response, however it reflects", async () => {
    stubResponse({ type: "application/json", html: (v) => `{"q":"${v}"}` });
    expect(await confirmReflectedXss(url, "q")).toMatchObject({ status: "not_confirmed", reason: expect.stringMatching(/application\/json/) });
    stubResponse({ type: "", html: (v) => v });
    expect(await confirmReflectedXss(url, "q")).toMatchObject({ status: "not_confirmed", reason: expect.stringMatching(/untyped/) });
  });

  it("reports failures as errors, never as safe", async () => {
    stubResponse({ fail: true });
    expect(await confirmReflectedXss(url, "q")).toMatchObject({ status: "error", note: expect.stringMatching(/network down/) });
    expect(await confirmReflectedXss("not a url", "q")).toMatchObject({ status: "error" });
  });

  it("asks the browser to confirm, and trusts it over the source text", async () => {
    stubResponse({ html: (v) => `<p>${v}</p>` });
    const yes = vi.fn(async () => true);
    expect((await confirmReflectedXss(url, "q", { verifyDom: yes })).status).toBe("confirmed");
    expect(yes).toHaveBeenCalledWith(expect.stringContaining("hc-xss-"), expect.stringMatching(/^hc-xss-/));
    expect(await confirmReflectedXss(url, "q", { verifyDom: async () => false })).toMatchObject({ status: "not_confirmed", reason: expect.stringMatching(/did not create the element/) });
    expect(await confirmReflectedXss(url, "q", { verifyDom: async () => { throw new Error("no browser"); } })).toMatchObject({ status: "error" });
  });

  it("does not use the browser for attribute breakout (nothing to look up in the DOM)", async () => {
    stubResponse({ html: (v) => `<input value="${v}">` });
    const verify = vi.fn(async () => false);
    expect((await confirmReflectedXss(url, "q", { verifyDom: verify })).status).toBe("confirmed");
    expect(verify).not.toHaveBeenCalled();
  });
});

describe("playwrightDomVerifier", () => {
  it("loads the probe URL with JavaScript off and looks for the element, then closes the browser", async () => {
    const close = vi.fn();
    const goto = vi.fn();
    const count = vi.fn(async () => 1);
    const newPage = vi.fn(async () => ({ goto, locator: () => ({ count }) }));
    vi.doMock("playwright", () => ({ chromium: { launch: async () => ({ newPage, close }) } }));
    expect(await playwrightDomVerifier("https://x.test/?q=1", "hc-xss-a")).toBe(true);
    expect(newPage).toHaveBeenCalledWith({ javaScriptEnabled: false });
    expect(close).toHaveBeenCalled();
    vi.doUnmock("playwright");
  });
});

describe("proof of exploit wiring", () => {
  const f = (over: Partial<Finding>): Finding => ({ severity: "medium", title: "t", detail: "d", checkId: "api-spec.xss:GET:/search:q", ...over });

  it("derives the URL and parameter from metadata or a GET api-spec checkId", () => {
    expect(xssTarget("https://x.test", f({ metadata: { url: "https://x.test/a", parameter: "p" } }))).toEqual({ url: "https://x.test/a", param: "p" });
    expect(xssTarget("https://x.test", f({}))).toEqual({ url: "https://x.test/search", param: "q" });
    expect(xssTarget("https://x.test", f({ checkId: "api-spec.xss:POST:/search:q" }))).toBeNull();
    expect(xssTarget("https://x.test", f({ checkId: "zap.xss" }))).toBeNull();
    expect(xssTarget("https://[bad", f({}))).toBeNull();
  });

  it("enriches a finding whose reflection is confirmed, and leaves unconfirmed ones alone", async () => {
    stubResponse({ html: (v) => `<p>${v}</p>` });
    const confirmed = await validateExploit("https://x.test", f({}));
    expect(confirmed.metadata?.proofOfExploit).toMatchObject({ confirmed: true, request: expect.stringContaining("GET https://x.test/search?q=") });

    stubResponse({ html: (v) => `<p>${v.replace(/</g, "&lt;")}</p>` });
    const plain = f({});
    expect(await validateExploit("https://x.test", plain)).toBe(plain);
    const noTarget = f({ checkId: "zap.xss" });
    expect(await validateExploit("https://x.test", noTarget)).toBe(noTarget);
  });

  it("includes xss findings in the batch enrichment", async () => {
    stubResponse({ html: (v) => `<p>${v}</p>` });
    const [a, b] = await enrichWithProofOfExploit("https://x.test", [f({}), f({ checkId: "headers.missing" })], { verifyDom: async () => true });
    expect(a.metadata?.proofOfExploit).toBeDefined();
    expect(b.metadata).toBeUndefined();
  });
});

describe("quote tracking and content types", () => {
  it("handles attributes whose earlier quoted values close before the reflection", () => {
    const v = (html: string) => classifyReflections(html, probe).map((r) => r.verdict);
    expect(v(`<input type="text" class='a' value="${probe.value}">`)).toEqual(["attribute-breakout"]);
  });

  it("accepts XHTML as a rendered page", async () => {
    stubResponse({ type: "application/xhtml+xml", html: (v) => `<p>${v}</p>` });
    expect((await confirmReflectedXss("https://x.test/s?q=1", "q")).status).toBe("confirmed");
  });
});

describe("the other proofs (open redirect, CORS, exposure)", () => {
  const f = (over: Partial<Finding>): Finding => ({ severity: "medium", title: "t", detail: "d", checkId: "x", ...over });
  const resp = (init: { status?: number; headers?: Record<string, string>; body?: string }) =>
    vi.fn(async () => new Response(init.body ?? "", { status: init.status ?? 200, headers: init.headers }));

  it("confirms an open redirect only when the Location points at the probe host", async () => {
    const finding = f({ checkId: "business-logic.open-redirect", metadata: { parameter: "next" } });
    vi.stubGlobal("fetch", resp({ status: 302, headers: { location: "https://evil.example.com/x" } }));
    expect((await validateExploit("https://x.test/", finding)).metadata?.proofOfExploit).toMatchObject({ confirmed: true });
    vi.stubGlobal("fetch", resp({ status: 302, headers: { location: "/home" } }));
    expect(await validateExploit("https://x.test/", finding)).toBe(finding);
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect(await validateExploit("https://x.test/", finding)).toBe(finding);
    const noParam = f({ checkId: "business-logic.open-redirect" });
    expect(await validateExploit("https://x.test/", noParam)).toBe(noParam);
  });

  it("confirms CORS only with a reflected origin and credentials", async () => {
    const finding = f({ checkId: "headers.cors-reflected" });
    vi.stubGlobal("fetch", resp({ headers: { "access-control-allow-origin": "https://evil.example.com", "access-control-allow-credentials": "true" } }));
    expect((await validateExploit("https://x.test", finding)).metadata?.proofOfExploit).toMatchObject({ confirmed: true });
    vi.stubGlobal("fetch", resp({ headers: { "access-control-allow-origin": "*" } }));
    expect(await validateExploit("https://x.test", finding)).toBe(finding);
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect(await validateExploit("https://x.test", finding)).toBe(finding);
  });

  it("confirms an exposed file only when it contains a secret-looking pattern", async () => {
    const finding = f({ checkId: "exposure.env-file", metadata: { path: "/.env" } });
    vi.stubGlobal("fetch", resp({ body: "DB=postgres://u:p@h/db" }));
    expect((await validateExploit("https://x.test", finding)).metadata?.proofOfExploit).toMatchObject({ confirmed: true });
    vi.stubGlobal("fetch", resp({ body: "just text" }));
    expect(await validateExploit("https://x.test", finding)).toBe(finding);
    vi.stubGlobal("fetch", resp({ status: 404 }));
    expect(await validateExploit("https://x.test", finding)).toBe(finding);
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect(await validateExploit("https://x.test", finding)).toBe(finding);
  });
});

describe("edge cases", () => {
  it("treats a response with no Content-Type header as not a page", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 200 })));
    expect(await confirmReflectedXss("https://x.test/s?q=1", "q")).toMatchObject({ status: "not_confirmed", reason: expect.stringMatching(/untyped/) });
  });

  it("ignores findings with no checkId or no exposure path", async () => {
    expect(xssTarget("https://x.test", { severity: "low", title: "t", detail: "d" })).toBeNull();
    const noPath: Finding = { severity: "low", title: "t", detail: "d", checkId: "exposure.env-file" };
    expect(await validateExploit("https://x.test", noPath)).toBe(noPath);
    const noId: Finding = { severity: "low", title: "t", detail: "d" };
    expect(await validateExploit("https://x.test", noId)).toBe(noId);
  });
});
