import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const execToolMock = vi.fn();
vi.mock("../../lib/execTool", () => ({ execTool: (...args: unknown[]) => execToolMock(...args) }));

import { buildKatanaArgs, buildKatanaFindings, parseKatanaOutput, runKatana, selectNewPages, KATANA_MAX_PAGES } from "./katana";
import { checkCrawl } from "../../lib/scanners/crawler";
import { getComplianceRefs } from "../../lib/scanners/compliance";
import { getFixDifficulty } from "../../lib/scanners/fixDifficulty";
import { findingSource, isCovered, scanCoverage } from "../../lib/findingLifecycle";

const ORIGIN = "https://shop.example.com";
const TARGET = `${ORIGIN}/`;
const SECURE = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

type Route = { status?: number; body?: string; headers?: Record<string, string> };

/** Fixture site on fetch; records every URL requested. */
function stubSite(routes: Record<string, Route>, opts: { down?: boolean } = {}) {
  const requested: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => {
      const url = new URL(String(input));
      requested.push(url.pathname + url.search);
      if (opts.down) throw new Error("ECONNREFUSED");
      const route = routes[url.pathname + url.search] ?? routes[url.pathname];
      if (!route) return new Response("nf", { status: 404, headers: { "content-type": "text/html" } });
      const type = url.pathname === "/robots.txt" ? "text/plain" : "text/html";
      return new Response(route.body ?? "<html><title>p</title></html>", { status: route.status ?? 200, headers: { "content-type": type, ...(route.headers ?? {}) } });
    })
  );
  return requested;
}

// Output shape of the real katana v1.8.0 (plain mode): one URL per line,
// the input URL first, JS-discovered routes included.
const KATANA_STDOUT = [
  TARGET,
  `${ORIGIN}/about`,
  `${ORIGIN}/static/app.js`,
  `${ORIGIN}/settings/profile`,
  `${ORIGIN}/api/orders?page=1`,
  `${ORIGIN}/dashboard/reports`,
  "",
].join("\n");

beforeEach(() => {
  execToolMock.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

describe("buildKatanaArgs", () => {
  it("parses JS, stays on the host, closes off action links and never omits bodies", () => {
    const args = buildKatanaArgs(TARGET);
    expect(args).toEqual(expect.arrayContaining(["-u", TARGET, "-jc", "-silent", "-nc", "-duc"]));
    expect(args[args.indexOf("-kf") + 1]).toBe("all"); // one value: a list is a flag error
    expect(args[args.indexOf("-fs") + 1]).toBe("fqdn");
    expect(args[args.indexOf("-H") + 1]).toMatch(/^User-Agent: HebridesCyberScanner\//);
    const cos = new RegExp(args[args.indexOf("-cos") + 1].replace(/^\(\?i\)/, ""), "i");
    expect(cos.test("/account/logout")).toBe(true);
    expect(cos.test("/cart/add-to-cart?id=1")).toBe(true);
    expect(cos.test("/dashboard/reports")).toBe(false);
    // -ob also disables JS endpoint extraction in v1.8.0; JSONL would carry bodies.
    expect(args).not.toContain("-ob");
    expect(args).not.toContain("-jsonl");
  });
});

describe("parseKatanaOutput", () => {
  it("reads one URL per line", () => {
    expect(parseKatanaOutput(KATANA_STDOUT)).toHaveLength(6);
    expect(parseKatanaOutput("")).toEqual([]);
  });

  it("throws on a flag error, which katana prints on stdout", () => {
    expect(() => parseKatanaOutput('invalid value "robotstxt,sitemapxml" for flag -kf')).toThrow(/unexpected katana output/);
    expect(() => parseKatanaOutput("ftp://example.com/x")).toThrow(/unexpected katana output/);
  });
});

describe("selectNewPages", () => {
  it("keeps same-site pages the base crawl missed, dropping assets, action links and the start page", () => {
    const urls = parseKatanaOutput(KATANA_STDOUT).concat([`${ORIGIN}/account/logout`, "https://other.example.org/x", `https://www.shop.example.com/about`]);
    expect(selectNewPages(urls, TARGET, [`${ORIGIN}/about`])).toEqual([
      `${ORIGIN}/settings/profile`,
      `${ORIGIN}/api/orders?page=1`,
      `${ORIGIN}/dashboard/reports`,
    ]);
  });

  it("caps the number of pages", () => {
    const many = Array.from({ length: KATANA_MAX_PAGES + 10 }, (_, i) => `${ORIGIN}/p${i}`);
    expect(selectNewPages(many, TARGET, [])).toHaveLength(KATANA_MAX_PAGES);
    expect(selectNewPages(many, "not a url", [])).toEqual([]);
  });
});

describe("checkCrawl onlyUrls mode", () => {
  it("visits the start page and exactly the listed URLs, following nothing", async () => {
    const requested = stubSite({
      "/": { body: '<a href="/linked">x</a>', headers: SECURE },
      "/robots.txt": { body: "User-agent: *\nDisallow: /private" },
      "/listed": { body: '<a href="/deeper">x</a>' },
      "/private/x": {},
    });
    const crawl = await checkCrawl(TARGET, { onlyUrls: ["/listed", `${ORIGIN}/private/x`, `${ORIGIN}/account/logout`] });
    expect(crawl.status).toBe("checked");
    expect(requested).not.toContain("/linked");
    expect(requested).not.toContain("/deeper");
    expect(requested).not.toContain("/sitemap.xml");
    expect(requested).not.toContain("/private/x"); // robots.txt still applies
    expect(requested).not.toContain("/account/logout"); // action links still skipped
    expect(crawl.status !== "error" && crawl.pages.map((p) => new URL(p.url).pathname)).toEqual(["/", "/listed"]);
  });
});

describe("buildKatanaFindings", () => {
  it("re-namespaces the crawler's findings so they never merge with or resolve crawl.*", async () => {
    stubSite({ "/": { headers: SECURE }, "/dashboard/reports": {} });
    const crawl = await checkCrawl(TARGET, { onlyUrls: ["/dashboard/reports"] });
    const findings = buildKatanaFindings(crawl);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.checkId).toMatch(/^katana\./);
      expect(f.title).toMatch(/\(pages found by katana\)$/);
    }
    const gap = findings.find((f) => f.checkId === "katana.header-gap:content-security-policy");
    expect(gap?.detail).toContain("/dashboard/reports");
    // Same mapping as the crawl.* original.
    expect(getComplianceRefs("katana.header-gap:x")).toEqual(getComplianceRefs("crawl.header-gap:x"));
    expect(getFixDifficulty("katana.mixed-content:/a")).toBe(getFixDifficulty("crawl.mixed-content:/a"));
  });

  it("is resolved only by a scan where katana itself completed", () => {
    expect(findingSource("katana.header-gap:csp", true, ["katana", "nuclei"])).toBe("katana");
    const ran = scanCoverage({ katana: { status: "completed" } });
    const partial = scanCoverage({ katana: { status: "partial" } });
    const passive = scanCoverage(undefined);
    expect(isCovered("katana", ran)).toBe(true);
    expect(isCovered("katana", partial)).toBe(false);
    expect(isCovered("katana", passive)).toBe(false);
  });
});

describe("runKatana", () => {
  const okExec = (stdout: string) =>
    execToolMock.mockImplementation(async (_bin: string, args: string[]) => (args.includes("-version") ? { stdout: "", stderr: "v1.8.0" } : { stdout, stderr: "" }));

  it("is not_configured without the binary, and an error when the probe fails otherwise", async () => {
    execToolMock.mockRejectedValueOnce(Object.assign(new Error("spawn katana ENOENT"), { code: "ENOENT" }));
    expect(await runKatana(TARGET)).toMatchObject({ status: "not_configured" });
    execToolMock.mockRejectedValueOnce(Object.assign(new Error("exec format error"), { code: 126 }));
    expect(await runKatana(TARGET)).toMatchObject({ status: "error" });
  });

  it("is an error, not clean, when the target is unreachable (katana would still exit 0)", async () => {
    okExec(`${TARGET}\n`);
    stubSite({}, { down: true });
    expect(await runKatana(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("unreachable") });
    expect(execToolMock).toHaveBeenCalledTimes(1);
  });

  it("runs the page checks on the pages the base crawl missed", async () => {
    okExec(KATANA_STDOUT);
    stubSite({ "/": { headers: SECURE }, "/about": { headers: SECURE }, "/settings/profile": { headers: SECURE }, "/api/orders": { headers: SECURE }, "/dashboard/reports": {} });
    const result = await runKatana(TARGET, [`${ORIGIN}/about`]);
    if (result.status !== "completed") throw new Error(JSON.stringify(result));
    expect(result.discovered).toBe(5);
    expect(result.newPages).toEqual([`${ORIGIN}/settings/profile`, `${ORIGIN}/api/orders?page=1`, `${ORIGIN}/dashboard/reports`]);
    expect(result.findings.map((f) => f.checkId)).toContain("katana.header-gap:content-security-policy");
  });

  it("is partial (not-run for lifecycle) when the page checks are throttled", async () => {
    okExec(KATANA_STDOUT);
    stubSite({ "/": { headers: SECURE }, "/settings/profile": { status: 429 }, "/api/orders": {}, "/dashboard/reports": {} });
    const result = await runKatana(TARGET);
    expect(result.status).toBe("partial");
  });

  it("is an error when the start page fails the page checks", async () => {
    okExec(KATANA_STDOUT);
    stubSite({ "/": { status: 403 } });
    expect(await runKatana(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("couldn't be checked") });
  });

  it("is an error on a timeout, a crash or unexpected output", async () => {
    stubSite({ "/": {} });
    execToolMock.mockImplementation(async (_b: string, args: string[]) => {
      if (args.includes("-version")) return { stdout: "", stderr: "" };
      throw Object.assign(new Error("killed"), { killed: true });
    });
    expect(await runKatana(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("exceeded") });
    execToolMock.mockImplementation(async (_b: string, args: string[]) => {
      if (args.includes("-version")) return { stdout: "", stderr: "" };
      throw Object.assign(new Error("exit 2"), { code: 2, stderr: "flag provided but not defined" });
    });
    expect(await runKatana(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("flag provided") });
    okExec('invalid value "x" for flag -kf');
    expect(await runKatana(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("unexpected katana output") });
  });
});
