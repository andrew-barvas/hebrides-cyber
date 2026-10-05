import { describe, it, expect, vi, afterEach } from "vitest";
import {
  buildScriptInventory,
  checkScriptInventory,
  detectPaymentPage,
  firstPartyMatcher,
  foundByPhrase,
  integrityPhrase,
  runtimeCapture,
  MAX_ORIGINS,
  MAX_SAMPLE_URLS,
  type InventoryInput,
  type ScriptInventoryResult,
  type ScriptOrigin,
} from "./scriptInventory";
import type { PlaywrightResult, RuntimeScripts } from "./playwright";
import { summariseResults, type ScanResults } from "./index";
import { getComplianceRefs, ALL_CONTROLS_BY_FRAMEWORK } from "./compliance";
import { getFixDifficulty } from "./fixDifficulty";
import { scanCoverage, isCovered } from "../findingLifecycle";

afterEach(() => {
  vi.unstubAllGlobals();
});

const PAGE = "https://www.example.com/";

type Checked = Extract<ScriptInventoryResult, { status: "checked" | "partial" }>;

function html(body: string, url = PAGE): InventoryInput["html"] {
  return { body, url };
}

function runtime(scripts: Partial<RuntimeScripts>, finalUrl = PAGE): InventoryInput["runtime"] {
  return { finalUrl, scripts: { requested: [], elements: [], ...scripts } };
}

function build(input: Partial<InventoryInput>): Checked {
  const result = buildScriptInventory({ targetUrl: PAGE, html: null, runtime: null, ...input });
  if (result.status === "error") throw new Error(result.note);
  return result;
}

const origins = (r: Checked) => r.origins.map((o) => o.origin);

describe("buildScriptInventory — static HTML", () => {
  const page = [
    '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-TEST"></script>',
    '<script src="https://cdn.jsdelivr.net/npm/a@1.0.0/a.min.js" integrity="sha384-abc" crossorigin="anonymous"></script>',
    '<script src="//cdn.jsdelivr.net/npm/b@2.0.0/b.min.js"></script>',
    '<script src="/assets/app.js"></script>',
    '<script src="https://static.example.com/site.js"></script>',
    '<script src="https://example.com/legacy.js"></script>',
    '<script src="data:text/javascript,void(0)"></script>',
    "<script>inline()</script>",
  ].join("\n");

  it("lists third-party origins only, grouped and sorted, and marks the inventory partial without a browser", () => {
    const result = build({ html: html(page) });
    expect(result.status).toBe("partial");
    expect(result.sources).toEqual({ html: true, runtime: false });
    expect(origins(result)).toEqual(["https://cdn.jsdelivr.net", "https://www.googletagmanager.com"]);
    expect(result.note).toContain("only scripts written into the page's HTML are listed");
  });

  it("resolves protocol-relative URLs and reads integrity per tag", () => {
    const jsdelivr = build({ html: html(page) }).origins[0];
    expect(jsdelivr).toEqual({
      origin: "https://cdn.jsdelivr.net",
      sampleUrls: ["https://cdn.jsdelivr.net/npm/a@1.0.0/a.min.js", "https://cdn.jsdelivr.net/npm/b@2.0.0/b.min.js"],
      scriptCount: 2,
      integrity: "some",
      foundBy: "html",
    });
  });

  it("reads integrity as all / none", () => {
    const all = build({ html: html('<script src="https://cdn.x.net/a.js" integrity="sha384-a"></script>') });
    const none = build({ html: html('<script src="https://cdn.x.net/a.js"></script>') });
    expect(all.origins[0].integrity).toBe("all");
    expect(none.origins[0].integrity).toBe("none");
  });

  it("resolves relative src against the URL the HTML was actually served from", () => {
    const result = build({
      targetUrl: "https://example.com/",
      html: html('<script src="/x.js"></script><script src="https://cdn.x.net/a.js"></script>', "https://www.example.com/home"),
    });
    expect(origins(result)).toEqual(["https://cdn.x.net"]);
  });
});

describe("first-party detection", () => {
  it("treats the page's own origin and its registrable domain as first party", () => {
    const isFirstParty = firstPartyMatcher(["https://shop.example.co.uk/"]);
    expect(isFirstParty(new URL("https://shop.example.co.uk/a.js"))).toBe(true);
    expect(isFirstParty(new URL("https://static.example.co.uk/a.js"))).toBe(true);
    expect(isFirstParty(new URL("https://example.co.uk/a.js"))).toBe(true);
    expect(isFirstParty(new URL("https://other.co.uk/a.js"))).toBe(false);
    expect(isFirstParty(new URL("https://notexample.co.uk/a.js"))).toBe(false);
  });

  it("counts the domain a scan was redirected to as first party too", () => {
    const result = build({
      targetUrl: "https://example.com/",
      html: html('<script src="https://cdn.example-shop.com/a.js"></script><script src="https://cdn.x.net/b.js"></script>', "https://www.example-shop.com/"),
    });
    expect(origins(result)).toEqual(["https://cdn.x.net"]);
  });

  it("falls back to the exact host for an IP-address site", () => {
    const isFirstParty = firstPartyMatcher(["http://203.0.113.10/"]);
    expect(isFirstParty(new URL("http://203.0.113.10:8080/a.js"))).toBe(true);
    expect(isFirstParty(new URL("https://cdn.x.net/a.js"))).toBe(false);
  });
});

describe("buildScriptInventory — runtime", () => {
  it("lists scripts the browser loaded that the HTML never mentioned", () => {
    const result = build({
      runtime: runtime({
        requested: ["https://www.example.com/app.js", "https://connect.facebook.net/en_US/fbevents.js", "https://www.google-analytics.com/analytics.js"],
        elements: [{ src: "https://connect.facebook.net/en_US/fbevents.js", integrity: false }],
      }),
    });
    expect(result.status).toBe("checked");
    expect(result.sources).toEqual({ html: false, runtime: true });
    expect(result.note).toContain("HTML couldn't be fetched directly");
    expect(result.origins).toEqual([
      expect.objectContaining({ origin: "https://connect.facebook.net", foundBy: "runtime", integrity: "none" }),
      // Only seen as a network request: no tag to read integrity from.
      expect.objectContaining({ origin: "https://www.google-analytics.com", foundBy: "runtime", integrity: "unknown" }),
    ]);
  });

  it("merges both sources: foundBy both, and integrity across every tag seen", () => {
    const result = build({
      html: html('<script src="https://www.googletagmanager.com/gtm.js?id=GTM-TEST"></script>'),
      runtime: runtime({
        requested: ["https://www.googletagmanager.com/gtm.js?id=GTM-TEST", "https://www.googletagmanager.com/gtag/js?id=G-TEST", "https://js.hs-scripts.com/1.js"],
        elements: [
          { src: "https://www.googletagmanager.com/gtm.js?id=GTM-TEST", integrity: false },
          { src: "https://js.hs-scripts.com/1.js", integrity: true },
        ],
      }),
    });
    expect(result.status).toBe("checked");
    expect(result.note).toBeUndefined();
    const [gtm, hubspot] = [result.origins.find((o) => o.origin === "https://www.googletagmanager.com")!, result.origins.find((o) => o.origin === "https://js.hs-scripts.com")!];
    expect(gtm).toMatchObject({ foundBy: "both", integrity: "none", scriptCount: 2 });
    expect(hubspot).toMatchObject({ foundBy: "runtime", integrity: "all" });
  });

  it("returns error, never an empty inventory, when neither source could be read", () => {
    const result = buildScriptInventory({ targetUrl: PAGE, html: null, runtime: null });
    expect(result).toEqual({ status: "error", note: expect.stringContaining("couldn't be listed") });
  });

  it("returns an honest empty inventory when the page really loads no third-party scripts", () => {
    const result = build({ html: html('<script src="/a.js"></script>'), runtime: runtime({ requested: ["https://www.example.com/a.js"] }) });
    expect(result).toMatchObject({ status: "checked", origins: [], totalOrigins: 0, truncated: false });
  });
});

describe("caps", () => {
  it(`lists at most ${MAX_ORIGINS} origins, alphabetically, and says how many there were`, () => {
    const page = Array.from({ length: 60 }, (_, i) => `<script src="https://cdn${String(i).padStart(2, "0")}.x.net/a.js"></script>`).join("");
    const result = build({ html: html(page) });
    expect(result.origins).toHaveLength(MAX_ORIGINS);
    expect(result.origins[0].origin).toBe("https://cdn00.x.net");
    expect(result).toMatchObject({ totalOrigins: 60, truncated: true });
    expect(result.note).toContain("60 third-party origins");
  });

  it(`keeps at most ${MAX_SAMPLE_URLS} sample URLs per origin but counts them all`, () => {
    const requested = Array.from({ length: 8 }, (_, i) => `https://cdn.x.net/${i}.js`);
    const [entry] = build({ runtime: runtime({ requested }) }).origins;
    expect(entry.sampleUrls).toHaveLength(MAX_SAMPLE_URLS);
    expect(entry.scriptCount).toBe(8);
  });

  it("clips very long script URLs", () => {
    const long = `https://cdn.x.net/a.js?${"q".repeat(400)}`;
    const [entry] = build({ runtime: runtime({ requested: [long] }) }).origins;
    expect(entry.sampleUrls[0].length).toBe(301);
    expect(entry.sampleUrls[0].endsWith("…")).toBe(true);
  });
});

describe("payment-page heuristics", () => {
  const origin = (o: string, paymentProvider?: string): ScriptOrigin => ({
    origin: o,
    sampleUrls: [`${o}/x.js`],
    scriptCount: 1,
    integrity: "none",
    foundBy: "html",
    ...(paymentProvider ? { paymentProvider } : {}),
  });

  it("finds nothing on an ordinary page", () => {
    expect(detectPaymentPage('<form action="/search"><input name="q"></form>', PAGE, [origin("https://cdn.x.net")])).toEqual({ detected: false, signals: [] });
  });

  it.each([
    ['<input type="text" autocomplete="cc-number">', 'a card input field (autocomplete="cc-number")'],
    ['<input autocomplete="cc-exp-month" name="m">', 'a card input field (autocomplete="cc-exp-month")'],
    ['<input type="tel" name="card_number">', 'a card input field named "card_number"'],
    ['<input type="tel" id="cvv">', 'a card input field named "cvv"'],
    ['<form method="post" action="/checkout/pay">', 'a form that submits to "/checkout/pay"'],
    ['<form action="https://www.paypal.com/cgi-bin/webscr">', 'a form that submits to "https://www.paypal.com/cgi-bin/webscr"'],
  ])("reads %s as a payment signal", (body, signal) => {
    expect(detectPaymentPage(body, PAGE, [])).toEqual({ detected: true, signals: [signal] });
  });

  it("does not mistake look-alike fields for card fields", () => {
    expect(detectPaymentPage('<input name="giftcard"><input name="scorecard"><input autocomplete="name"><form action="/paypal-info">', PAGE, []).detected).toBe(false);
  });

  it("reads a checkout page address as a signal", () => {
    expect(detectPaymentPage(null, "https://shop.example.com/checkout/", []).signals).toEqual(["the page address (/checkout/)"]);
    expect(detectPaymentPage(null, "https://shop.example.com/paying-guests", []).detected).toBe(false);
  });

  it("names payment provider scripts from the inventory", () => {
    const result = build({
      html: html(
        [
          '<script src="https://js.stripe.com/v3/"></script>',
          '<script src="https://www.paypal.com/sdk/js?client-id=test"></script>',
          '<script src="https://web.squarecdn.com/v1/square.js"></script>',
          '<script src="https://www.paypal.com/tagmanager/pptm.js"></script>',
        ].join("")
      ),
    });
    // In inventory (origin) order.
    expect(result.paymentPage).toEqual({
      detected: true,
      signals: ["Stripe script from js.stripe.com", "Square script from web.squarecdn.com", "PayPal script from www.paypal.com"],
    });
    expect(result.origins.find((o) => o.origin === "https://js.stripe.com")?.paymentProvider).toBe("Stripe");
    expect(result.origins.find((o) => o.origin === "https://www.paypal.com")?.paymentProvider).toBe("PayPal");
  });

  it("does not treat a PayPal script outside the SDK path as a payment SDK", () => {
    const result = build({ html: html('<script src="https://www.paypal.com/tagmanager/pptm.js"></script>') });
    expect(result.paymentPage.detected).toBe(false);
    expect(result.origins[0].paymentProvider).toBeUndefined();
  });

  it("caps the evidence list at five signals", () => {
    const sdks = ["https://js.stripe.com", "https://js.braintreegateway.com", "https://cdn.checkout.com", "https://js.mollie.com", "https://pay.google.com", "https://x.klarnacdn.net"];
    const result = detectPaymentPage('<input autocomplete="cc-csc">', PAGE, sdks.map((o) => origin(o, "Some provider")));
    expect(result.signals).toHaveLength(5);
  });
});

describe("runtimeCapture", () => {
  const scripts: RuntimeScripts = { requested: ["https://cdn.x.net/a.js"], elements: [] };
  const checked: PlaywrightResult = {
    status: "checked",
    loadedOk: true,
    httpStatus: 200,
    title: "Shop",
    consoleErrors: [],
    mixedContentUrls: [],
    finalUrl: "https://www.example.com/",
    redirected: false,
    scripts,
  };

  it("uses what the browser saw on a page that loaded", () => {
    expect(runtimeCapture(checked)).toEqual({ finalUrl: "https://www.example.com/", scripts });
  });

  it("ignores a failed browser, an error page, and results from before runtime capture", () => {
    expect(runtimeCapture({ status: "error", loadedOk: false, note: "Executable doesn't exist" })).toBeNull();
    expect(runtimeCapture({ ...checked, loadedOk: false, httpStatus: 503 })).toBeNull();
    expect(runtimeCapture({ ...checked, scripts: undefined })).toBeNull();
  });
});

describe("checkScriptInventory", () => {
  const playwrightDown: PlaywrightResult = { status: "error", loadedOk: false, note: "Headless page load failed: browserType.launch: Executable doesn't exist" };

  it("fetches the page with a timeout and builds a static-only (partial) inventory when the browser failed", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response('<script src="https://cdn.x.net/a.js"></script>', { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await checkScriptInventory(PAGE, playwrightDown);
    expect(result).toMatchObject({ status: "partial", origins: [expect.objectContaining({ origin: "https://cdn.x.net" })] });
    expect(fetchMock.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it("reports an error, not an empty inventory, when the page can't be read either way", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("Service Unavailable", { status: 503 })));
    expect((await checkScriptInventory(PAGE, playwrightDown)).status).toBe("error");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("ECONNRESET"); }));
    expect((await checkScriptInventory(PAGE, playwrightDown)).status).toBe("error");
  });

  it("still lists what the browser saw when the plain fetch is blocked", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("Forbidden", { status: 403 })));
    const result = await checkScriptInventory(PAGE, {
      status: "checked",
      loadedOk: true,
      httpStatus: 200,
      title: "",
      consoleErrors: [],
      mixedContentUrls: [],
      finalUrl: PAGE,
      redirected: false,
      scripts: { requested: ["https://cdn.x.net/a.js"], elements: [] },
    });
    expect(result).toMatchObject({ status: "checked", sources: { html: false, runtime: true } });
  });
});

describe("phrases", () => {
  it("describes how a script was found and its integrity", () => {
    expect(foundByPhrase("both")).toContain("HTML and loaded by the browser");
    expect(foundByPhrase("html")).toBe("written into the page's HTML");
    expect(foundByPhrase("runtime")).toContain("tag manager");
    expect(integrityPhrase("all")).toContain("refuses a modified file");
    expect(integrityPhrase("some")).toContain("Some, but not all");
    expect(integrityPhrase("none")).toContain("runs whatever that server sends");
    expect(integrityPhrase("unknown")).toContain("unknown");
  });
});

// ---- Findings ------------------------------------------------------------------

const err = { status: "error", note: "not run" } as const;

function results(extra: Partial<ScanResults>): ScanResults {
  return {
    target_url: PAGE,
    checked_at: "2026-10-01T00:00:00Z",
    tls: { ...err } as unknown as ScanResults["tls"],
    headers: err as ScanResults["headers"],
    dns: err as ScanResults["dns"],
    exposure: err as ScanResults["exposure"],
    directoryListing: { status: "error", listings: [], note: "x" } as unknown as ScanResults["directoryListing"],
    cloudMisconfig: { status: "error", publicBuckets: [], note: "x" } as unknown as ScanResults["cloudMisconfig"],
    fingerprint: err as ScanResults["fingerprint"],
    ports: err as ScanResults["ports"],
    playwright: err as ScanResults["playwright"],
    recon: err as ScanResults["recon"],
    webapp: err as ScanResults["webapp"],
    safeBrowsing: err as ScanResults["safeBrowsing"],
    waybackDiscovery: err as ScanResults["waybackDiscovery"],
    hibp: err as ScanResults["hibp"],
    wpVulnDb: err as unknown as ScanResults["wpVulnDb"],
    softwareCveDb: err as unknown as ScanResults["softwareCveDb"],
    businessLogic: err as ScanResults["businessLogic"],
    apiSpec: { status: "not_configured", findings: [], endpointsTested: 0, specSource: "none" } as unknown as ScanResults["apiSpec"],
    zap: { status: "not_configured", note: "x" } as ScanResults["zap"],
    ...extra,
  };
}

describe("script inventory findings", () => {
  const marketing = build({
    html: html('<script src="https://www.googletagmanager.com/gtm.js?id=GTM-TEST"></script>'),
    runtime: runtime({ requested: ["https://www.googletagmanager.com/gtm.js?id=GTM-TEST", "http://cdn.x.net:8080/a.js"] }),
  });
  const checkout = build({
    html: html('<script src="https://js.stripe.com/v3/"></script><input autocomplete="cc-number">'),
    runtime: runtime({ requested: ["https://js.stripe.com/v3/", "https://www.googletagmanager.com/gtag/js?id=G-TEST"] }),
  });

  it("opens one info finding (no score cost) per third-party origin, keyed by origin, on an ordinary page", () => {
    const findings = summariseResults(results({ scriptInventory: marketing })).findings;
    expect(findings.map((f) => [f.checkId, f.severity, f.title])).toEqual([
      ["script-inventory.unreviewed:http://cdn.x.net:8080", "info", "Unreviewed third-party script source: http://cdn.x.net:8080"],
      ["script-inventory.unreviewed:https://www.googletagmanager.com", "info", "Unreviewed third-party script source: www.googletagmanager.com"],
    ]);
    const gtm = findings[1];
    expect(gtm.detail).toContain("https://www.googletagmanager.com/gtm.js?id=GTM-TEST");
    expect(gtm.detail).toContain("written into the page's HTML and loaded by the browser");
    expect(gtm.detail).toContain("None of the script tags");
    expect(gtm.detail).toContain("no payment signals");
    expect(gtm.detail).toContain('"Mark as accepted / authorised"');
    expect(gtm.remediation).toContain("script-src 'self' https://www.googletagmanager.com");
    expect(gtm.remediation).not.toContain("hosted fields");
  });

  it("raises every origin to low on a page with payment signals, citing the evidence", () => {
    const findings = summariseResults(results({ scriptInventory: checkout })).findings;
    expect(findings.map((f) => f.severity)).toEqual(["low", "low"]);
    const stripe = findings.find((f) => f.checkId === "script-inventory.unreviewed:https://js.stripe.com")!;
    expect(stripe.detail).toContain("looks like a payment page (Stripe script from js.stripe.com; a card input field");
    expect(stripe.detail).toContain("6.4.3");
    expect(stripe.detail).toContain("11.6.1");
    expect(stripe.remediation).toContain("hosted fields");
  });

  it("mentions the extra scripts beyond the samples", () => {
    const many = build({ runtime: runtime({ requested: Array.from({ length: 7 }, (_, i) => `https://cdn.x.net/${i}.js`) }) });
    expect(summariseResults(results({ scriptInventory: many })).findings[0].detail).toContain("(and 2 more)");
  });

  it("maps to PCI DSS 6.4.3 and 11.6.1, OWASP A08 and CIS 16, rated trivial to fix", () => {
    const [f] = summariseResults(results({ scriptInventory: marketing })).findings;
    // The curated mapping, then what the SOC 2 / HIPAA crosswalk derives from it.
    expect(f.complianceRefs?.map((r) => r.control)).toEqual([
      "Requirement 6.4.3 – Payment Page Scripts Are Inventoried, Authorised and Integrity-Assured",
      "Requirement 11.6.1 – Unauthorised Changes to Payment Pages Are Detected",
      "A08:2021 – Software and Data Integrity Failures",
      "CIS Control 16 – Application Software Security",
      "CC7.1 – Detection of Vulnerabilities and Configuration Changes",
      "§164.308(a)(8) – Evaluation (Periodic Technical Review)",
      "§164.312(c)(1) – Integrity",
    ]);
    expect(f.fixDifficulty).toBe("trivial");
    expect(f.estimatedFixMinutes).toBe(15);
    expect(getComplianceRefs("script-inventory.unreviewed:https://js.stripe.com")).toEqual(f.complianceRefs);
    expect(getFixDifficulty("script-inventory.unreviewed")).toBe("trivial");
    expect(ALL_CONTROLS_BY_FRAMEWORK["pci-dss"].has("Requirement 6.4.3 – Payment Page Scripts Are Inventoried, Authorised and Integrity-Assured")).toBe(true);
    expect(ALL_CONTROLS_BY_FRAMEWORK["pci-dss"].has("Requirement 11.6.1 – Unauthorised Changes to Payment Pages Are Detected")).toBe(true);
  });

  it("still reports the origins a partial (HTML-only) inventory evidences", () => {
    const partial = build({ html: html('<script src="https://cdn.x.net/a.js"></script>') });
    expect(summariseResults(results({ scriptInventory: partial })).findings.map((f) => f.checkId)).toEqual(["script-inventory.unreviewed:https://cdn.x.net"]);
  });

  it("reports nothing when the inventory errored, found nothing, or predates the check", () => {
    const ids = (r: ScanResults) => summariseResults(r).findings.map((f) => f.checkId);
    expect(ids(results({ scriptInventory: { status: "error", note: "x" } }))).toEqual(["meta.no-issues"]);
    expect(ids(results({ scriptInventory: build({ html: html("<p>no scripts</p>"), runtime: runtime({}) }) }))).toEqual(["meta.no-issues"]);
    expect(ids(results({}))).toEqual(["meta.no-issues"]);
  });
});

describe("finding lifecycle", () => {
  const id = "script-inventory.unreviewed:https://cdn.x.net";

  it("lets a full inventory resolve an origin that's gone", () => {
    expect(isCovered("base", scanCoverage(undefined, { scriptInventory: { status: "checked" } }), id)).toBe(true);
  });

  it("never lets a partial or failed inventory resolve one — runtime-only origins may simply not have been seen", () => {
    expect(isCovered("base", scanCoverage(undefined, { scriptInventory: { status: "partial" } }), id)).toBe(false);
    expect(isCovered("base", scanCoverage(undefined, { scriptInventory: { status: "error" } }), id)).toBe(false);
  });
});
