// checkPlaywrightPageLoad against a mocked Chromium — no browser binary, no
// network. Covers the runtime script capture scriptInventory.ts relies on,
// and that a missing/failed browser is an "error", never an empty capture.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { chromium } from "playwright";
import { checkPlaywrightPageLoad, MAX_RUNTIME_SCRIPTS } from "./playwright";

vi.mock("playwright", () => ({ chromium: { launch: vi.fn() } }));

type Handler = (arg: unknown) => void;
type FakeRequest = { url: () => string; resourceType: () => string; frame: () => unknown };

const MAIN_FRAME = { name: "main" };
const IFRAME = { name: "payment-provider-iframe" };

function request(url: string, opts: { type?: string; frame?: unknown; noFrame?: boolean } = {}): FakeRequest {
  return {
    url: () => url,
    resourceType: () => opts.type ?? "script",
    frame: () => {
      if (opts.noFrame) throw new Error("Service Worker requests do not have an associated frame.");
      return opts.frame ?? MAIN_FRAME;
    },
  };
}

type Scenario = {
  /** Requests fired while the page loads. */
  duringLoad?: FakeRequest[];
  /** Requests fired after the load event (a tag manager injecting scripts). */
  afterLoad?: FakeRequest[];
  elements?: Array<{ src: string; integrity: boolean }> | Error;
  networkIdle?: "settles" | "times out";
  status?: number;
  finalUrl?: string;
  gotoError?: Error;
  /** The DOM-XSS probe's second page: whether the marker element is found, or a load failure. */
  domXss?: "found" | "not-found" | Error;
};

function fakeBrowser(scenario: Scenario) {
  const handlers: Record<string, Handler[]> = {};
  const emit = (event: string, arg: unknown) => (handlers[event] ?? []).forEach((h) => h(arg));
  const page = {
    on: vi.fn((event: string, handler: Handler) => {
      (handlers[event] ??= []).push(handler);
    }),
    goto: vi.fn(async () => {
      if (scenario.gotoError) throw scenario.gotoError;
      for (const r of scenario.duringLoad ?? []) emit("request", r);
      const status = scenario.status ?? 200;
      return { ok: () => status >= 200 && status < 300, status: () => status };
    }),
    waitForLoadState: vi.fn(async () => {
      for (const r of scenario.afterLoad ?? []) emit("request", r);
      if (scenario.networkIdle === "times out") throw new Error("Timeout 5000ms exceeded.");
    }),
    title: vi.fn(async () => "Example shop"),
    url: vi.fn(() => scenario.finalUrl ?? "https://www.example.com/"),
    mainFrame: () => MAIN_FRAME,
    $$eval: vi.fn(async () => {
      if (scenario.elements instanceof Error) throw scenario.elements;
      return scenario.elements ?? [];
    }),
  };
  const probeClose = vi.fn(async () => undefined);
  const probePage = {
    goto: vi.fn(async () => {
      if (scenario.domXss instanceof Error) throw scenario.domXss;
    }),
    locator: () => ({ count: async () => (scenario.domXss === "found" ? 1 : 0) }),
    close: probeClose,
  };
  const newPage = vi.fn().mockResolvedValueOnce(page).mockResolvedValue(probePage);
  const browser = { newPage, close: vi.fn(async () => undefined) };
  vi.mocked(chromium.launch).mockResolvedValue(browser as never);
  return { page, probePage, probeClose, browser };
}

beforeEach(() => {
  vi.mocked(chromium.launch).mockReset();
});

describe("runtime script capture", () => {
  it("records main-frame script requests, including ones injected after load, deduplicated", async () => {
    const { page } = fakeBrowser({
      duringLoad: [
        request("https://www.example.com/app.js"),
        request("https://www.googletagmanager.com/gtm.js?id=GTM-TEST"),
        request("https://www.example.com/style.css", { type: "stylesheet" }),
        request("https://www.example.com/app.js"),
      ],
      afterLoad: [request("https://connect.facebook.net/en_US/fbevents.js")],
      elements: [{ src: "https://www.googletagmanager.com/gtm.js?id=GTM-TEST", integrity: false }],
    });

    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    if (result.status !== "checked") throw new Error(result.note);
    expect(result.scripts).toEqual({
      requested: ["https://www.example.com/app.js", "https://www.googletagmanager.com/gtm.js?id=GTM-TEST", "https://connect.facebook.net/en_US/fbevents.js"],
      elements: [{ src: "https://www.googletagmanager.com/gtm.js?id=GTM-TEST", integrity: false }],
    });
    expect(page.waitForLoadState).toHaveBeenCalledWith("networkidle", { timeout: 5_000 });
  });

  it("leaves out scripts that run inside a third-party iframe, and keeps service-worker scripts", async () => {
    fakeBrowser({
      duringLoad: [
        request("https://js.stripe.com/v3/"),
        request("https://js.stripe.com/v3/fingerprinted/js/elements-inner.js", { frame: IFRAME }),
        request("https://cdn.onesignal.com/sdks/OneSignalSDKWorker.js", { noFrame: true }),
      ],
    });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    expect(result.status === "checked" && result.scripts?.requested).toEqual([
      "https://js.stripe.com/v3/",
      "https://cdn.onesignal.com/sdks/OneSignalSDKWorker.js",
    ]);
  });

  it("still succeeds when the page never goes network-idle or the DOM read fails", async () => {
    fakeBrowser({
      duringLoad: [request("https://cdn.x.net/a.js")],
      networkIdle: "times out",
      elements: new Error("Execution context was destroyed"),
    });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    expect(result).toMatchObject({ status: "checked", loadedOk: true, scripts: { requested: ["https://cdn.x.net/a.js"], elements: [] } });
  });

  it(`caps the capture at ${MAX_RUNTIME_SCRIPTS} scripts`, async () => {
    fakeBrowser({
      duringLoad: Array.from({ length: MAX_RUNTIME_SCRIPTS + 20 }, (_, i) => request(`https://cdn.x.net/${i}.js`)),
      elements: Array.from({ length: MAX_RUNTIME_SCRIPTS + 20 }, (_, i) => ({ src: `https://cdn.x.net/${i}.js`, integrity: false })),
    });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    if (result.status !== "checked") throw new Error(result.note);
    expect(result.scripts?.requested).toHaveLength(MAX_RUNTIME_SCRIPTS);
    expect(result.scripts?.elements).toHaveLength(MAX_RUNTIME_SCRIPTS);
  });

  it("keeps the existing page-health signals: status, redirect and mixed content", async () => {
    fakeBrowser({
      duringLoad: [request("http://cdn.x.net/insecure.js"), request("http://cdn.x.net/logo.png", { type: "image" })],
      status: 503,
      finalUrl: "https://www.example.com/maintenance",
    });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    expect(result).toMatchObject({
      status: "checked",
      loadedOk: false,
      httpStatus: 503,
      redirected: true,
      mixedContentUrls: ["http://cdn.x.net/insecure.js", "http://cdn.x.net/logo.png"],
    });
  });
});

describe("DOM-based XSS probe", () => {
  it("confirms when the marker reaches the DOM of the second (probe) page, and closes it", async () => {
    const { probePage, probeClose } = fakeBrowser({ domXss: "found" });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    if (result.status !== "checked") throw new Error("unreachable");
    expect(result.domXss).toMatchObject({ status: "confirmed" });
    expect(probePage.goto).toHaveBeenCalled();
    expect(probeClose).toHaveBeenCalled();
  });

  it("is not_confirmed when the marker never reaches the DOM", async () => {
    fakeBrowser({ domXss: "not-found" });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    if (result.status !== "checked") throw new Error("unreachable");
    expect(result.domXss).toMatchObject({ status: "not_confirmed" });
  });

  it("is an error, not a crash, when the probe page itself fails to load — the rest of the result still returns", async () => {
    fakeBrowser({ domXss: new Error("probe page crashed") });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    if (result.status !== "checked") throw new Error("unreachable");
    expect(result.domXss).toMatchObject({ status: "error" });
    expect(result.loadedOk).toBe(true); // the main check still succeeded
  });
});

describe("browser failures", () => {
  it("reports an error, not an empty capture, when Chromium isn't installed", async () => {
    vi.mocked(chromium.launch).mockRejectedValue(new Error("browserType.launch: Executable doesn't exist"));
    expect(await checkPlaywrightPageLoad("https://www.example.com/")).toEqual({
      status: "error",
      loadedOk: false,
      note: "Headless page load failed: browserType.launch: Executable doesn't exist",
    });
  });

  it("reports an error and closes the browser when the page doesn't load", async () => {
    const { browser } = fakeBrowser({ gotoError: new Error("net::ERR_NAME_NOT_RESOLVED") });
    const result = await checkPlaywrightPageLoad("https://www.example.com/");
    expect(result.status).toBe("error");
    expect(browser.close).toHaveBeenCalled();
  });
});
