import { describe, it, expect } from "vitest";
import {
  classifyCookieConsent,
  detectCmp,
  checkCookieConsent,
  type CookieConsentInput,
} from "./cookieConsent";
import type { PlaywrightResult } from "./playwright";

function input(overrides: Partial<CookieConsentInput> = {}): CookieConsentInput {
  return {
    cookies: [],
    scriptHosts: [],
    pageHost: "shop.example.com",
    html: null,
    ...overrides,
  };
}

describe("classifyCookieConsent", () => {
  it("flags a known-tracker cookie set with no CMP present", () => {
    const result = classifyCookieConsent(input({ cookies: [{ name: "_ga", domain: ".example.com" }] }));
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.cmpDetected).toBe(false);
    const cookieNames = result.trackers.filter((t) => t.kind === "cookie").map((t) => t.name);
    expect(cookieNames).toContain("_ga");
  });

  it("flags a request to a known-tracker host with no CMP present", () => {
    const result = classifyCookieConsent(input({ scriptHosts: ["https://www.googletagmanager.com/gtm.js?id=GTM-XXatt"] }));
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.trackers.some((t) => t.kind === "request")).toBe(true);
  });

  it("stays silent (no trackers reported) when a CMP is present, even with trackers", () => {
    const result = classifyCookieConsent(
      input({
        cookies: [{ name: "_ga", domain: ".example.com" }],
        scriptHosts: ["https://consent.cookiebot.com/uc.js"],
      })
    );
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.cmpDetected).toBe(true);
    expect(result.cmpVendor).toBe("Cookiebot");
    expect(result.trackers).toEqual([]);
  });

  it("detects a CMP from an HTML marker, not just a script host", () => {
    const result = classifyCookieConsent(
      input({
        cookies: [{ name: "_fbp", domain: ".example.com" }],
        html: `<div id="onetrust-banner-sdk"></div>`,
      })
    );
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.cmpDetected).toBe(true);
  });

  it("is not_applicable when no known trackers are seen at all", () => {
    const result = classifyCookieConsent(input({ cookies: [{ name: "session", domain: "shop.example.com" }], scriptHosts: ["https://cdn.jsdelivr.net/x.js"] }));
    expect(result.status).toBe("not_applicable");
  });

  it("does not treat the site's own domain as a tracker host", () => {
    // google-analytics.com is a tracker; the site's own cdn is not.
    const result = classifyCookieConsent(input({ scriptHosts: ["https://cdn.example.com/app.js"], pageHost: "www.example.com" }));
    expect(result.status).toBe("not_applicable");
  });

  it("does not flag an app's own cookie that merely resembles a tracker name loosely", () => {
    // `_gauge` must not match the anchored `^_ga$` / `^_ga_…$` patterns.
    const result = classifyCookieConsent(input({ cookies: [{ name: "_gauge", domain: "shop.example.com" }] }));
    expect(result.status).toBe("not_applicable");
  });
});

describe("detectCmp", () => {
  it("recognises CMP script hosts", () => {
    expect(detectCmp(["https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"], null)).toMatchObject({ detected: true, vendor: "OneTrust" });
    expect(detectCmp(["https://app.termly.io/embed.min.js"], null)).toMatchObject({ detected: true, vendor: "Termly" });
  });

  it("recognises an IAB TCF global in the HTML", () => {
    expect(detectCmp([], "<script>window.__tcfapi = function(){}</script>")).toMatchObject({ detected: true });
  });

  it("is false when nothing matches", () => {
    expect(detectCmp(["https://cdn.jsdelivr.net/x.js"], "<html></html>")).toEqual({ detected: false });
  });
});

describe("checkCookieConsent lifecycle status", () => {
  const base: Extract<PlaywrightResult, { status: "checked" }> = {
    status: "checked",
    loadedOk: true,
    httpStatus: 200,
    title: "Shop",
    consoleErrors: [],
    mixedContentUrls: [],
    finalUrl: "https://shop.example.com/",
    redirected: false,
    scripts: { requested: [], elements: [] },
    cookies: [],
  };

  it("errors when the browser did not run", () => {
    expect(checkCookieConsent({ status: "error", loadedOk: false, note: "x" }, "shop.example.com", null).status).toBe("error");
  });

  it("is partial when the page did not load cleanly", () => {
    expect(checkCookieConsent({ ...base, loadedOk: false }, "shop.example.com", null).status).toBe("partial");
  });

  it("is partial when the browser pass predates cookie capture", () => {
    const noCookies = { ...base } as Extract<PlaywrightResult, { status: "checked" }>;
    delete (noCookies as { cookies?: unknown }).cookies;
    expect(checkCookieConsent(noCookies, "shop.example.com", null).status).toBe("partial");
  });

  it("reads cookies and runtime script hosts from the Playwright result", () => {
    const pw = {
      ...base,
      cookies: [{ name: "_fbp", domain: ".example.com" }],
      scripts: { requested: ["https://connect.facebook.net/en_US/fbevents.js"], elements: [] },
    };
    const result = checkCookieConsent(pw, "shop.example.com", null);
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    // Both the _fbp cookie and the facebook.net host are Meta Pixel trackers.
    expect(result.trackers.length).toBeGreaterThan(0);
  });
});
