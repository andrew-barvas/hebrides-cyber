// Headless browser check — launches Chromium via Playwright and inspects
// the rendered page for load errors, mixed content, and console violations.
// It also records the scripts the page actually loads, for
// scriptInventory.ts: a tag manager injects most of a site's third-party
// scripts at runtime, where a plain HTML fetch can't see them.
import { chromium, type Page, type Request } from "playwright";

export type RuntimeScripts = {
  /** Script URLs the page's main frame requested while loading (resourceType
   *  "script"), deduplicated. Scripts inside a third-party iframe — a payment
   *  provider's hosted card fields, say — run in that provider's page, not
   *  this one, and are left out. */
  requested: string[];
  /** `<script src>` elements in the DOM once the page settled, including ones
   *  other scripts injected; `integrity` is whether the element carries an
   *  integrity attribute. */
  elements: Array<{ src: string; integrity: boolean }>;
};

export type PlaywrightResult =
  | {
      status: "checked";
      loadedOk: boolean;
      httpStatus: number | null;
      title: string;
      consoleErrors: string[];
      mixedContentUrls: string[];
      finalUrl: string;
      redirected: boolean;
      /** Optional because scans stored before this was recorded lack it. */
      scripts?: RuntimeScripts;
    }
  | { status: "error"; loadedOk: false; note: string };

/** Bounds memory on a page that loads an absurd number of scripts. */
export const MAX_RUNTIME_SCRIPTS = 500;

// Tag managers inject most of their scripts after the load event. Give the
// page a short window to go quiet; one that never does (analytics polling)
// just costs this timeout.
const NETWORK_IDLE_WAIT_MS = 5_000;

function fromMainFrame(page: Page, req: Request): boolean {
  try {
    return req.frame() === page.mainFrame();
  } catch {
    // Service-worker requests have no frame. Keep them: first-party ones are
    // filtered out downstream, and anything else is still a script the site loads.
    return true;
  }
}

export async function checkPlaywrightPageLoad(targetUrl: string): Promise<PlaywrightResult> {
  let browser;
  try {
    browser = await chromium.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();

    const consoleErrors: string[] = [];
    const mixedContentUrls: string[] = [];
    const scriptUrls = new Set<string>();

    page.on("console", (msg) => {
      if (msg.type() === "error") {
        const text = msg.text();
        consoleErrors.push(text);
      }
    });

    // Intercept requests to detect mixed content (HTTP assets on HTTPS page).
    if (new URL(targetUrl).protocol === "https:") {
      page.on("request", (req) => {
        if (req.url().startsWith("http://") && !req.url().startsWith("http://localhost")) {
          mixedContentUrls.push(req.url());
        }
      });
    }

    page.on("request", (req) => {
      if (req.resourceType() !== "script" || scriptUrls.size >= MAX_RUNTIME_SCRIPTS) return;
      if (fromMainFrame(page, req)) scriptUrls.add(req.url());
    });

    const response = await page.goto(targetUrl, { waitUntil: "load", timeout: 20_000 });
    await page.waitForLoadState("networkidle", { timeout: NETWORK_IDLE_WAIT_MS }).catch(() => undefined);
    const title = await page.title();
    const finalUrl = page.url();
    const redirected = finalUrl !== targetUrl;

    // The DOM read is best-effort: without it the inventory still has every
    // requested URL, just not which ones carry an integrity hash.
    const elements = await page
      .$$eval("script[src]", (nodes) =>
        nodes.map((node) => {
          const script = node as HTMLScriptElement;
          return { src: script.src, integrity: script.integrity !== "" };
        })
      )
      .catch(() => [] as RuntimeScripts["elements"]);

    return {
      status: "checked",
      loadedOk: Boolean(response?.ok()),
      httpStatus: response?.status() ?? null,
      title,
      consoleErrors: consoleErrors.slice(0, 10),
      mixedContentUrls: [...new Set(mixedContentUrls)].slice(0, 10),
      finalUrl,
      redirected,
      scripts: { requested: [...scriptUrls], elements: elements.slice(0, MAX_RUNTIME_SCRIPTS) },
    };
  } catch (err) {
    return { status: "error", loadedOk: false, note: `Headless page load failed: ${(err as Error).message}` };
  } finally {
    await browser?.close();
  }
}
