// Headless browser check — launches Chromium via Playwright and inspects
// the rendered page for load errors, mixed content, and console violations.
import { chromium } from "playwright";

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
    }
  | { status: "error"; loadedOk: false; note: string };

export async function checkPlaywrightPageLoad(targetUrl: string): Promise<PlaywrightResult> {
  let browser;
  try {
    browser = await chromium.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();

    const consoleErrors: string[] = [];
    const mixedContentUrls: string[] = [];

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

    const response = await page.goto(targetUrl, { waitUntil: "load", timeout: 20_000 });
    const title = await page.title();
    const finalUrl = page.url();
    const redirected = finalUrl !== targetUrl;

    return {
      status: "checked",
      loadedOk: Boolean(response?.ok()),
      httpStatus: response?.status() ?? null,
      title,
      consoleErrors: consoleErrors.slice(0, 10),
      mixedContentUrls: [...new Set(mixedContentUrls)].slice(0, 10),
      finalUrl,
      redirected,
    };
  } catch (err) {
    return { status: "error", loadedOk: false, note: `Headless page load failed: ${(err as Error).message}` };
  } finally {
    await browser?.close();
  }
}
