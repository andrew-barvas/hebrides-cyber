import { test, expect, type Page } from "@playwright/test";
import { signIn } from "./helpers/session";
import { openReport } from "./helpers/report";

// "Download PDF" on the scan report is window.print(), so the PDF is the page
// under print media. Exported reports once came out pale grey: the dark
// theme's white text tokens carried into print, landed on white paper, and
// Chrome greyed them. globals.css now gives print its own palette (near-black
// text, light-mode semantic colours) and an alpha-step floor. These tests
// render the report as print, in both themes, and read the computed colours.

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

/** Text colour of every visible element that directly holds text, blended
 *  over the white page, with its WCAG contrast ratio against white. */
async function printedTextColours(page: Page, root: string) {
  return page.locator(root).evaluate((main) => {
    // Computed colours come back as rgb(), color(srgb ...) or oklab() (Tailwind
    // 4 builds the /N steps with color-mix), so let a canvas resolve them.
    const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
    const parse = (c: string) => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = c;
      ctx.fillRect(0, 0, 1, 1);
      const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data;
      // Blend over the white page.
      return [r, g, b].map((v) => (v * a + 255 * (255 - a)) / 255);
    };
    const lum = (rgb: number[]) => {
      const [r, g, b] = rgb.map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const out: { text: string; colour: string; contrast: number }[] = [];
    for (const el of Array.from(main.querySelectorAll<HTMLElement>("*"))) {
      if (el.closest("svg")) continue;
      const ownText = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? "")
        .join("")
        .trim();
      if (!ownText || !el.checkVisibility({ visibilityProperty: true })) continue;
      const colour = getComputedStyle(el).color;
      const rgb = parse(colour);
      out.push({ text: ownText.slice(0, 60), colour, contrast: 1.05 / (lum(rgb) + 0.05) });
    }
    return out;
  });
}

/** Contrast against white of the element holding exactly `text`. */
async function contrastOf(page: Page, text: string) {
  const colours = await printedTextColours(page, "main");
  const hit = colours.find((c) => c.text === text);
  expect(hit, `"${text}" should be printed`).toBeTruthy();
  return hit!.contrast;
}

for (const theme of ["dark", "light"] as const) {
  test(`printed report has dark, readable text in the ${theme} theme`, async ({ page }) => {
    if (theme === "light") {
      await page.addInitScript(() => localStorage.setItem("hc-theme", "light"));
    }
    await openReport(page);
    await expect(page.locator("html")).toHaveClass(theme === "dark" ? /\bdark\b/ : /^(?!.*\bdark\b)/);
    await page.emulateMedia({ media: "print" });

    // The labels from the reported PDF are near-black, not grey: 12:1 is far
    // past AA; slate-900 at the 0.9 label floor reaches ~13:1 on white.
    for (const label of [
      "Executive summary",
      "Score",
      "Critical + High",
      "Open findings",
      "Est. remediation",
      "Top priorities",
      "Compliance control areas",
      "Secure configuration",
      "Malware protection",
    ]) {
      expect(await contrastOf(page, label), label).toBeGreaterThanOrEqual(12);
    }

    // Everything else on the printed report, coloured accents included,
    // clears WCAG AA (4.5:1) on the white page.
    const colours = await printedTextColours(page, "main");
    expect(colours.length).toBeGreaterThan(50);
    const faint = colours.filter((c) => c.contrast < 4.5);
    expect(faint, JSON.stringify(faint, null, 2)).toEqual([]);
  });
}

test("the print palette does not touch the screen", async ({ page }) => {
  await openReport(page);
  const scoreLabel = page.getByText("Score", { exact: true });
  const rgba = () =>
    scoreLabel.evaluate((el) => {
      const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
      ctx.fillStyle = getComputedStyle(el).color;
      ctx.fillRect(0, 0, 1, 1);
      return Array.from(ctx.getImageData(0, 0, 1, 1).data);
    });
  const near = (actual: number[], expected: number[]) =>
    actual.every((v, i) => Math.abs(v - expected[i]) <= 2);

  // Dark theme on screen: white text at the /50 step, as before.
  const screen = await rgba();
  expect(near(screen, [255, 255, 255, 128]), String(screen)).toBe(true);
  await page.emulateMedia({ media: "print" });
  const printed = await rgba();
  expect(printed.slice(0, 3).every((v) => v < 60), String(printed)).toBe(true);
  await page.emulateMedia({ media: "screen" });
  expect(near(await rgba(), [255, 255, 255, 128])).toBe(true);
});
