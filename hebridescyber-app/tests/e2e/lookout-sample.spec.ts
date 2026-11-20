import { test, expect } from "@playwright/test";

// /lookout/sample: the sample Lookout report (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 11).
test("the Lookout page's report button points at the sample report", async ({ page }) => {
  await page.goto("/lookout");
  await expect(page.getByRole("link", { name: "See a sample report" })).toHaveAttribute("href", /\/lookout\/sample$/);
});

test("the sample report says it's an example and shows the real report's sections", async ({ page }) => {
  await page.goto("/lookout/sample");
  await expect(page.getByRole("note")).toContainText("Harbour Bakery is a fictional business");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Harbour Bakery");
  for (const name of ["Summary", "Your security score over this period", "What to fix, in order", "Lookalike domains"]) {
    await expect(page.getByRole("heading", { level: 2, name })).toBeVisible();
  }
  await expect(page.getByRole("img", { name: /average security score/i })).toBeVisible();
  await expect(page.getByRole("link", { name: "Book a call about Lookout" })).toBeVisible();
});
