import { test, expect } from "@playwright/test";

// The campaign landing pages must be reachable from the public site, not only
// from a link someone was sent.
test("home page links to the NCSC Web Check alternative", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: /See what replaces them/i }).click();
  await expect(page).toHaveURL(/\/web-check-alternative$/);
  await expect(page.getByRole("heading", { level: 1, name: /retired Web Check and Mail Check/i })).toBeVisible();
});

test("footer resources reach the Cyber Essentials page", async ({ page }) => {
  await page.goto("/pricing");
  await page.getByRole("navigation", { name: "Resources" }).getByRole("link", { name: "Cyber Essentials readiness" }).click();
  await expect(page).toHaveURL(/\/cyber-essentials$/);
  await expect(page.getByRole("heading", { level: 1, name: "Cyber Essentials readiness scan" })).toBeVisible();
});
