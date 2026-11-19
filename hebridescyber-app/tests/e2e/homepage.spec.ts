import { test, expect } from "@playwright/test";

// Homepage renders with no Supabase/Azure configuration required — it's
// static marketing content. This is the cheapest possible smoke test that
// the app builds and serves correctly.
test("homepage shows the hero and links to pricing", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: /Professional security for UK small businesses/i })
  ).toBeVisible();

  await expect(page.getByRole("link", { name: /see services and pricing/i })).toHaveAttribute("href", "/pricing");
});

test("services and pricing pages are reachable from the homepage", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: /see services and pricing/i }).click();
  await expect(page).toHaveURL(/\/pricing$/);
});

test("the hero's website box opens the free check for that address", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Your website address").fill("example.com");
  await page.getByRole("button", { name: "Check my site free" }).click();
  await expect(page).toHaveURL(/\/check\?url=example\.com$/);
  await expect(page.getByLabel("Website address")).toHaveValue("example.com");
});
