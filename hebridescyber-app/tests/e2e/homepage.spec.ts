import { test, expect } from "@playwright/test";

// Homepage renders with no Supabase/Azure configuration required — it's
// static marketing content. This is the cheapest possible smoke test that
// the app builds and serves correctly.
test("homepage shows the hero and links to pricing", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: /Developer-grade security for small businesses/i })
  ).toBeVisible();

  await expect(page.getByRole("link", { name: /View services & pricing/i })).toHaveAttribute(
    "href",
    "/pricing"
  );
});

test("services and pricing pages are reachable from the homepage", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: /View services & pricing/i }).click();
  await expect(page).toHaveURL(/\/pricing$/);
});
