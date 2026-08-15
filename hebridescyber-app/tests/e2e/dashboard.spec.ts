import { test, expect } from "@playwright/test";

// Auth-protected pages (dashboard) require a real Supabase session, which
// cannot be created in CI (no real accounts / no magic-link inbox). The
// auth protection itself is covered by unit tests in src/__tests__/.
//
// These e2e tests cover the pages that are reachable WITHOUT auth so we
// can at least verify the app boots, routes correctly, and the public-facing
// pages render.

test("login page shows sign-in form", async ({ page }) => {
  // Abort Supabase calls so the session-check useEffect fails fast rather
  // than hanging on DNS for a project that doesn't exist in CI.
  await page.route(/\.supabase\.co/, (route) => route.abort());
  await page.goto("/login");
  // The form renders immediately (before the background session check resolves).
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Send magic link" })).toBeVisible();
});

test("pricing page is reachable and shows plan options", async ({ page }) => {
  await page.goto("/pricing");
  await expect(page).toHaveURL(/\/pricing$/);
  // At least one heading is visible (plan names or the page title).
  await expect(page.locator("h1, h2").first()).toBeVisible();
});
