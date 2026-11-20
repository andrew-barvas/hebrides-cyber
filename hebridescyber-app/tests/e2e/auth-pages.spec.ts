import { test, expect } from "@playwright/test";

// Sign-in pages after #247 (own page titles) and #273 ("Continue with Google",
// hidden until NEXT_PUBLIC_GOOGLE_SIGNIN is "true", which the e2e build leaves unset).

test("login and signup have their own titles and no Google button until it's switched on", async ({ page }) => {
  await page.goto("/login");
  await expect(page).toHaveTitle("Sign in | Hebrides Cyber");
  await expect(page.getByRole("button", { name: "Send magic link" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Continue with Google" })).toHaveCount(0);

  await page.goto("/signup");
  await expect(page).toHaveTitle("Create your account | Hebrides Cyber");
  await expect(page.getByRole("button", { name: "Create account" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Continue with Google" })).toHaveCount(0);
});

test("password reset pages have their own titles", async ({ page }) => {
  await page.goto("/forgot-password");
  await expect(page).toHaveTitle("Reset your password | Hebrides Cyber");
});
