import { test, expect } from "@playwright/test";

// The "test project" URL configured in playwright.config.ts's webServer env.
const FAKE_PROJECT_REF = "example-project";
// Supabase-js v2 default storage key format: `sb-<project-ref>-auth-token`.
// TODO: this is derived from an undocumented internal convention, not a
// public API — if a future @supabase/supabase-js version changes it, this
// mock will silently stop working (the test will just see "Sign in
// required" instead of failing loudly). Prefer a real test user + magic
// link flow against a disposable Supabase project once one exists in CI.
const STORAGE_KEY = `sb-${FAKE_PROJECT_REF}-auth-token`;

test("unauthenticated dashboard prompts sign-in", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Sign in required" })).toBeVisible();
});

test("authenticated dashboard lists scans (mocked session + API)", async ({ page }) => {
  // Mock the REST calls the dashboard makes via the Supabase JS client.
  await page.route("**/rest/v1/scans*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: "11111111-1111-1111-1111-111111111111",
          target_url: "https://example.com",
          status: "completed",
          created_at: new Date().toISOString(),
        },
      ]),
    })
  );

  // Seed a fake (but shaped-correctly) session before any page script runs,
  // so supabase.auth.getSession() resolves truthy without a real sign-in.
  await page.addInitScript(
    ({ key }) => {
      const fakeSession = {
        access_token: "fake-access-token",
        token_type: "bearer",
        expires_in: 3600,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        refresh_token: "fake-refresh-token",
        user: {
          id: "22222222-2222-2222-2222-222222222222",
          email: "test-user@example.com",
        },
      };
      window.localStorage.setItem(key, JSON.stringify(fakeSession));
    },
    { key: STORAGE_KEY }
  );

  await page.goto("/dashboard");

  await expect(page.getByRole("heading", { name: "Your Scans" })).toBeVisible();
  await expect(page.getByText("https://example.com")).toBeVisible();
  await expect(page.getByText("completed")).toBeVisible();
});
