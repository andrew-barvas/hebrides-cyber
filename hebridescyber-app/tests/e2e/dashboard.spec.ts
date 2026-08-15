import { test, expect } from "@playwright/test";

// The "test project" URL configured in playwright.config.ts's webServer env.
const FAKE_PROJECT_REF = "example-project";
// Supabase-js v2 default storage key format: `sb-<project-ref>-auth-token`.
const STORAGE_KEY = `sb-${FAKE_PROJECT_REF}-auth-token`;

test("unauthenticated dashboard prompts sign-in", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Sign in required" })).toBeVisible();
});

test("authenticated dashboard lists scans (mocked session + API)", async ({ page }) => {
  // Mock ALL requests to the fake Supabase project so no real network calls
  // happen. Supabase JS v2 validates sessions and calls MFA endpoints even
  // when reading from localStorage — without these mocks those calls go to
  // example-project.supabase.co (which doesn't exist) and can cause
  // getSession() to return null before the page renders.
  await page.route(`**/${FAKE_PROJECT_REF}.supabase.co/**`, (route) => {
    const url = route.request().url();

    if (url.includes("/rest/v1/scans")) {
      return route.fulfill({
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
      });
    }

    if (url.includes("/rest/v1/subscriptions")) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(null),
      });
    }

    if (url.includes("/auth/v1/factors")) {
      // MFA factors — empty list means no MFA enrolled, no challenge redirect
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ totp: [], phone: [] }),
      });
    }

    // All other auth/REST calls (token refresh, user lookup, etc.) — return
    // a minimal success so they don't throw and block rendering.
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({}),
    });
  });

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
