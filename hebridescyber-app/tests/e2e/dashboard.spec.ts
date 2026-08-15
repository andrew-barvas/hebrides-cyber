import { test, expect } from "@playwright/test";

// playwright.config.ts hardcodes NEXT_PUBLIC_SUPABASE_URL to the fake value
// below so that the dev server ALWAYS uses "example-project" as the project
// ref — regardless of what CI env vars are set. This makes tests hermetic.
const FAKE_PROJECT_REF = "example-project";
const STORAGE_KEY = `sb-${FAKE_PROJECT_REF}-auth-token`;

test("unauthenticated dashboard prompts sign-in", async ({ page }) => {
  // Block ALL Supabase requests so getSession() resolves immediately with null
  // rather than hanging on a network call to the fake hostname in CI.
  await page.route(`**/${FAKE_PROJECT_REF}.supabase.co/**`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({}) })
  );

  await page.goto("/dashboard");
  // The page starts in a loading state while getSession() resolves; once it
  // resolves without a session it renders the "Sign in required" heading.
  // expectTimeout in playwright.config.ts is 15 s to allow for async auth.
  await expect(page.getByRole("heading", { name: "Sign in required" })).toBeVisible();
});

test("authenticated dashboard lists scans (mocked session + API)", async ({ page }) => {
  // Mock ALL requests to the fake Supabase project so no real network calls
  // happen. Supabase JS v2 validates sessions and calls MFA endpoints even
  // when reading from localStorage — without these mocks those calls go to
  // example-project.supabase.co (which doesn't exist) and can hang in CI.
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
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ totp: [], phone: [] }),
      });
    }

    // All other auth/REST calls (token refresh, user lookup, etc.)
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({}),
    });
  });

  // Seed a fake-but-structurally-valid JWT session before any page script
  // runs. Supabase JS v2 calls jwtDecode() locally — the token must be three
  // dot-separated base64url parts even though the signature is never verified
  // client-side.
  await page.addInitScript(
    ({ key }) => {
      const toB64url = (s: string) =>
        btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      const header = toB64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const payload = toB64url(
        JSON.stringify({
          sub: "22222222-2222-2222-2222-222222222222",
          email: "test-user@example.com",
          exp: 9_999_999_999,
          aud: "authenticated",
          role: "authenticated",
          aal: "aal1",
          iss: "supabase",
          session_id: "test-session-id",
        })
      );
      const fakeJwt = `${header}.${payload}.fakesig`;

      const fakeSession = {
        access_token: fakeJwt,
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

  // The main h1 when authenticated is "Dashboard".
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("https://example.com")).toBeVisible();
  await expect(page.getByText("completed")).toBeVisible();
});
