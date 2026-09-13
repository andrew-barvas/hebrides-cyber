import { defineConfig, devices } from "@playwright/test";

// Runs against a local `next dev` server that Playwright starts itself.
// IMPORTANT: the webServer env below HARDCODES fake Supabase values so that
// tests are always hermetic regardless of CI env vars. The real
// NEXT_PUBLIC_SUPABASE_URL may be present as a CI repo variable — using it
// here would mean the browser's Supabase client calls the real project, the
// route mocks in dashboard.spec.ts wouldn't match, and auth tests would fail.
export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
  },
  expect: {
    // Default Playwright expectTimeout is 5 s — too short for pages with async
    // auth checks that wait on getSession() before updating state.
    timeout: 15_000,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run build && npm run start",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    env: {
      // These literal values override whatever the CI environment has set so
      // the Supabase project ref is ALWAYS "example-project" in tests.
      // dashboard.spec.ts seeds localStorage with "sb-example-project-auth-token"
      // and mocks "*.example-project.supabase.co" network requests to match.
      NEXT_PUBLIC_SUPABASE_URL: "https://example-project.supabase.co",
      NEXT_PUBLIC_SUPABASE_ANON_KEY: "test-anon-key",
    },
  },
});
