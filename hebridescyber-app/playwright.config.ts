import path from "node:path";
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
  projects: [
    // *.mobile.spec.ts is excluded here and run only by the "mobile" project
    // below — the rest of the suite assumes desktop viewport/interactions
    // and would need its own pass to be mobile-safe.
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, testIgnore: /.*\.mobile\.spec\.ts$/ },
    // "Pixel 7" rather than an iPhone preset: it's Chromium-based, and
    // deploy.yml/scheduled-scans.yml/on-demand-scan.yml only install the
    // chromium browser (not webkit), which an iPhone/Safari preset needs.
    { name: "mobile", use: { ...devices["Pixel 7"] }, testMatch: /.*\.mobile\.spec\.ts$/ },
  ],
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
      // supabaseAdmin (used by API routes such as create-checkout-session) is
      // also pointed at the fake project so its auth.getUser() calls are
      // handled by supabase-auth-preload.cjs alongside the middleware's call.
      // Without this, a real SUPABASE_URL in CI makes the admin client send
      // the fake test JWT to the real project, which returns 401 before any
      // plan-validation logic runs.
      SUPABASE_URL: "https://example-project.supabase.co",
      SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
      // src/middleware.ts validates the session server-side, which a browser
      // page.route() mock can't intercept. This preload answers that one
      // request for the fake project, and only for the test JWT — see
      // tests/e2e/helpers/supabase-auth-preload.cjs.
      NODE_OPTIONS: `--require ${path.join(__dirname, "tests/e2e/helpers/supabase-auth-preload.cjs")}`,
    },
  },
});
