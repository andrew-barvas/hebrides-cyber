import { defineConfig, devices } from "@playwright/test";

// Minimal Playwright config. Runs against a local `next dev` server that
// Playwright starts itself (see `webServer` below), so `npm run test`
// works standalone without a separately-running dev server.
//
// TODO: once a real Supabase project + test user exist in CI, extend
// tests/e2e/dashboard.spec.ts beyond the mocked auth flow to exercise a
// real sign-in.
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
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: {
      // Deliberately fake-but-well-formed values so @supabase/supabase-js's
      // createClient() doesn't throw at import time (it validates the URL
      // shape, not reachability). No network calls to Supabase happen in
      // the test suite — see tests/e2e/dashboard.spec.ts for how the
      // "authenticated" state is mocked via localStorage instead.
      NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL ?? "https://example-project.supabase.co",
      NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "test-anon-key",
    },
  },
});
