import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dirname = path.dirname(fileURLToPath(import.meta.url));

// Unit + integration tests (pure lib functions, API route handlers with a
// mocked Supabase client, component render/interaction tests). Kept
// separate from Playwright, which owns real end-to-end browser tests
// (see playwright.config.ts / tests/e2e/) — this config never starts a
// dev server or a browser.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(dirname, "./src"),
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "json-summary"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/app/**/layout.tsx",
        "src/app/**/page.tsx", // route entrypoints — thin composition, exercised by e2e instead
        "src/**/*.d.ts",
        "src/scripts/**", // standalone GitHub Actions scripts — need real Supabase, out of unit scope
      ],
      // This is a large, mostly-untested-until-now codebase (25k+ LOC) — the
      // thresholds below are a calibrated FLOOR set to the actual numbers
      // achieved as of the first real test-writing pass, not an aspirational
      // target. CI fails on any regression below this floor. Never lower
      // these; raise them (to match, not exceed, whatever `npm run
      // test:unit:coverage` reports) whenever a PR adds real coverage — see
      // the sibling WorldCup2026Predictions project's CLAUDE.md for the
      // same convention this mirrors.
      thresholds: {
        statements: 44,
        branches: 38,
        functions: 43,
        lines: 45,
      },
    },
  },
});
