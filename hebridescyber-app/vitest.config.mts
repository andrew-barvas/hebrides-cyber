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
    },
  },
});
