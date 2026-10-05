import { defineConfig } from "vitest/config";

// Real-Postgres migration + RLS tests (tests/db). Kept out of the normal
// unit config (vitest.config.mts include is src/** only) so `npm run
// test:unit[:coverage]` needs no database. Run with `npm run test:db`, which
// sets RUN_DB_TESTS=1; without it every suite here is skipped.
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/db/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    // One shared server, but each file makes its own database; files can run in parallel.
  },
});
