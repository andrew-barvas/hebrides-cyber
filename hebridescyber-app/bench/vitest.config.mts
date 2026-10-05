import { defineConfig } from "vitest/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dirname = path.dirname(fileURLToPath(import.meta.url));

// Unit tests for the benchmark's own logic (scoring, baseline diff, runner,
// expectation loading, fixture sites). Kept out of the main vitest.config.mts
// so `npm run test:unit` and its coverage floor are unaffected; run with
// `npm run bench:test`. Coverage here is measured for bench/ only.
export default defineConfig({
  resolve: { alias: { "@": path.resolve(dirname, "../src") } },
  test: {
    environment: "node",
    include: ["bench/**/*.test.ts"],
    root: path.resolve(dirname, ".."),
    coverage: {
      provider: "v8",
      reporter: ["text"],
      include: ["bench/**/*.ts"],
      exclude: ["bench/**/*.test.ts", "bench/run.ts", "bench/network.ts","bench/vitest.config.mts"],
    },
  },
});
