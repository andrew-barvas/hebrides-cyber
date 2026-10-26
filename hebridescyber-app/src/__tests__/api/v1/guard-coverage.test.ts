// Every /api/v1 route must go through guardV1 (auth + scope + rate limits +
// version headers). Source-level on purpose, like rate-limit-coverage.test.ts:
// it runs over files added after this test, so a new route that calls
// authenticateApiRequest directly — and so skips scopes and the failure
// throttle — fails CI instead of shipping unguarded.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const V1_DIR = join(process.cwd(), "src", "pages", "api", "v1");
// Public by design: it describes the interface, not any account's data.
const PUBLIC = new Set(["openapi.json.ts"]);

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const full = join(dir, n);
    return statSync(full).isDirectory() ? files(full) : /\.ts$/.test(n) ? [full] : [];
  });
}
const strip = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");

const routes = files(V1_DIR).map((f) => ({ route: relative(V1_DIR, f).split(sep).join("/"), code: strip(readFileSync(f, "utf8")) }));

describe("/api/v1 guard coverage", () => {
  it("finds the routes (not vacuous)", () => {
    expect(routes.length).toBeGreaterThanOrEqual(8);
  });

  it.each(routes.filter((r) => !PUBLIC.has(r.route)).map((r) => [r.route, r.code] as const))("%s uses guardV1, never raw authentication", (_route, code) => {
    expect(code).toMatch(/\bguardV1\(/);
    expect(code).not.toMatch(/\bauthenticateApiRequest\(/);
  });

  it("the public routes are rate-limited by IP instead", () => {
    for (const route of PUBLIC) {
      const r = routes.find((x) => x.route === route);
      expect(r, route).toBeDefined();
      expect(r!.code).toMatch(/\bcheckRateLimit\(/);
    }
  });

  it("every error response carries the version header, via setV1Headers or guardV1", () => {
    for (const { route, code } of routes.filter((r) => !PUBLIC.has(r.route))) {
      expect(/\bsetV1Headers\(|\bguardV1\(/.test(code), route).toBe(true);
    }
  });
});
