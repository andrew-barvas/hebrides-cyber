// LIVE-1 (docs/ROADMAP.md): every API route must either identify its caller
// or rate-limit by client IP, so an unauthenticated endpoint can't be
// hammered for free. Static, source-level check by design — it runs over
// every file under src/pages/api, including routes added after this test,
// so the guarantee can't regress unnoticed the way a per-route test can.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const API_DIR = join(process.cwd(), "src", "pages", "api");

// Each of these establishes who the caller is before any work happens.
// constructEvent is Stripe's signature verification — only Stripe can call.
const AUTH_MARKERS = [/\bauthenticateApiRequest\(/, /\brequireAdmin\(/, /\.auth\.getUser\(/, /\.webhooks\.constructEvent\(/];
const RATE_LIMIT_MARKER = /\bcheckRateLimit\(/;

// Route (relative to src/pages/api, forward slashes) → why it is allowed to
// be neither. Keep empty unless there's a genuine reason; the last test below
// fails if an entry here stops being needed.
const EXEMPT: Record<string, string> = {};

function listRoutes(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return listRoutes(full);
    return /\.(ts|tsx|js)$/.test(name) ? [full] : [];
  });
}

/** Drops comments so a marker that only appears in prose doesn't count.
 *  The `(^|[^:])` guard keeps `https://` inside string literals intact. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

const routes = listRoutes(API_DIR).map((file) => {
  const code = stripComments(readFileSync(file, "utf8"));
  return {
    route: relative(API_DIR, file).split(sep).join("/"),
    authenticated: AUTH_MARKERS.some((m) => m.test(code)),
    rateLimited: RATE_LIMIT_MARKER.test(code),
  };
});

describe("API route protection (LIVE-1)", () => {
  it("actually finds the routes (guards against this test passing vacuously)", () => {
    expect(routes.length).toBeGreaterThan(40);
    expect(routes.map((r) => r.route)).toContain("contact.ts");
  });

  it("every route either identifies its caller or rate-limits by IP", () => {
    const unprotected = routes.filter((r) => !r.authenticated && !r.rateLimited && !(r.route in EXEMPT)).map((r) => r.route);
    expect(unprotected).toEqual([]);
  });

  it("the known public routes are rate-limited, not just authenticated-by-accident", () => {
    for (const route of ["contact.ts", "health.ts", "badge/[scanId].ts", "reports/[token].ts"]) {
      const r = routes.find((x) => x.route === route);
      expect(r, route).toBeDefined();
      expect(r!.authenticated, `${route} should be public`).toBe(false);
      expect(r!.rateLimited, `${route} should be rate-limited`).toBe(true);
    }
  });

  it("has no stale exemptions", () => {
    for (const route of Object.keys(EXEMPT)) {
      const r = routes.find((x) => x.route === route);
      expect(r, `${route} no longer exists — remove its exemption`).toBeDefined();
      expect(r!.authenticated || r!.rateLimited, `${route} is protected now — remove its exemption`).toBe(false);
    }
  });
});
