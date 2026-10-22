import { test, expect } from "@playwright/test";

// The nonce CSP (src/middleware.ts, src/lib/csp.ts) blocks any script without
// the per-request nonce. Unit tests can't see the browser enforce it, so load
// real pages and fail on any violation — a blocked bootstrap script would
// leave the page rendered but dead.
for (const path of ["/", "/pricing", "/login"]) {
  test(`${path} loads under the nonce CSP with no violations and is interactive`, async ({ page }) => {
    const violations: string[] = [];
    page.on("console", (m) => {
      if (/content security policy|refused to (execute|load)/i.test(m.text())) violations.push(m.text());
    });

    const res = await page.goto(path);
    const csp = res?.headers()["content-security-policy"] ?? "";
    expect(csp).toMatch(/script-src [^;]*'nonce-[^']+'/);
    expect(csp).toContain("'strict-dynamic'");
    expect(csp.split(";").find((d) => d.trim().startsWith("script-src"))).not.toContain("'unsafe-inline'");

    // Hydration proves Next's own nonced scripts ran: the theme script sets the
    // `dark` class before React, and the client-rendered cookie banner mounts after.
    await expect(page.locator("html")).toHaveClass(/dark/);
    await page.waitForLoadState("networkidle");
    expect(violations).toEqual([]);
  });
}
