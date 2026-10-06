import { test, expect } from "@playwright/test";
import { signIn } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SCAN_ROWS, SCAN_ID, SUBSCRIPTION } from "./helpers/fixtures";

// Signed-in dashboard overview (/dashboard). The session cookie is seeded by
// helpers/session.ts and middleware's server-side check is answered by
// helpers/supabase-auth-preload.cjs; everything the page loads in the browser
// is mocked, so no real Supabase project is involved.

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("overview shows the latest scan's score, change and findings", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: SCAN_ROWS });
  await mockApi(page, { "GET /api/emerging-threats": { json: { available: true, alerts: [] } } });

  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  await expect(page.getByRole("link", { name: "example.com", exact: true })).toHaveAttribute("href", `/dashboard/scans/${SCAN_ID}`);

  // KPI tiles: score 52 (down 9 from the previous 61), 2 findings new since
  // the previous scan, 2 critical/high.
  const tile = (label: string) => page.getByText(label, { exact: true }).locator("xpath=..");
  await expect(tile("Security score")).toContainText("52/100");
  await expect(tile("Security score")).toContainText("Poor");
  await expect(tile("Change")).toContainText("9 points down");
  await expect(tile("New findings")).toContainText("2");
  await expect(tile("Critical & high")).toContainText("2");

  // Latest findings, most severe first.
  const latest = page.getByRole("heading", { name: "latest findings" }).locator("xpath=ancestor::*[contains(@class,'rounded-xl')][1]");
  await expect(latest.getByText("Exposed .env file", { exact: true })).toBeVisible();
  await expect(latest.getByText("Missing Content-Security-Policy header", { exact: true })).toBeVisible();
});

test("overview findings can be filtered to what is new since the previous scan", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: SCAN_ROWS });
  await mockApi(page, { "GET /api/emerging-threats": { json: { available: true, alerts: [] } } });

  await page.goto("/dashboard");
  const filter = page.getByRole("group", { name: "Filter findings" });
  await expect(filter.getByRole("button", { name: "All (4)" })).toHaveAttribute("aria-pressed", "true");
  await expect(filter.getByRole("button", { name: "Fixed (1)" })).toBeVisible();

  await filter.getByRole("button", { name: "New (2)" }).click();
  await expect(filter.getByRole("button", { name: "New (2)" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText("Missing Content-Security-Policy header", { exact: true })).toBeVisible();
  // Present on both scans, so not "new".
  await expect(page.getByText("Exposed .env file", { exact: true })).toHaveCount(0);
});

test("a first-time account sees the empty state and onboarding", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [], scans: [] });
  await mockApi(page, {});

  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "No completed scans yet" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Run your first scan" })).toHaveAttribute("href", "/dashboard/scans#run-a-scan");
  // No scan, so none of the score tiles render.
  await expect(page.getByText("Security score", { exact: true })).toHaveCount(0);
});

test("onboarding doesn't count a refused scan as a first scan", async ({ page }) => {
  // run-scan creates the row before checking ownership, so an attempt on an
  // unverified domain leaves a `pending` scan behind. That isn't a scan.
  await mockSupabase(page, {
    subscriptions: [],
    scans: [{ id: "pending-1", owner: "e2e-user", target_url: "https://example.com", status: "pending", created_at: "2026-10-01T00:00:00Z" }],
    verifications: [{ id: "v1", domain: "example.com", verified_at: "2026-10-01T00:00:00Z" }],
  });
  await mockApi(page, {});

  await page.goto("/dashboard");
  const checklist = page.getByRole("heading", { name: /getting started \(1\/4\)/ }).locator("xpath=../..");
  await expect(checklist).toBeVisible();
  await expect(checklist.getByText("✓ Verify a domain you own")).toBeVisible();
  await expect(checklist.getByText("○ Run your first scan")).toBeVisible();
  await expect(checklist.getByRole("link", { name: "Run a scan" })).toHaveAttribute("href", "/dashboard/scans#run-a-scan");
});

test("a past-due subscription shows the payment banner", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [{ ...SUBSCRIPTION, status: "past_due" }], scans: SCAN_ROWS });
  await mockApi(page, { "GET /api/emerging-threats": { json: { available: true, alerts: [] } } });

  await page.goto("/dashboard");
  await expect(page.getByText("Your last payment failed")).toBeVisible();
  await expect(page.getByRole("button", { name: "Update billing" })).toBeVisible();
});

test("an unmocked API call is rejected, never sent to a real backend", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: SCAN_ROWS });
  const api = await mockApi(page, {});

  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  // The overview asks for emerging threats once it has a token; with no mock
  // registered it is answered 501 and the panel simply stays hidden.
  await expect.poll(() => api.to("GET", "/api/emerging-threats").length).toBe(1);
  await expect(page.getByText("emerging threats")).toHaveCount(0);
});
