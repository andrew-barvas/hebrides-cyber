import { test, expect } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SCAN_ID, SCAN_ROWS, SUBSCRIPTION } from "./helpers/fixtures";

// Mobile-viewport coverage (run only by the "mobile" Playwright project — see
// playwright.config.ts) for the tables that used to force horizontal
// scrolling on a phone. Each one now stacks into cards below the `sm:`
// breakpoint instead: this checks the stacked layout actually renders the
// data (not just that the table "exists" in the DOM), and that nothing on
// the page forces the viewport to scroll sideways.

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

async function hasNoHorizontalOverflow(page: import("@playwright/test").Page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

test("scans list stacks into cards on a phone, with every column still readable", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: SCAN_ROWS });
  await mockApi(page, {});

  await page.goto("/dashboard/scans");
  await expect(page.getByRole("heading", { name: "Scans", level: 1 })).toBeVisible();

  // The column headers are desktop-only furniture; on mobile each row is its
  // own card and the labels move onto each value via a `data-label` instead.
  await expect(page.getByRole("columnheader", { name: "Target" })).toBeHidden();

  const row = page.getByRole("row").filter({ hasText: "example.com" }).first();
  await expect(row).toContainText("52/100");
  await expect(row).toContainText("completed");
  await expect(row.getByRole("link", { name: "View report →" })).toHaveAttribute("href", `/dashboard/scans/${SCAN_ID}`);

  expect(await hasNoHorizontalOverflow(page)).toBe(true);
});

test("remediation SLA findings stack into cards on a phone", async ({ page }) => {
  const slaBody = {
    access: true,
    available: true,
    resolvedWindowDays: 90,
    policy: { days: { critical: 15, high: 30, medium: 90, low: 180 }, warnDays: 3, alertsEnabled: true },
    summary: {
      open: 2,
      triaged: 0,
      onTrack: 1,
      dueSoon: 0,
      breached: 1,
      truncated: false,
      items: [
        {
          id: "f1",
          host: "example.com",
          checkId: "exposure.env",
          severity: "critical",
          title: "Exposed .env file",
          firstSeenAt: "2026-09-01T00:00:00Z",
          dueAt: "2026-09-16T00:00:00Z",
          daysRemaining: -5,
          state: "breached",
        },
        {
          id: "f2",
          host: "example.com",
          checkId: "headers.csp",
          severity: "high",
          title: "Missing Content-Security-Policy header",
          firstSeenAt: "2026-10-01T00:00:00Z",
          dueAt: "2026-10-31T00:00:00Z",
          daysRemaining: 19,
          state: "on_track",
        },
      ],
      resolved: {
        critical: { count: 1, medianDaysToFix: 4, withinSla: 1 },
        high: { count: 0, medianDaysToFix: null, withinSla: 0 },
        medium: { count: 0, medianDaysToFix: null, withinSla: 0 },
        low: { count: 0, medianDaysToFix: null, withinSla: 0 },
      },
      hosts: [{ host: "example.com", open: 2, dueSoon: 0, breached: 1 }],
    },
  };
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  await mockApi(page, { "GET /api/account/sla": { json: slaBody } });

  await page.goto("/dashboard/sla");
  await expect(page.getByRole("heading", { name: "Remediation SLAs" })).toBeVisible();

  await expect(page.getByRole("columnheader", { name: "Finding" })).toBeHidden();
  const row = page.getByRole("row").filter({ hasText: "Exposed .env file" });
  await expect(row).toContainText("example.com");
  await expect(row).toContainText("overdue");

  expect(await hasNoHorizontalOverflow(page)).toBe(true);
});

// Sanity check that the mock plumbing used `ACCESS_TOKEN` correctly rather
// than silently talking to no one — the SLA fetch must have carried it.
test("the SLA fetch is authenticated", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const api = await mockApi(page, {
    "GET /api/account/sla": {
      json: { access: true, available: false, policy: { days: { critical: 15, high: 30, medium: 90, low: 180 }, warnDays: 3, alertsEnabled: true }, summary: null },
    },
  });

  await page.goto("/dashboard/sla");
  await expect(page.getByText("SLA tracking isn't switched on yet")).toBeVisible();
  expect(api.to("GET", "/api/account/sla")[0]?.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
});
