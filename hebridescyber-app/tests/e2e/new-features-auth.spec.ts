import { test, expect } from "@playwright/test";
import { signIn, TEST_USER } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// Smaller features added from 2026-11-18: the estate map (#265), the weekly
// "one thing to fix" switch (#255), the security evidence pack (#264) and the
// repository-linking prompt (#267). Every API call is mocked.

const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("the estate map lists every host with its web status, certificate and open issues", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  await mockApi(page, {
    "GET /api/estate/map": {
      json: {
          domains: [
            {
              domain: "example.com",
              hosts: [
                { host: "www.example.com", kind: "domain", firstSeenAt: "2026-10-01T00:00:00Z", lastSeenAt: "2026-11-19T00:00:00Z", web: { statusCode: 200, title: "Example shop", webserver: "nginx", url: "https://www.example.com" }, certificate: { expiresAt: "2026-11-29T00:00:00Z", daysLeft: 9, issuer: "Let's Encrypt" }, exposedPorts: [], openFindings: { ...zero, high: 1 }, scanId: null },
                { host: "old.example.com", kind: "subdomain", firstSeenAt: "2026-10-01T00:00:00Z", lastSeenAt: "2026-11-19T00:00:00Z", web: null, certificate: null, exposedPorts: ["3389"], openFindings: zero, scanId: null },
              ],
            },
          ],
          totals: { hosts: 2, live: 1, certificatesExpiringSoon: 1, withCriticalOrHigh: 1 },
      },
    },
  });

  await page.goto("/dashboard/assets");
  const map = page.locator("section", { has: page.locator("#estate-map-heading") });
  await expect(map.getByText("www.example.com")).toBeVisible();
  await expect(map.getByText("old.example.com")).toBeVisible();
  await expect(map.getByText("3389")).toBeVisible();
});

test("the weekly 'one thing to fix' email can be switched off", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const api = await mockApi(page, {
    "GET /api/account/notification-prefs": { json: { notify_email: true, notify_score_threshold: null, notify_severity_min: null, notify_weekly_fix: true } },
    "PATCH /api/account/notification-prefs": { json: { ok: true } },
  });

  await page.goto("/dashboard/integrations");
  const weekly = page.getByRole("checkbox", { name: /Weekly .one thing to fix. email/ });
  await expect(weekly).toBeChecked();
  await weekly.uncheck();
  await page.getByRole("button", { name: "Save preferences" }).click();

  await expect.poll(() => api.to("PATCH", "/api/account/notification-prefs").length).toBeGreaterThan(0);
  expect(api.to("PATCH", "/api/account/notification-prefs")[0].body).toMatchObject({ notify_weekly_fix: false });
});

test("the Cyber Essentials page downloads the security evidence pack", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  await mockApi(page, {});
  const packs: string[] = [];
  await page.route("**/api/account/evidence-pack**", (route) => {
    packs.push(route.request().url());
    return route.fulfill({ status: 200, contentType: "application/pdf", body: "%PDF-1.4 e2e" });
  });

  await page.goto("/dashboard/cyber-essentials");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download evidence pack" }).click();
  expect((await download).suggestedFilename()).toMatch(/\.pdf$/);
  expect(packs).toHaveLength(1);
});

test("an owner with a repository not linked to a site is prompted to link it", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], repo_connections: [{ id: "r1", owner: TEST_USER.id, github_repo: "acme/site", target_host: null, connected_at: "2026-11-01T00:00:00Z" }] });
  await mockApi(page, { "GET /api/emerging-threats": { json: { available: true, alerts: [] } } });

  await page.goto("/dashboard");
  await expect(page.getByText(/acme\/site/).first()).toBeVisible();
  await expect(page.getByRole("link", { name: "Choose its site" })).toHaveAttribute("href", /integrations/);
});
