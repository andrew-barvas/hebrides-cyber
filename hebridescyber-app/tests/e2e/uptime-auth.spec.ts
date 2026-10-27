import { test, expect, type Page } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// Bring-your-own UptimeRobot monitoring (Pro and above): the Integrations card
// and the uptime badges on Assets -> monitored sites. Every /api/* call is
// mocked (helpers/mocks.ts), so neither UptimeRobot nor Supabase is reached,
// and the API key typed here is a made-up test value.

const TEST_KEY = "ur-e2e-test-key-0001";

const CONNECTED = {
  allowed: true,
  connected: true,
  lastSyncAt: "2026-10-26T12:00:00Z",
  lastError: null,
  monitors: [
    { target_url: "https://shop.example.co.uk", last_status: "down", last_status_at: null, state_duration_seconds: 600, last_checked_at: "2026-10-26T12:00:00Z", missing: false },
    { target_url: "https://gone.example.co.uk", last_status: "up", last_status_at: null, state_duration_seconds: 7200, last_checked_at: "2026-10-25T12:00:00Z", missing: true },
  ],
  unmonitored: ["https://blog.example.co.uk"],
};
const NOT_CONNECTED = { allowed: true, connected: false, monitors: [], unmonitored: [] };

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

async function openUptimeCard(page: Page) {
  await page.goto("/dashboard/integrations");
  const card = page.locator("details", { has: page.locator("summary", { hasText: "Uptime monitoring" }) });
  await card.locator("summary").click();
  return card;
}

test("a Pro account connects its own UptimeRobot key, which is never shown back", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  let connected = false;
  const api = await mockApi(page, {
    "GET /api/uptime/status": () => ({ json: connected ? CONNECTED : NOT_CONNECTED }),
    "POST /api/account/uptime-integration": () => {
      connected = true;
      return { json: { ok: true, provider: "uptimerobot" } };
    },
  });

  const card = await openUptimeCard(page);
  await card.getByLabel("UptimeRobot API key").fill(TEST_KEY);
  await card.getByRole("button", { name: "Connect" }).click();

  await expect(card.getByText("Connected. Now create monitors for your verified sites.")).toBeVisible();
  const [save] = api.to("POST", "/api/account/uptime-integration");
  expect(save.body).toEqual({ apiKey: TEST_KEY });
  expect(save.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);

  // Statuses as UptimeRobot reported them; a monitor the last sync didn't find is not shown as up.
  // The status and its duration share one element ("Down for 10 min"), so match the text, not the bare word.
  await expect(card.getByText("Down for 10 min")).toBeVisible();
  await expect(card.getByText("Not found in UptimeRobot")).toBeVisible();
  await expect(card.getByText(/^Up/)).toHaveCount(0);
  // The form is gone and the key appears nowhere on the page.
  await expect(card.getByLabel("UptimeRobot API key")).toHaveCount(0);
  expect(await page.content()).not.toContain(TEST_KEY);
});

test("creates monitors for sites that have none and reports what happened to each", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const api = await mockApi(page, {
    "GET /api/uptime/status": { json: CONNECTED },
    "POST /api/uptime/monitors": { json: { results: [{ targetUrl: "https://blog.example.co.uk", result: "not_verified" }] } },
  });

  const card = await openUptimeCard(page);
  await card.getByRole("button", { name: "Create monitors for 1 site" }).click();

  await expect(card.getByText("https://blog.example.co.uk: verify this domain first (Assets)")).toBeVisible();
  expect(api.to("POST", "/api/uptime/monitors")[0].body).toEqual({ targetUrls: ["https://blog.example.co.uk"] });
});

test("below Pro the card is locked and the uptime API is never called", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [{ ...SUBSCRIPTION, plan: "basic" }] });
  const api = await mockApi(page, {});

  await page.goto("/dashboard/integrations");
  await expect(page.getByText(/Connect your own UptimeRobot account to watch your verified sites/)).toBeVisible();
  await expect(page.locator("summary", { hasText: "Uptime monitoring" })).toHaveCount(0);
  expect(api.to("GET", "/api/uptime/status")).toHaveLength(0);
});

test("monitored sites show each site's uptime from the connected account", async ({ page }) => {
  await mockSupabase(page, {
    subscriptions: [SUBSCRIPTION],
    monitored_targets: [
      { id: "t1", owner: "e2e-user", target_url: "https://shop.example.co.uk/", created_at: "2026-10-01T00:00:00Z", scan_profile: "full" },
      { id: "t2", owner: "e2e-user", target_url: "https://gone.example.co.uk", created_at: "2026-10-02T00:00:00Z", scan_profile: "full" },
      { id: "t3", owner: "e2e-user", target_url: "https://blog.example.co.uk", created_at: "2026-10-03T00:00:00Z", scan_profile: "full" },
    ],
  });
  await mockApi(page, { "GET /api/uptime/status": { json: CONNECTED } });

  await page.goto("/dashboard/assets");
  await expect(page.getByText("Uptime: Down")).toBeVisible();
  await expect(page.getByText("Uptime: Not found in UptimeRobot")).toBeVisible();
  // The site with no monitor gets no badge rather than a guessed status.
  await expect(page.getByText(/^Uptime:/)).toHaveCount(2);
});
