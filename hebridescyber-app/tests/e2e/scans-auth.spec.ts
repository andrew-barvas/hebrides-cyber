import { test, expect } from "@playwright/test";
import { signIn, ACCESS_TOKEN, TEST_USER } from "./helpers/session";
import { applyQuery, mockApi, mockSupabase } from "./helpers/mocks";
import { QUEUED_SCAN_ID, SCAN_ID, SCAN_ROWS, SUBSCRIPTION } from "./helpers/fixtures";

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("scans page lists the account's scans with status, score and report links", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: SCAN_ROWS });
  await mockApi(page, {});

  await page.goto("/dashboard/scans");
  await expect(page.getByRole("heading", { name: "Scans", level: 1 })).toBeVisible();

  const rows = page.getByRole("row").filter({ hasText: "example.com" });
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("52/100");
  await expect(rows.first()).toContainText("completed");
  await expect(rows.first().getByRole("link", { name: "View report →" })).toHaveAttribute("href", `/dashboard/scans/${SCAN_ID}`);
});

test("an account with no scans sees the empty list", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: [] });
  await mockApi(page, {});

  await page.goto("/dashboard/scans");
  await expect(page.getByText("No scans yet.")).toBeVisible();
});

test("starting a scan creates it, queues it, and shows it as queued in the list", async ({ page }) => {
  // The scans table changes as the flow progresses, like the real one.
  const scans: Record<string, unknown>[] = [];
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: (url) => applyQuery(scans, url) });
  const api = await mockApi(page, {
    "POST /api/run-scan": (call) => {
      const body = call.body as { targetUrl?: string; scanId?: string };
      if (body.targetUrl) {
        // Step 1: the scan row exists (pending) and the client gets a proof token.
        scans.unshift({
          id: QUEUED_SCAN_ID,
          target_url: body.targetUrl,
          status: "pending",
          created_at: new Date().toISOString(),
          owner: TEST_USER.id,
          scan_results: [],
        });
        return { json: { scanId: QUEUED_SCAN_ID, proofToken: "proof-token-1" } };
      }
      // Step 2 (and every poll): the job is on the queue.
      scans[0].status = "queued";
      return { status: 202, json: { status: "queued", message: "Scan queued. A runner usually picks it up within a minute." } };
    },
  });

  await page.goto("/dashboard/scans");
  await page.getByLabel("Website URL").fill("https://example.com");
  await page.getByRole("button", { name: "Run scan" }).click();

  // The queued message from the API is shown, and the new row's badge follows it.
  await expect(page.getByText("Scan queued. A runner usually picks it up within a minute.")).toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "https://example.com" });
  await expect(row).toContainText("queued");
  // Not completed, so there is no report to link to yet.
  await expect(row.getByRole("link", { name: "View report →" })).toHaveCount(0);

  // Exactly the documented two-step contract, authenticated as the session user.
  const posts = api.to("POST", "/api/run-scan");
  expect(posts[0].body).toEqual({ targetUrl: "https://example.com" });
  expect(posts[1].body).toEqual({ scanId: QUEUED_SCAN_ID });
  for (const call of posts) expect(call.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
});

test("scanning a domain that is not verified explains how to fix it", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION], scans: [] });
  await mockApi(page, {
    "POST /api/run-scan": (call) =>
      (call.body as { targetUrl?: string }).targetUrl
        ? { json: { scanId: QUEUED_SCAN_ID, proofToken: "proof-token-1" } }
        : { status: 403, json: { error: "Verify ownership of this domain before scanning it.", code: "domain_not_verified" } },
  });

  await page.goto("/dashboard/scans");
  await page.getByLabel("Website URL").fill("https://unverified.example.org");
  await page.getByRole("button", { name: "Run scan" }).click();

  await expect(page.getByText("Verify this domain first")).toBeVisible();
  await expect(page.getByRole("link", { name: "Go to domain verification →" })).toHaveAttribute("href", "/dashboard/assets#domain-verification");
  // The submit button is usable again.
  await expect(page.getByRole("button", { name: "Run scan" })).toBeEnabled();
});
