import { test, expect, type Page } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { findingCard, openFindingTitles, openReport as openReportPage } from "./helpers/report";
import { SCAN_ID } from "./helpers/fixtures";
import { triageApi, triageRecord } from "./helpers/triage";

// Finding triage on the scan report: Mark as… (accepted/authorised, false
// positive, snooze) -> PUT /api/findings/triage, and Undo -> DELETE. The API
// is a stateful mock (helpers/triage.ts), so the UI is asserted against what
// the page was actually told, not against hard-coded responses.

const CSP = "Missing Content-Security-Policy header";
const SCRIPT = "Third-party script from cdn.example.net";

async function openReport(page: Page, handlers: Parameters<typeof openReportPage>[1] = {}) {
  const api = await openReportPage(page, handlers);
  // "Mark as…" only renders once the triage GET has confirmed it is available.
  await expect(page.getByRole("button", { name: "Mark as…" }).first()).toBeVisible();
  return api;
}


test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("accepting a third-party script as authorised requires and sends a justification", async ({ page }) => {
  const api = await openReport(page);
  await findingCard(page, SCRIPT).getByRole("button", { name: "Mark as…" }).click();

  // Accepted / authorised is the default choice. Save stays disabled until a reason is given.
  const save = page.getByRole("button", { name: "Save" });
  await expect(page.getByRole("button", { name: "Accepted / authorised" })).toHaveAttribute("aria-pressed", "true");
  await expect(save).toBeDisabled();
  await page.getByLabel("Reason (required)").fill("Our own CDN, approved by the security lead on 2026-10-01");
  await expect(save).toBeEnabled();
  await save.click();

  // Moves out of the open list into the Triaged group, with its reason.
  await expect(page.getByText("Triaged (1)")).toBeVisible();
  await expect(openFindingTitles(page)).toHaveCount(3);
  await page.getByText("Triaged (1)").click();
  const triaged = page.locator("details", { hasText: "Triaged (1)" });
  await expect(triaged.getByText(SCRIPT, { exact: true })).toBeVisible();
  await expect(triaged.getByText("Our own CDN, approved by the security lead on 2026-10-01")).toBeVisible();
  await expect(triaged.getByText("Accepted / authorised", { exact: true })).toBeVisible();

  const [put] = api.to("PUT", "/api/findings/triage");
  expect(put.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(put.body).toEqual({
    scanId: SCAN_ID,
    checkId: "script-inventory.unreviewed:cdn.example.net",
    reason: "Our own CDN, approved by the security lead on 2026-10-01",
    state: "accepted_risk",
    expiresAt: null,
  });
});

test("marking a finding as a false positive removes it from the open counts", async ({ page }) => {
  const api = await openReport(page);
  await expect(page.getByText("2 critical/high findings found.")).toBeVisible();

  await findingCard(page, CSP).getByRole("button", { name: "Mark as…" }).click();
  await page.getByRole("button", { name: "False positive" }).click();
  await page.getByLabel("Reason (required)").fill("Header is set by the CDN edge, not visible to the scanner");
  await page.getByRole("button", { name: "Save" }).click();

  await expect(page.getByText("1 triaged", { exact: true })).toBeVisible();
  await expect(page.getByText("1 critical/high finding found.")).toBeVisible();
  await expect(openFindingTitles(page)).toHaveText(["Exposed .env file", "No SPF record", SCRIPT]);

  const [put] = api.to("PUT", "/api/findings/triage");
  expect(put.body).toMatchObject({ checkId: "headers.csp", state: "false_positive", expiresAt: null });
});

test("snoozing sends an expiry about N days out", async ({ page }) => {
  const api = await openReport(page);
  await findingCard(page, "No SPF record").getByRole("button", { name: "Mark as…" }).click();
  await page.getByRole("button", { name: "Snooze 30 days" }).click();
  await page.getByLabel("Reason (required)").fill("Mail moves to the new provider next month");
  await page.getByRole("button", { name: "Save" }).click();

  await expect(page.getByText("Triaged (1)")).toBeVisible();
  const [put] = api.to("PUT", "/api/findings/triage");
  const body = put.body as { state: string; expiresAt: string };
  expect(body.state).toBe("snoozed");
  const days = (new Date(body.expiresAt).getTime() - Date.now()) / 86_400_000;
  expect(days).toBeGreaterThan(29.9);
  expect(days).toBeLessThanOrEqual(30);
});

test("a rejected save keeps the form open and shows the error", async ({ page }) => {
  await openReport(page, { "PUT /api/findings/triage": { status: 503, json: { error: "Finding triage is not available yet." } } });
  await findingCard(page, CSP).getByRole("button", { name: "Mark as…" }).click();
  await page.getByLabel("Reason (required)").fill("Because I said so");
  await page.getByRole("button", { name: "Save" }).click();

  await expect(page.getByRole("alert").filter({ hasText: "Finding triage is not available yet." })).toBeVisible();
  await expect(findingCard(page, CSP)).toBeVisible();
  await expect(page.getByText("Triaged (1)")).toHaveCount(0);
});

test("undo puts a triaged finding back in the open list", async ({ page }) => {
  const api = await openReport(
    page,
    triageApi([triageRecord("headers.csp", "false_positive", "Set at the CDN edge, scanner cannot see it")])
  );

  // Starts triaged: out of the open list, listed in the Triaged group with its reason.
  await expect(page.getByText("Triaged (1)")).toBeVisible();
  await expect(openFindingTitles(page)).toHaveCount(3);
  await page.getByText("Triaged (1)").click();
  const triaged = page.locator("details", { hasText: "Triaged (1)" });
  await expect(triaged.getByText("Set at the CDN edge, scanner cannot see it")).toBeVisible();
  await expect(triaged.getByText(/False positive by e2e@example\.com on/)).toBeVisible();

  await triaged.getByRole("button", { name: "Undo" }).click();

  await expect(page.getByText("Triaged (1)")).toHaveCount(0);
  await expect(openFindingTitles(page)).toHaveCount(4);
  await expect(findingCard(page, CSP).getByRole("button", { name: "Mark as…" })).toBeVisible();

  const [del] = api.to("DELETE", "/api/findings/triage");
  expect(del.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(del.body).toEqual({ scanId: SCAN_ID, checkId: "headers.csp" });
});

test("when triage is unavailable (migration not applied) no Mark as… controls render", async ({ page }) => {
  const api = await openReportPage(page, { "GET /api/findings/triage": { json: { available: false, host: "example.com", items: [] } } });
  await expect(openFindingTitles(page)).toHaveCount(4);
  await expect.poll(() => api.to("GET", "/api/findings/triage").length).toBe(1);
  await expect(page.getByRole("button", { name: "Mark as…" })).toHaveCount(0);
});
