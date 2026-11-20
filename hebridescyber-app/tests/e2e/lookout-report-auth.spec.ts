import { test, expect } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// The customer's Lookout report page (/dashboard/lookout/<id>): the engineer's
// items (#242), "I've read this report", the dated PDF (#252), lookalike
// domains (#253) and breached accounts (#258). Every API call is mocked.

const REPORT_ID = "bbbbbbbb-0000-4000-8000-000000000001";

const REPORT = {
  report: {
    id: REPORT_ID, period_start: "2026-10-21", period_end: "2026-11-20", status: "published",
    summary: "In this period 1 new issue appeared and 2 were fixed; 3 remain open.", published_at: "2026-11-20T09:00:00Z", acknowledged_at: null,
  },
  items: [
    { id: "i1", host: "shop.example.com", severity: "high", title: "Certificate expires in 9 days", priority: 1, analyst_note: "Ask your IT supplier to renew it.", business_impact: "Visitors would see a browser warning.", fix_owner: "it_supplier" },
  ],
  galleryScanId: null,
  lookalikes: { available: true, newInPeriod: [{ domain: "exmple.com", targetDomain: "example.com", how: "a character removed", spottedAt: "2026-11-10T08:00:00Z" }], totalKnown: 3 },
  breaches: {
    available: true,
    sites: [{ host: "example.com", status: "checked", affectedAliasCount: 2, breaches: [{ name: "AcmeLeak", title: "Acme Leak", breachDate: "2025-06-01", affectedAliasCount: 2, dataClasses: ["Email addresses", "Passwords"] }] }],
  },
};

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("a customer reads their report, marks it read, and downloads the PDF", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  let acknowledged = false;
  const api = await mockApi(page, {
    [`GET /api/lookout/reports/${REPORT_ID}`]: () => ({ json: acknowledged ? { ...REPORT, report: { ...REPORT.report, status: "acknowledged", acknowledged_at: "2026-11-21T10:00:00Z" } } : REPORT }),
    [`POST /api/lookout/reports/${REPORT_ID}`]: () => {
      acknowledged = true;
      return { json: { acknowledged: true, acknowledged_at: "2026-11-21T10:00:00Z" } };
    },
  });
  // The PDF is a binary download, so it's routed separately from the JSON mocks.
  const pdfRequests: string[] = [];
  await page.route("**/api/lookout/report-pdf**", (route) => {
    pdfRequests.push(route.request().url());
    return route.fulfill({ status: 200, contentType: "application/pdf", body: "%PDF-1.4 e2e" });
  });

  await page.goto(`/dashboard/lookout/${REPORT_ID}`);
  await expect(page.getByRole("heading", { name: "Lookout report: 2026-10-21 to 2026-11-20" })).toBeVisible();
  await expect(page.getByText("Certificate expires in 9 days")).toBeVisible();
  await expect(page.getByText("Who fixes it: Your IT supplier")).toBeVisible();

  // Lookalikes and breached accounts.
  await expect(page.getByRole("heading", { name: "Lookalike domains" })).toBeVisible();
  await expect(page.getByText("exmple.com")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Email addresses in known data breaches" })).toBeVisible();
  await expect(page.getByText(/Acme Leak \(2025-06-01\): 2 addresses/)).toBeVisible();

  // The dated PDF.
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PDF" }).click();
  expect((await download).suggestedFilename()).toBe("lookout-report-2026-11-20.pdf");
  expect(new URL(pdfRequests[0]).searchParams.get("id")).toBe(REPORT_ID);

  // Marking it read.
  await page.getByRole("button", { name: "I've read this report" }).click();
  await expect(page.getByText(/You marked this report as read on/)).toBeVisible();
  const [ack] = api.to("POST", `/api/lookout/reports/${REPORT_ID}`);
  expect(ack.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(ack.body).toEqual({ action: "acknowledge" });
});

test("a report that can't be found says so", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  await mockApi(page, { [`GET /api/lookout/reports/${REPORT_ID}`]: { status: 404, json: { error: "Report not found" } } });
  await page.goto(`/dashboard/lookout/${REPORT_ID}`);
  await expect(page.getByRole("alert")).toHaveText("Report not found.");
});
