import { test, expect, type Page } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase, type ApiCall } from "./helpers/mocks";

// The admin panel's Lookout reports tab (#242, #252, #256): find a customer by
// email, create a draft, edit and publish it, unpublish to correct, preview the
// PDF, and a report the customer acknowledged is read-only. Every API call is
// mocked; the admin gate is /api/admin/metrics answering 200.

const REPORT_ID = "cccccccc-0000-4000-8000-000000000001";
const CUSTOMER = "owner@shop.example";

type Status = "draft" | "published" | "acknowledged";

function detail(status: Status) {
  return {
    report: {
      id: REPORT_ID, customer: "11111111-2222-4333-8444-555555555555", customer_email: CUSTOMER,
      period_start: "2026-11-13", period_end: "2026-11-20", status, summary: "Two things to fix this week.",
      published_at: status === "draft" ? null : "2026-11-20T09:00:00Z", acknowledged_at: status === "acknowledged" ? "2026-11-21T09:00:00Z" : null,
    },
    items: [
      { id: "i1", host: "shop.example", check_id: "tls.expiry", severity: "high", title: "Certificate expires in 9 days", included: true, priority: 1, analyst_note: "", business_impact: "", fix_owner: "unknown" },
      { id: "i2", host: "old.shop.example", check_id: "headers.hsts", severity: "low", title: "No HSTS header", included: true, priority: 2, analyst_note: "", business_impact: "", fix_owner: "unknown" },
    ],
  };
}

/** A list row is the report without its summary. */
const listRow = (status: Status) => {
  const row: Partial<ReturnType<typeof detail>["report"]> = { ...detail(status).report };
  delete row.summary;
  return row;
};

/** Signs in as an admin and opens the Lookout reports tab, with the report endpoints answering `status`. */
async function openTab(page: Page, opts: { status?: Status; list?: boolean; extra?: Record<string, (call: ApiCall) => { status?: number; json: unknown }> } = {}) {
  let status: Status = opts.status ?? "draft";
  let metricsCalls = 0;
  await mockSupabase(page, {});
  const api = await mockApi(page, {
    // First call is the page's admin gate; the Overview tab's own read then
    // fails, which it shows as an error rather than rendering empty metrics.
    "GET /api/admin/metrics": () => (metricsCalls++ === 0 ? { json: {} } : { status: 503, json: { error: "metrics not mocked" } }),
    "GET /api/admin/lookout/reports": () => ({ json: { reports: opts.list === false ? [] : [listRow(status)] } }),
    "POST /api/admin/lookout/reports": () => ({ json: { report: listRow("draft") } }),
    [`GET /api/admin/lookout/reports/${REPORT_ID}`]: () => ({ json: detail(status) }),
    [`PATCH /api/admin/lookout/reports/${REPORT_ID}`]: (call) => {
      const next = (call.body as { status?: Status }).status;
      if (next) status = next;
      return { json: { ok: true } };
    },
    ...opts.extra,
  });
  await page.goto("/admin");
  await page.getByRole("button", { name: "Lookout reports" }).click();
  return api;
}

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("an admin finds the customer by email, drafts a report, edits it and publishes it", async ({ page }) => {
  const api = await openTab(page, { list: false });
  const create = page.getByRole("button", { name: "New draft report" });

  // Only an email address or a user id can start a draft.
  await page.getByLabel("Customer email or user id").fill("not an email");
  await expect(create).toBeDisabled();
  await page.getByLabel("Customer email or user id").fill(CUSTOMER);
  await expect(create).toBeEnabled();
  await page.getByLabel("Period").selectOption("7");
  await create.click();

  await expect(page.getByRole("heading", { name: /Report 2026-11-13 to 2026-11-20 · draft/ })).toBeVisible();
  expect(api.to("POST", "/api/admin/lookout/reports")[0]).toMatchObject({ body: { customer: CUSTOMER, period_days: 7 }, authorization: `Bearer ${ACCESS_TOKEN}` });

  await page.getByLabel("Summary for the customer").fill("One urgent fix: renew the certificate.");
  await page.getByLabel("Priority for No HSTS header").fill("5");
  await page.locator("li", { hasText: "No HSTS header" }).getByRole("checkbox").uncheck();
  const cert = page.locator("li", { hasText: "Certificate expires in 9 days" });
  await cert.getByPlaceholder("What this means for them and what to do").fill("Ask your IT supplier to renew it this week.");
  await cert.getByPlaceholder("Business impact, in one line").fill("Visitors would see a browser warning.");
  await page.getByLabel("Who fixes Certificate expires in 9 days").selectOption("it_supplier");
  await page.getByRole("button", { name: "Save and publish" }).click();

  await expect(page.getByRole("status")).toHaveText("Published. The customer can now read it.");
  const patch = api.to("PATCH", `/api/admin/lookout/reports/${REPORT_ID}`)[0];
  expect(patch.body).toEqual({
    summary: "One urgent fix: renew the certificate.",
    status: "published",
    items: [
      { id: "i1", included: true, priority: 1, analyst_note: "Ask your IT supplier to renew it this week.", business_impact: "Visitors would see a browser warning.", fix_owner: "it_supplier" },
      { id: "i2", included: false, priority: 5, analyst_note: "", business_impact: "", fix_owner: "unknown" },
    ],
  });
  // Re-opened from the server: now published, so it offers to unpublish.
  await expect(page.getByRole("button", { name: "Unpublish to correct" })).toBeVisible();
});

test("saving without publishing keeps a draft, and a published report can be taken back to correct", async ({ page }) => {
  const api = await openTab(page, { status: "published" });
  await page.getByRole("row", { name: /published/ }).getByRole("button", { name: "Open" }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");
  expect((api.to("PATCH", `/api/admin/lookout/reports/${REPORT_ID}`)[0].body as Record<string, unknown>).status).toBeUndefined();

  await page.getByRole("button", { name: "Unpublish to correct" }).click();
  await expect(page.getByRole("status")).toHaveText("Moved back to draft.");
  expect((api.to("PATCH", `/api/admin/lookout/reports/${REPORT_ID}`)[1].body as Record<string, unknown>).status).toBe("draft");
  await expect(page.getByRole("button", { name: "Save and publish" })).toBeVisible();
});

test("a report the customer has acknowledged is read-only", async ({ page }) => {
  await openTab(page, { status: "acknowledged" });
  await page.getByRole("button", { name: "Open" }).click();
  await expect(page.getByText("The customer has acknowledged this report, so it can no longer be changed.")).toBeVisible();
  await expect(page.getByLabel("Summary for the customer")).toBeDisabled();
  await expect(page.getByLabel("Who fixes Certificate expires in 9 days")).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Unpublish to correct" })).toHaveCount(0);
  // The saved PDF can still be previewed.
  await expect(page.getByRole("button", { name: "Preview PDF (saved version)" })).toBeEnabled();
});

test("the list shows the customer's email, and a failed draft says why", async ({ page }) => {
  await openTab(page, {
    extra: { "POST /api/admin/lookout/reports": () => ({ status: 404, json: { error: "No customer with that email." } }) },
  });
  await expect(page.getByRole("row", { name: new RegExp(CUSTOMER) })).toBeVisible();
  await page.getByLabel("Customer email or user id").fill("nobody@shop.example");
  await page.getByRole("button", { name: "New draft report" }).click();
  await expect(page.getByRole("status")).toHaveText("No customer with that email.");
});

test("previewing the PDF asks the admin route with the admin's token and opens it", async ({ page }) => {
  const api = await openTab(page, {
    extra: { "GET /api/admin/lookout/report-pdf": () => ({ json: { pdf: "stub" } }) },
  });
  await page.getByRole("button", { name: "Open" }).click();
  const popup = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Preview PDF (saved version)" }).click();
  await popup;
  expect(api.to("GET", "/api/admin/lookout/report-pdf")[0].authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
});

test("a PDF that can't be rendered shows the server's reason", async ({ page }) => {
  await openTab(page, {
    extra: { "GET /api/admin/lookout/report-pdf": () => ({ status: 500, json: { error: "PDF rendering is unavailable." } }) },
  });
  await page.getByRole("button", { name: "Open" }).click();
  await page.getByRole("button", { name: "Preview PDF (saved version)" }).click();
  await expect(page.getByRole("status")).toHaveText("PDF rendering is unavailable.");
});

test("a signed-in non-admin is refused the admin panel", async ({ page }) => {
  await mockSupabase(page, {});
  await mockApi(page, { "GET /api/admin/metrics": { status: 403, json: { error: "Forbidden" } } });
  await page.goto("/admin");
  await expect(page.getByRole("heading", { name: "Admin access required" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Lookout reports" })).toHaveCount(0);
});
