import { test, expect } from "@playwright/test";

// /plan/<token>: a shared fix plan (src/lib/fixPlans.ts). The plan API is
// mocked at the network layer, so no database is needed.
const TOKEN = "A".repeat(43);

type Item = { checkId: string; position: number; severity: string; title: string; remediation: string; status: string; fixedAt: string | null; markedDoneAt: string | null; note: string };
type Plan = { title: string; host: string; createdAt: string; expiresAt: string; progress: { fixed: number; markedDone: number; open: number; total: number }; items: Item[] };

const plan: Plan = {
  title: "Before go-live",
  host: "shop.example.com",
  createdAt: "2026-11-01T00:00:00Z",
  expiresAt: "2027-01-30T00:00:00Z",
  progress: { fixed: 1, markedDone: 0, open: 1, total: 2 },
  items: [
    { checkId: "tls.old", position: 1, severity: "high", title: "Old TLS versions accepted", remediation: "Turn off TLS 1.0 and 1.1.", status: "fixed", fixedAt: "2026-11-10T00:00:00Z", markedDoneAt: null, note: "" },
    { checkId: "headers.hsts", position: 2, severity: "medium", title: "Missing HSTS", remediation: "Add the Strict-Transport-Security header.", status: "open", fixedAt: null, markedDoneAt: null, note: "" },
  ],
};

test("a shared fix plan shows progress and lets the person with the link mark an item done", async ({ page }) => {
  let current: Plan = plan;
  let posted: unknown = null;
  await page.route(`**/api/plans/${TOKEN}`, (route) => route.fulfill({ json: current }));
  await page.route(`**/api/plans/${TOKEN}/done`, async (route) => {
    posted = route.request().postDataJSON();
    current = {
      ...plan,
      progress: { fixed: 1, markedDone: 1, open: 0, total: 2 },
      items: [plan.items[0], { ...plan.items[1], status: "marked_done", markedDoneAt: "2026-11-20T00:00:00Z", note: "Added in Cloudflare" }],
    };
    await route.fulfill({ json: { ok: true, markedDoneAt: "2026-11-20T00:00:00Z" } });
  });

  await page.goto(`/plan/${TOKEN}`);
  await expect(page.getByRole("heading", { level: 1, name: "Before go-live" })).toBeVisible();
  await expect(page.getByText("fixed and confirmed")).toBeVisible();
  await expect(page.getByText(/Fixed, confirmed by a scan/)).toBeVisible();
  await expect(page.getByText("Add the Strict-Transport-Security header.")).toBeVisible();

  await page.getByLabel(/Note for them/).fill("Added in Cloudflare");
  await page.getByRole("button", { name: "I've done this" }).click();
  await expect(page.getByText(/Marked done, waiting for a scan to confirm/)).toBeVisible();
  expect(posted).toEqual({ checkId: "headers.hsts", done: true, note: "Added in Cloudflare" });
});

test("an invalid or expired link says so", async ({ page }) => {
  await page.route(`**/api/plans/${TOKEN}`, (route) =>
    route.fulfill({ status: 404, json: { error: "This fix plan link isn't valid any more. Ask whoever sent it for a new one." } })
  );
  await page.goto(`/plan/${TOKEN}`);
  await expect(page.getByText(/isn't valid any more/)).toBeVisible();
});

test("the plan page is kept out of search engines", async ({ page }) => {
  await page.route(`**/api/plans/${TOKEN}`, (route) => route.fulfill({ json: plan }));
  await page.goto(`/plan/${TOKEN}`);
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
});
