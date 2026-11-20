import { test, expect } from "@playwright/test";
import { signIn, ACCESS_TOKEN, TEST_USER } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// Findings Explorer (/dashboard/findings): assigning findings to a team member
// (#249) and a team member reading the owner's findings, read-only, filtered
// to what's assigned to them (#250). Every API call is mocked.

const OWNER = TEST_USER.id;
const DEV = "22222222-2222-4222-8222-222222222222";
const BOSS = "33333333-3333-4333-8333-333333333333";

const row = (over: Record<string, unknown>) => ({
  key: "a.example headers.hsts", host: "a.example", checkId: "headers.hsts", checkBase: "headers.hsts", category: "headers",
  severity: "medium", title: "Missing HSTS", detail: null, firstSeenAt: "2026-10-01T00:00:00Z", ageDays: 50, slaState: null, slaDueAt: null,
  knownExploited: false, ransomware: false, epss: null, cvssScore: null, cveIds: [], scanId: null, triage: null, exploitabilityAssessment: null, assignee: null,
  ...over,
});

const ROWS = [
  row({}),
  row({ key: "b.example headers.hsts", host: "b.example" }),
  row({ key: "a.example dns.spf", checkId: "dns.spf", checkBase: "dns.spf", category: "dns", title: "No SPF record", severity: "high", assignee: { id: DEV, email: "dev@example.com" } }),
];

function listBody(rows: typeof ROWS, readOnly = false) {
  return {
    available: true, readOnly, triageAvailable: true, slaEnabled: false, detailComplete: true, truncated: false,
    facets: { sites: [{ value: "a.example", count: 2 }, { value: "b.example", count: 1 }], categories: [{ value: "headers", count: 2 }, { value: "dns", count: 1 }], severities: { critical: 0, high: 1, medium: 2, low: 0, info: 0 }, knownExploited: 0 },
    view: "rows", sort: "severity", totalFindings: rows.length, items: rows, groups: [], page: 1, pageSize: 50, total: rows.length, pageCount: 1,
  };
}

const ASSIGNEES = [
  { id: OWNER, email: TEST_USER.email, role: "owner" },
  { id: DEV, email: "dev@example.com", role: "developer" },
];

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("the owner assigns selected findings to a team member", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const api = await mockApi(page, {
    "GET /api/findings": { json: listBody(ROWS) },
    "GET /api/findings/accounts": { json: { accounts: [{ ownerId: OWNER, email: null, role: "owner", own: true }] } },
    "GET /api/findings/assign": { json: { available: true, assignees: ASSIGNEES } },
    "PUT /api/findings/assign": { json: { count: 1, assignee: ASSIGNEES[1] } },
  });

  await page.goto("/dashboard/findings");
  await expect(page.getByText("Assigned to dev@example.com").first()).toBeVisible();

  await page.getByRole("checkbox", { name: "Select Missing HSTS on a.example" }).check();
  await page.getByLabel("Assign to").selectOption(DEV);
  await page.getByRole("button", { name: "Assign" }).click();

  await expect(page.getByText("1 finding assigned to dev@example.com.")).toBeVisible();
  const [put] = api.to("PUT", "/api/findings/assign");
  expect(put.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(put.body).toEqual({ items: [{ targetHost: "a.example", checkId: "headers.hsts" }], titles: ["Missing HSTS"], assigneeId: DEV });
});

test("a team member opens the owner's findings read-only, filtered to what's assigned to them", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const listUrls: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).pathname === "/api/findings") listUrls.push(r.url());
  });
  await mockApi(page, {
    "GET /api/findings": { json: listBody(ROWS.slice(2), true) },
    "GET /api/findings/accounts": { json: { accounts: [{ ownerId: OWNER, email: null, role: "owner", own: true }, { ownerId: BOSS, email: "boss@example.com", role: "member", own: false }] } },
    "GET /api/findings/assign": { json: { available: true, assignees: [] } },
  });

  // The assignment email's link.
  await page.goto(`/dashboard/findings?account=${BOSS}&assignee=me`);
  await expect(page.getByText(/viewing boss@example.com.s findings as a team member/)).toBeVisible();
  await expect(page.getByText("No SPF record").first()).toBeVisible();
  // Read-only: no selection boxes, so no triage or assignment.
  await expect(page.getByRole("checkbox", { name: /^Select/ })).toHaveCount(0);

  const last = new URL(listUrls[listUrls.length - 1]);
  expect(last.searchParams.get("account")).toBe(BOSS);
  expect(last.searchParams.get("assignee")).toBe("me");
});
