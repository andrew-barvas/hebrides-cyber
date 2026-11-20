import { test, expect, type Page } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// The customer's engagement status page (Exploit, P-07): the stop button and
// signing an authorisation. The API is a small stateful mock, so what the page
// shows after a click is what it was told, not a hard-coded answer.

const ID = "e1000000-0000-4000-8000-000000000001";
const HOUR = 3_600_000;

function view(state: string, hostAuthorised = state !== "scoped") {
  const now = Date.now();
  return {
    engagement: {
      id: ID,
      owner: "11111111-1111-4111-8111-111111111111",
      reference: "ENG-2026-001",
      customer_name: "Acme Ltd",
      state,
      scan_profile: "offensive",
      window_start: new Date(now - 24 * HOUR).toISOString(),
      window_end: new Date(now + 24 * HOUR).toISOString(),
      expires_at: new Date(now + 48 * HOUR).toISOString(),
      contract_signed_at: new Date(now - 72 * HOUR).toISOString(),
      contract_signed_by_name: "A Person",
      contract_signed_by_role: "Director",
      contract_document_ref: "Contracts/ENG-2026-001.pdf",
      roe_signed_at: new Date(now - 72 * HOUR).toISOString(),
      roe_signed_by_name: "A Person",
      roe_signed_by_role: "Director",
      roe_document_ref: "ROE ENG-2026-001 v1",
      roe_document_sha256: null,
      created_at: new Date(now - 96 * HOUR).toISOString(),
      closed_at: null,
      aborted_at: state === "aborted" ? new Date(now).toISOString() : null,
      abort_reason: state === "aborted" ? "the site is slow" : null,
    },
    scope: [
      { host: "shop.example.com", included: true, targetUrls: ["https://shop.example.com"], authorization: !hostAuthorised ? null : { authorized_at: new Date(now - 48 * HOUR).toISOString(), expires_at: new Date(now + 48 * HOUR).toISOString() } },
      { host: "legacy.example.com", included: false, targetUrls: [], authorization: null },
    ],
    contacts: [{ id: "c1", kind: "emergency", name: "On-call engineer", role: null, email: null, phone: "+44 1851 000000" }],
    testingWindows: [],
  };
}

async function open(page: Page, initial: string) {
  let state = initial;
  let hostAuthorised = initial !== "scoped";
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const api = await mockApi(page, {
    [`GET /api/engagements/${ID}`]: () => ({ json: view(state, hostAuthorised) }),
    [`POST /api/engagements/${ID}/abort`]: () => {
      state = "aborted";
      return { json: { state: "aborted", authorisationsRevoked: 1, simulationsWithdrawn: 0 } };
    },
    "POST /api/account/offensive-authorization": () => {
      hostAuthorised = true;
      return { json: { ok: true, host: "shop.example.com" } };
    },
  });
  await page.goto(`/dashboard/engagements/${ID}`);
  await expect(page.getByRole("heading", { name: "Engagement ENG-2026-001", level: 1 })).toBeVisible();
  return api;
}

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("the stop button asks once, sends the reason, and the page then shows the engagement stopped", async ({ page }) => {
  const api = await open(page, "in_window");
  await expect(page.getByText("Testing may be running now.")).toBeVisible();
  await expect(page.getByText("legacy.example.com")).toBeVisible();

  await page.getByRole("button", { name: "Stop testing now" }).click();
  await page.getByLabel("Reason (optional)").fill("the site is slow");
  await page.getByRole("button", { name: "Yes, stop all testing" }).click();

  await expect(page.getByText("Testing is stopped. 1 authorisation was withdrawn. Anything still running stops within about half a minute, and nothing new starts.")).toBeVisible();
  await expect(page.getByText("Stopped", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop testing now" })).toHaveCount(0);

  const [abort] = api.to("POST", `/api/engagements/${ID}/abort`);
  expect(abort.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(abort.body).toEqual({ reason: "the site is slow" });
});

test("cancelling the stop sends nothing", async ({ page }) => {
  const api = await open(page, "authorised");
  await page.getByRole("button", { name: "Stop testing now" }).click();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Stop testing now" })).toBeVisible();
  expect(api.to("POST", `/api/engagements/${ID}/abort`)).toHaveLength(0);
});

test("authorising a host needs the acknowledgement and links it to this engagement", async ({ page }) => {
  const api = await open(page, "scoped");
  await expect(page.getByText("Not testing now: Scope agreed.")).toBeVisible();
  await page.getByRole("button", { name: "Authorise testing" }).click();
  const authorise = page.getByRole("button", { name: "Authorise", exact: true });
  await expect(authorise).toBeDisabled();
  await page.getByRole("checkbox").check();
  await authorise.click();
  await expect(page.getByText("shop.example.com is authorised for this engagement.")).toBeVisible();

  const [post] = api.to("POST", "/api/account/offensive-authorization");
  expect(post.body).toMatchObject({ targetUrl: "https://shop.example.com", acknowledge: true, engagementId: ID });
  // The engagement's own expiry (two days out here), inside the 30-day limit.
  const expiresAt = Date.parse((post.body as { expiresAt: string }).expiresAt);
  expect(expiresAt).toBeGreaterThan(Date.now() + 47 * HOUR);
  expect(expiresAt).toBeLessThan(Date.now() + 49 * HOUR);
});

test("a stopped engagement offers no stop and says when it stopped", async ({ page }) => {
  await open(page, "aborted");
  await expect(page.getByText("This engagement can no longer run any test.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop testing now" })).toHaveCount(0);
  await expect(page.getByText(/: the site is slow$/)).toBeVisible();
});

test("the engagements list links each engagement to its status page", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const api = await mockApi(page, {
    "GET /api/engagements": {
      json: {
        engagements: [
          { id: ID, reference: "ENG-2026-001", customer_name: "Acme Ltd", state: "in_window", window_start: "2026-12-01T09:00:00Z", window_end: "2026-12-05T17:00:00Z", expires_at: "2026-12-06T00:00:00Z", created_at: "2026-11-20T00:00:00Z", aborted_at: null, closed_at: null },
        ],
      },
    },
  });
  await page.goto("/dashboard/engagements");
  await expect(page.getByRole("heading", { name: "Testing engagements", level: 1 })).toBeVisible();
  await expect(page.getByRole("link", { name: "ENG-2026-001 (Acme Ltd)" })).toHaveAttribute("href", `/dashboard/engagements/${ID}`);
  await expect(page.getByText(/Testing window open ·/)).toBeVisible();
  expect(api.to("GET", "/api/engagements")[0].authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
});

test("the engagements list says so when there are none, and when it can't load", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  let fail = false;
  await mockApi(page, { "GET /api/engagements": () => (fail ? { status: 500, json: { error: "x" } } : { json: { engagements: [] } }) });
  await page.goto("/dashboard/engagements");
  await expect(page.getByText("You have no testing engagements.")).toBeVisible();
  fail = true;
  await page.reload();
  await expect(page.getByRole("alert").filter({ hasText: "Couldn't load your engagements" })).toHaveText("Couldn't load your engagements. Refresh to try again.");
});

test("signing early shows the 30-day warning", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  const far = view("scoped", false);
  far.engagement.window_end = new Date(Date.now() + 60 * 24 * HOUR).toISOString();
  far.engagement.expires_at = new Date(Date.now() + 61 * 24 * HOUR).toISOString();
  await mockApi(page, { [`GET /api/engagements/${ID}`]: { json: far } });
  await page.goto(`/dashboard/engagements/${ID}`);
  await expect(page.getByText(/one signed today would end before the testing window does/)).toBeVisible();
});
