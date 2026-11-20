import { test, expect, type Page } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";

// The admin Engagements tab (Exploit, P-07): an analyst books an engagement for
// a customer found by email, sets its scope and record, is told in words why a
// move was refused, and stops it. The API is a small stateful mock, so what the
// page shows after a click is what it was told, not a hard-coded answer.

test.use({ timezoneId: "UTC" });

const ID = "e1000000-0000-4000-8000-000000000001";
const OWNER = "22222222-2222-4222-8222-222222222222";
const EMAIL = "it@acme.example";
// A second account whose lookup answers slowly, to race a later lookup.
const SLOW_OWNER = "33333333-3333-4333-8333-333333333333";
const SLOW_EMAIL = "slow@other.example";

/** A timestamp as PostgREST writes it ("+00:00"), not as the browser sent it (".000Z"). */
const pg = (iso: unknown) => String(iso).replace(/.000Z$/, "+00:00");

const METRICS = {
  totalCustomers: 1,
  activeSubscriptions: 1,
  totalScans: 0,
  scansLast30d: 0,
  scansByStatus: {},
  planBreakdown: [],
  mrrUsd: 0,
  revenue: { payingMrrGbp: 0, payingCount: 0, compedCount: 0, bespokeCount: 0, byPlan: [], pastDueCount: 0, newSubs30d: 0, cancellations30d: 0, churnRatePct: null },
  recentSignups: [],
};

type Engagement = Record<string, unknown> & { state: string };

function newEngagement(reference: string): Engagement {
  return {
    id: ID,
    owner: OWNER,
    reference,
    customer_name: null,
    state: "booked",
    scan_profile: "exposure",
    window_start: null,
    window_end: null,
    expires_at: null,
    contract_signed_at: null,
    contract_signed_by_name: null,
    contract_signed_by_role: null,
    contract_document_ref: null,
    roe_signed_at: null,
    roe_signed_by_name: null,
    roe_signed_by_role: null,
    roe_document_ref: null,
    roe_document_sha256: null,
    created_at: new Date().toISOString(),
    closed_at: null,
    aborted_at: null,
    abort_reason: null,
  };
}

async function open(page: Page, opts: { failReloadAfterStop?: boolean } = {}) {
  let engagement: Engagement | null = null;
  let scope: { host: string; included: boolean }[] = [];
  let contacts: Record<string, unknown>[] = [];
  let windows: Record<string, unknown>[] = [];

  const row = () => (engagement ? [{ ...engagement, owner_email: EMAIL }] : []);
  const view = () => ({
    engagement,
    scope: scope.map((h) => ({ ...h, targetUrls: [], authorization: null })),
    contacts,
    testingWindows: windows,
  });

  await mockSupabase(page, {});
  const api = await mockApi(page, {
    "GET /api/admin/metrics": { json: METRICS },
    "GET /api/admin/engagements": () => ({ json: { customer: null, engagements: row() } }),
    "POST /api/engagements": (call) => {
      engagement = newEngagement((call.body as { reference: string }).reference);
      return { status: 201, json: { engagement } };
    },
    [`GET /api/engagements/${ID}`]: () =>
      opts.failReloadAfterStop && engagement?.state === "aborted" ? { status: 500, json: { error: "Could not complete the engagement request" } } : { json: view() },
    [`PATCH /api/engagements/${ID}`]: (call) => {
      const body = call.body as Record<string, unknown>;
      const e = engagement as Engagement;
      if (body.to === "authorised" && !contacts.some((c) => c.kind === "emergency")) {
        return { status: 409, json: { error: "The engagement can't move to that state.", reason: "no_emergency_contact", state: e.state } };
      }
      if (body.to) e.state = body.to as string;
      if (body.windowStart) e.window_start = pg(body.windowStart);
      if (body.windowEnd) e.window_end = pg(body.windowEnd);
      if (body.expiresAt) e.expires_at = pg(body.expiresAt);
      if (body.customerName) e.customer_name = body.customerName;
      const roe = body.roe as Record<string, string> | undefined;
      if (roe) Object.assign(e, { roe_document_ref: roe.documentRef, roe_document_sha256: roe.documentSha256 ?? null, roe_signed_at: pg(roe.signedAt), roe_signed_by_name: roe.signedByName, roe_signed_by_role: roe.signedByRole });
      return { json: { engagement: e } };
    },
    [`POST /api/engagements/${ID}/scope`]: (call) => {
      const body = call.body as { add?: { host: string; included: boolean }[]; remove?: string[] };
      const removed = (body.remove ?? []).filter((h) => scope.some((s) => s.host === h));
      scope = scope.filter((s) => !removed.includes(s.host));
      const added = (body.add ?? []).filter((a) => !a.host.startsWith("unverified."));
      const refused = (body.add ?? []).filter((a) => a.host.startsWith("unverified.")).map((a) => ({ host: a.host, reason: "domain_not_verified" }));
      scope = [...scope, ...added];
      return { json: { added, removed, refused } };
    },
    [`PUT /api/engagements/${ID}/contacts`]: (call) => {
      contacts = (call.body as { contacts: Record<string, unknown>[] }).contacts.map((c, i) => ({ id: `c${i}`, role: null, email: null, phone: null, ...c }));
      return { json: { contacts } };
    },
    [`PUT /api/engagements/${ID}/windows`]: (call) => {
      windows = (call.body as { windows: { startsAt: string; endsAt: string }[] }).windows.map((w, i) => ({ id: `w${i}`, starts_at: pg(w.startsAt), ends_at: pg(w.endsAt) }));
      return { json: { windows } };
    },
    [`POST /api/engagements/${ID}/abort`]: (call) => {
      const e = engagement as Engagement;
      e.state = "aborted";
      e.aborted_at = new Date().toISOString();
      e.abort_reason = (call.body as { reason?: string }).reason ?? null;
      return { json: { state: "aborted", authorisationsRevoked: 0, simulationsWithdrawn: 0 } };
    },
  });
  // The customer lookup: the account for its email or id, refused in words for anything else.
  await page.route((url) => url.pathname === "/api/admin/engagements" && url.searchParams.has("customer"), async (route) => {
    const asked = new URL(route.request().url()).searchParams.get("customer");
    api.calls.push({ method: "GET", path: "/api/admin/engagements", body: { customer: asked }, authorization: route.request().headers()["authorization"] });
    if (asked === SLOW_EMAIL) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      return route.fulfill({ json: { customer: { id: SLOW_OWNER, email: SLOW_EMAIL }, engagements: [] } }).catch(() => undefined);
    }
    return asked === EMAIL || asked === OWNER ? route.fulfill({ json: { customer: { id: OWNER, email: EMAIL }, engagements: row() } }) : route.fulfill({ status: 404, json: { error: `No account uses ${asked}.` } });
  });

  await page.goto("/admin");
  await page.getByRole("button", { name: "Engagements", exact: true }).click();
  await expect(page.getByText("No engagements yet")).toBeVisible();
  return api;
}

async function bookFor(page: Page) {
  await page.getByLabel("Customer email or user id").fill(EMAIL);
  await page.getByRole("button", { name: "Find customer" }).click();
  await page.getByLabel("Reference", { exact: true }).fill("ENG-2026-001");
  await page.getByRole("button", { name: "Book engagement" }).click();
  await expect(page.getByRole("heading", { name: "Engagement ENG-2026-001" })).toBeVisible();
}

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("an analyst books an engagement, sets its scope, sees why authorising was refused, and stops it", async ({ page }) => {
  const api = await open(page);

  // An unknown email is refused in words, and nothing is booked.
  await page.getByLabel("Customer email or user id").fill("nobody@acme.example");
  await page.getByRole("button", { name: "Find customer" }).click();
  await expect(page.getByText("No account uses nobody@acme.example.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Book engagement" })).toHaveCount(0);

  // Create, under the account the email resolved to.
  await bookFor(page);
  await expect(page.getByText("Engagement booked.")).toBeVisible();
  await expect(page.getByRole("cell", { name: "ENG-2026-001", exact: true })).toBeVisible();
  const [created] = api.to("POST", "/api/engagements");
  expect(created.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(created.body).toEqual({ owner: OWNER, reference: "ENG-2026-001", scanProfile: "exposure" });

  // Scope: one host added, one refused per host with the reason, then one removed.
  await page.getByLabel("Hosts to add (one per line)").fill("shop.example.com\nwww.example.com\nunverified.example.com");
  await page.getByRole("button", { name: "Add hosts" }).click();
  await expect(page.getByText("Added shop.example.com, www.example.com. Refused unverified.example.com: the customer hasn't verified this domain")).toBeVisible();
  await page.getByRole("button", { name: "Remove www.example.com" }).click();
  await expect(page.getByText("Removed www.example.com.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove shop.example.com" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove www.example.com" })).toHaveCount(0);
  expect(api.to("POST", `/api/engagements/${ID}/scope`).map((c) => c.body)).toEqual([
    { add: [{ host: "shop.example.com", included: true }, { host: "www.example.com", included: true }, { host: "unverified.example.com", included: true }] },
    { remove: ["www.example.com"] },
  ]);

  // State: booked → scoped succeeds; scoped → authorised is refused, with the reason shown.
  await page.getByRole("button", { name: "Move to Scope agreed" }).click();
  await expect(page.getByText("Moved to Scope agreed.")).toBeVisible();
  await page.getByRole("button", { name: "Move to Authorised" }).click();
  await expect(page.getByText("Add at least one emergency stop contact first.")).toBeVisible();
  await expect(page.getByText(/^Scope agreed\. /)).toBeVisible();
  expect(api.to("PATCH", `/api/engagements/${ID}`).map((c) => c.body)).toEqual([{ to: "scoped" }, { to: "authorised" }]);

  // Stop: asks once, sends the reason, and the engagement then shows stopped.
  await page.getByRole("button", { name: "Stop engagement" }).click();
  await page.getByLabel("Reason (optional)").fill("customer asked us to stop");
  await page.getByRole("button", { name: "Yes, stop this engagement" }).click();
  await expect(page.getByText(/^Engagement stopped\. 0 authorisations were withdrawn\./)).toBeVisible();
  await expect(page.getByText(/: customer asked us to stop$/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop engagement" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Add hosts" })).toHaveCount(0);
  const [abort] = api.to("POST", `/api/engagements/${ID}/abort`);
  expect(abort.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  expect(abort.body).toEqual({ reason: "customer asked us to stop" });
});

test("cancelling the stop sends nothing", async ({ page }) => {
  const api = await open(page);
  await bookFor(page);
  await page.getByRole("button", { name: "Stop engagement" }).click();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Stop engagement" })).toBeVisible();
  expect(api.to("POST", `/api/engagements/${ID}/abort`)).toHaveLength(0);
});

test("a failed lookup clears the last search's rows rather than leaving them under the error", async ({ page }) => {
  await open(page);
  await bookFor(page);
  await expect(page.getByRole("cell", { name: "ENG-2026-001", exact: true })).toBeVisible();
  await page.getByLabel("Customer email or user id").fill("nobody@acme.example");
  await page.getByRole("button", { name: "Find customer" }).click();
  await expect(page.getByText("No account uses nobody@acme.example.")).toBeVisible();
  await expect(page.getByRole("cell", { name: "ENG-2026-001", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Book engagement" })).toHaveCount(0);
});

test("a slow lookup answering after a newer one never replaces the customer being booked for", async ({ page }) => {
  await open(page);
  const lookup = page.getByLabel("Customer email or user id");
  await lookup.fill(SLOW_EMAIL);
  await page.getByRole("button", { name: "Find customer" }).click();
  await lookup.fill(EMAIL);
  await page.getByRole("button", { name: "Find customer" }).click();
  await expect(page.getByText(`Book a new engagement for ${EMAIL}`)).toBeVisible();
  // The slow answer lands about 1.5 s later and must be ignored.
  await page.waitForTimeout(2_000);
  await expect(page.getByText(`Book a new engagement for ${EMAIL}`)).toBeVisible();
  await expect(page.getByText(SLOW_EMAIL)).toHaveCount(0);
});

test("a stop that went through is reported as done even when the reload after it fails", async ({ page }) => {
  const api = await open(page, { failReloadAfterStop: true });
  await bookFor(page);
  await page.getByRole("button", { name: "Stop engagement" }).click();
  await page.getByRole("button", { name: "Yes, stop this engagement" }).click();
  await expect(page.getByText(/^Engagement stopped\. .*The page couldn't reload the engagement/)).toBeVisible();
  await expect(page.getByText("Could not complete the engagement request")).toHaveCount(0);
  expect(api.to("POST", `/api/engagements/${ID}/abort`)).toHaveLength(1);
});

test("contacts, testing windows, the window, expiry and the signed rules of engagement are sent as the routes expect", async ({ page }) => {
  const api = await open(page);
  await bookFor(page);

  await page.getByLabel("Window opens").fill("2026-12-01T09:00");
  await page.getByLabel("Window closes").fill("2026-12-05T17:00");
  await page.getByLabel("Expires").fill("2026-12-06T00:00");
  const saveDates = page.getByRole("button", { name: "Save window and expiry" });
  await saveDates.click();
  await expect(page.getByText("Window and expiry saved.")).toBeVisible();
  // Reloaded in the database's own format ("+00:00"), the dates still count as unchanged.
  await expect(saveDates).toBeDisabled();

  // An emptied date is flagged, never sent, and can be put back.
  await page.getByLabel("Expires").fill("");
  await expect(page.getByText("Expires: once set, a date can be changed but not removed.")).toBeVisible();
  await expect(saveDates).toBeDisabled();
  await page.getByRole("button", { name: "Put it back" }).click();
  await expect(page.getByText("once set, a date can be changed but not removed")).toHaveCount(0);

  await page.getByRole("button", { name: "Add contact" }).click();
  await page.getByLabel("Contact 1 name").fill("On-call engineer");
  await page.getByLabel("Contact 1 phone").fill("+44 1851 000000");
  await expect(page.getByText(/^Unsaved changes in Contacts\. Moving on checks only what is saved/)).toBeVisible();
  await page.getByRole("button", { name: "Save contacts" }).click();
  await expect(page.getByText("Contacts saved.")).toBeVisible();
  await expect(page.getByText(/^Unsaved changes in/)).toHaveCount(0);

  await page.getByRole("button", { name: "Add testing window" }).click();
  await page.getByLabel("Testing window 1 starts").fill("2026-12-01T09:00");
  await page.getByLabel("Testing window 1 ends").fill("2026-12-01T17:00");
  await page.getByRole("button", { name: "Save testing windows" }).click();
  await expect(page.getByText("Testing windows saved.")).toBeVisible();

  const save = page.getByRole("button", { name: "Save rules of engagement" });
  await page.getByLabel("Document reference and version").fill("ROE ENG-2026-001 v1");
  await page.getByLabel("Rules signed", { exact: true }).fill("2026-11-20T10:00");
  await page.getByLabel("Rules signed by").fill("A Person");
  await page.getByLabel("Rules signer's role").fill("Director");
  await page.getByLabel("SHA-256 of the signed file (optional)").fill("not-a-hash");
  await expect(page.getByText("A SHA-256 is 64 hexadecimal characters.")).toBeVisible();
  await expect(save).toBeDisabled();
  await page.getByLabel("SHA-256 of the signed file (optional)").fill("A".repeat(64));
  await save.click();
  await expect(page.getByText("Rules of engagement recorded.")).toBeVisible();

  // Changing only the organisation name sends only that, not the stored dates again.
  await page.getByLabel("Organisation name", { exact: true }).fill("Acme Ltd");
  await saveDates.click();
  await expect(page.getByText("Window and expiry saved.")).toBeVisible();

  expect(api.to("PATCH", `/api/engagements/${ID}`).map((c) => c.body)).toEqual([
    { windowStart: "2026-12-01T09:00:00.000Z", windowEnd: "2026-12-05T17:00:00.000Z", expiresAt: "2026-12-06T00:00:00.000Z" },
    { roe: { documentRef: "ROE ENG-2026-001 v1", signedAt: "2026-11-20T10:00:00.000Z", signedByName: "A Person", signedByRole: "Director", documentSha256: "a".repeat(64) } },
    { customerName: "Acme Ltd" },
  ]);
  expect(api.to("PUT", `/api/engagements/${ID}/contacts`)[0].body).toEqual({ contacts: [{ kind: "emergency", name: "On-call engineer", phone: "+44 1851 000000" }] });
  expect(api.to("PUT", `/api/engagements/${ID}/windows`)[0].body).toEqual({ windows: [{ startsAt: "2026-12-01T09:00:00.000Z", endsAt: "2026-12-01T17:00:00.000Z" }] });
});
