import { test, expect } from "@playwright/test";
import { signIn } from "./helpers/session";
import { applyQuery, mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// Agency client workspaces: create a client, assign a site to it, then use the
// header switcher to scope the Scans list. Everything is mocked in the browser
// (example-project, fake hosts); the in-memory tables change as the flow does.

const OWNER = "11111111-1111-4111-8111-111111111111";
const scan = (id: string, host: string) => ({
  id,
  target_url: `https://${host}`,
  status: "completed",
  created_at: "2026-10-04T09:00:00.000Z",
  owner: OWNER,
  scan_results: [{ id: `r-${id}`, scan_id: id, score: 70, summary: "ok", created_at: "2026-10-04T09:00:00.000Z", results: { findings: [] } }],
});

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("create a client, assign a site, and the switcher filters scans", async ({ page }) => {
  const clients: Record<string, unknown>[] = [];
  const targets: Record<string, unknown>[] = [
    { id: "t-a", target_url: "https://client-a.example.com", created_at: "2026-10-01T00:00:00Z", scan_profile: "full", client_id: null },
    { id: "t-b", target_url: "https://client-b.example.com", created_at: "2026-10-02T00:00:00Z", scan_profile: "full", client_id: null },
  ];
  const scans = [scan("aaaaaaaa-0000-4000-8000-0000000000a1", "client-a.example.com"), scan("aaaaaaaa-0000-4000-8000-0000000000b1", "client-b.example.com")];

  await mockSupabase(page, {
    subscriptions: [{ ...SUBSCRIPTION, plan: "agency" }],
    scans: (url) => applyQuery(scans, url),
    clients: (url) => applyQuery(clients, url),
    // applyQuery ignores `is.null`, which the "Unassigned" scope uses, so model it here.
    monitored_targets: (url) => {
      const rows = applyQuery(targets, url);
      return url.searchParams.get("client_id") === "is.null" ? rows.filter((t) => !t.client_id) : rows;
    },
  });
  const api = await mockApi(page, {
    "GET /api/clients": () => ({
      json: { clients: clients.map((c) => ({ ...c, site_count: targets.filter((t) => t.client_id === c.id).length })), unassigned_sites: targets.filter((t) => !t.client_id).length },
    }),
    "POST /api/clients": (call) => {
      const row = { id: "cccccccc-0000-4000-8000-000000000001", name: (call.body as { name: string }).name, notes: null, brand_name: null, brand_logo_url: null, created_at: "2026-10-05T00:00:00Z" };
      clients.push(row);
      return { status: 201, json: { ...row, site_count: 0 } };
    },
    "POST /api/clients/assign": (call) => {
      const body = call.body as { client_id: string | null; target_ids: string[] };
      for (const t of targets) if (body.target_ids.includes(String(t.id))) t.client_id = body.client_id;
      return { json: { updated: { sites: body.target_ids.length, domains: 0 } } };
    },
  });

  // 1. Create a client on Assets.
  await page.goto("/dashboard/assets");
  await page.getByLabel("Client name").fill("Acme Ltd");
  await page.getByRole("button", { name: "Add client" }).click();
  await expect(page.getByText("Acme Ltd").first()).toBeVisible();
  expect(api.to("POST", "/api/clients")).toHaveLength(1);

  // 2. Assign one site to it.
  await page.getByLabel("Client for https://client-a.example.com").selectOption({ label: "Acme Ltd" });
  await expect.poll(() => api.to("POST", "/api/clients/assign").length).toBe(1);
  expect(api.to("POST", "/api/clients/assign")[0].body).toMatchObject({ client_id: "cccccccc-0000-4000-8000-000000000001", target_ids: ["t-a"] });

  // 3. The switcher scopes the Scans list to that client, and Unassigned shows the rest.
  await page.goto("/dashboard/scans");
  await expect(page.getByRole("row").filter({ hasText: "client-b.example.com" })).toHaveCount(1);
  await page.getByLabel(/client/i).first().selectOption({ label: "Acme Ltd" });
  await expect(page.getByRole("row").filter({ hasText: "client-a.example.com" })).toHaveCount(1);
  await expect(page.getByRole("row").filter({ hasText: "client-b.example.com" })).toHaveCount(0);

  await page.getByLabel(/client/i).first().selectOption({ label: "Unassigned" });
  await expect(page.getByRole("row").filter({ hasText: "client-b.example.com" })).toHaveCount(1);
  await expect(page.getByRole("row").filter({ hasText: "client-a.example.com" })).toHaveCount(0);

  // The choice is in the URL, so it survives a reload.
  await expect(page).toHaveURL(/client=unassigned/);
});
