import { expect, type Page } from "@playwright/test";
import { mockApi, mockSupabase, type ApiMock } from "./mocks";
import { SCAN_ID, SCAN_RESULT_ROWS, SCAN_ROWS, SUBSCRIPTION } from "./fixtures";
import { triageApi } from "./triage";

type Handlers = Parameters<typeof mockApi>[1];

/** Opens /dashboard/scans/<SCAN_ID> with the report fixtures and a stateful
 *  triage API (or `handlers` overrides, which win), once the report has rendered. */
export async function openReport(page: Page, handlers: Handlers = {}): Promise<ApiMock> {
  await mockSupabase(page, {
    subscriptions: [SUBSCRIPTION],
    scan_results: SCAN_RESULT_ROWS,
    scans: SCAN_ROWS,
    ticket_integrations: [],
    repo_connections: [],
  });
  const api = await mockApi(page, {
    ...triageApi(),
    [`GET /api/scans/${SCAN_ID}/shares`]: { json: { shares: [] } },
    ...handlers,
  });
  await page.goto(`/dashboard/scans/${SCAN_ID}`);
  await expect(page.getByRole("heading", { name: "https://example.com", level: 1 })).toBeVisible();
  return api;
}

/** The "// findings" section of the report. */
export const findingsSection = (page: Page) => page.getByRole("heading", { name: "// findings" }).locator("xpath=../..");

/** Titles of the open (untriaged) findings, in display order. The Triaged
 *  group's own titles live inside a <details>, so they are excluded. */
export const openFindingTitles = (page: Page) => findingsSection(page).locator("p.text-sm.font-medium:not(details *)");

/** One finding card inside the findings section, found by its title. */
export const findingCard = (page: Page, title: string) =>
  findingsSection(page).locator("div.rounded-lg").filter({ has: page.getByText(title, { exact: true }) }).first();
