import { test, expect } from "@playwright/test";
import { signIn, ACCESS_TOKEN } from "./helpers/session";
import { mockApi, mockSupabase } from "./helpers/mocks";
import { SUBSCRIPTION } from "./helpers/fixtures";

// Security questionnaire autopilot (/dashboard/questionnaires): upload a
// questionnaire, confirm the question column, review the drafted answers and
// export. Every API call is mocked; no real Supabase.

const QID = "44444444-4444-4444-8444-444444444444";
const CSV = "Ref,Question\n1,Is multi-factor authentication enforced?\n2,Do staff receive security awareness training?\n";

const answers = (mfaStatus: "draft" | "accepted") => [
  {
    id: "55555555-5555-4555-8555-555555555555", row_index: 0, question: "Is multi-factor authentication enforced?", topic: "mfa",
    draft_answer: "Yes. Multi-factor authentication is in place for our Microsoft 365 accounts.", answer: "Yes. Multi-factor authentication is in place for our Microsoft 365 accounts.",
    evidence: [{ source: "m365", label: "Microsoft 365 check", detail: "No accounts without multi-factor authentication were found.", date: "2026-11-21" }],
    confidence: "high", status: mfaStatus, edited: false, ai_worded: false, reused_from: null,
  },
  {
    id: "66666666-6666-4666-8666-666666666666", row_index: 1, question: "Do staff receive security awareness training?", topic: "training",
    draft_answer: "Needs your answer", answer: "", evidence: [], confidence: "none", status: "needs_answer", edited: false, ai_worded: false, reused_from: null,
  },
];

const detail = (mfaStatus: "draft" | "accepted") => ({
  questionnaire: { id: QID, name: "supplier.csv", source_format: "csv", sheet_name: null, headers: ["Ref", "Question"], question_column: 1, created_at: "2026-11-27T10:00:00Z", rowCount: 2 },
  answers: answers(mfaStatus),
  counts: { draft: mfaStatus === "draft" ? 1 : 0, needs_answer: 1, accepted: mfaStatus === "accepted" ? 1 : 0, rejected: 0, total: 2 },
  aiAvailable: false,
});

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("a Pro customer uploads a questionnaire, reviews the drafts and exports them", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [SUBSCRIPTION] });
  let accepted = false;
  const api = await mockApi(page, {
    "GET /api/questionnaires": { json: { questionnaires: [], enabled: true, aiAvailable: false } },
    "POST /api/questionnaires": (call) =>
      (call.body as { preview?: boolean }).preview
        ? { json: { format: "csv", sheets: [{ name: null, headers: ["Ref", "Question"], sample: [["1", "Is multi-factor authentication enforced?"]], rowCount: 2, suggestedColumn: 1, confident: true, questions: 2 }] } }
        : { status: 201, json: { id: QID, questions: 2 } },
    [`GET /api/questionnaires/${QID}`]: () => ({ json: detail(accepted ? "accepted" : "draft") }),
    [`PATCH /api/questionnaires/${QID}`]: () => {
      accepted = true;
      return { json: { updated: ["55555555-5555-4555-8555-555555555555"], skipped: [] } };
    },
    [`GET /api/questionnaires/${QID}/export`]: { json: {} },
  });

  await page.goto("/dashboard/questionnaires");
  await expect(page.getByRole("heading", { name: "Security questionnaires" })).toBeVisible();
  await expect(page.getByText("No questionnaires yet")).toBeVisible();

  await page.getByLabel("Questionnaire file").setInputFiles({ name: "supplier.csv", mimeType: "text/csv", buffer: Buffer.from(CSV) });
  await expect(page.getByText("supplier.csv: 2 rows")).toBeVisible();
  await expect(page.getByLabel("Which column holds the questions?")).toHaveValue("1");
  await page.getByRole("button", { name: "Draft answers" }).click();

  await expect(page).toHaveURL(new RegExp(`/dashboard/questionnaires/${QID}$`));
  await expect(page.getByText("Draft answers, not certification")).toBeVisible();
  await expect(page.getByText("Confidence: High")).toBeVisible();
  await expect(page.getByText("No evidence held for this question.")).toBeVisible();

  await page.locator("#main-content").getByRole("button", { name: "Accept", exact: true }).click();
  await expect(page.locator("#main-content").getByText("Accepted", { exact: true })).toBeVisible();
  expect(api.to("PATCH", `/api/questionnaires/${QID}`)[0].body).toEqual({ action: "accept", answerIds: ["55555555-5555-4555-8555-555555555555"] });

  await page.getByRole("button", { name: "Export .csv" }).click();
  await expect.poll(() => api.to("GET", `/api/questionnaires/${QID}/export`).length).toBe(1);

  const upload = api.to("POST", "/api/questionnaires");
  expect(upload).toHaveLength(2);
  expect(upload[1].body).toMatchObject({ fileName: "supplier.csv", questionColumn: 1 });
  expect(upload[1].authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
});

test("a Basic customer sees the upgrade prompt, not the upload", async ({ page }) => {
  await mockSupabase(page, { subscriptions: [{ ...SUBSCRIPTION, plan: "basic" }] });
  const api = await mockApi(page, {});
  await page.goto("/dashboard/questionnaires");
  await expect(page.getByRole("heading", { name: "Security questionnaires" })).toBeVisible();
  await expect(page.getByLabel("Questionnaire file")).toHaveCount(0);
  expect(api.to("GET", "/api/questionnaires")).toHaveLength(0);
});
