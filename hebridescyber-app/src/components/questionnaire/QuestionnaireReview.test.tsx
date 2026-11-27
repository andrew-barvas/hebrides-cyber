import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import QuestionnaireReview from "./QuestionnaireReview";
import type { QuestionnaireDetail, ReviewAnswer } from "@/lib/questionnaire/client";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  ({ ok: status < 400, status, json: async () => body, blob: async () => new Blob(["x"]), headers: new Headers(headers) }) as unknown as Response;

const answer = (over: Partial<ReviewAnswer>): ReviewAnswer => ({
  id: "a1",
  row_index: 0,
  question: "Is MFA enforced?",
  topic: "mfa",
  draft_answer: "Yes. MFA is in place.",
  answer: "Yes. MFA is in place.",
  evidence: [{ source: "m365", label: "Microsoft 365 check", detail: "No accounts without MFA.", date: "2026-11-21" }],
  confidence: "high",
  status: "draft",
  edited: false,
  ai_worded: false,
  reused_from: null,
  ...over,
});

const detail = (answers: ReviewAnswer[], aiAvailable = false): QuestionnaireDetail => {
  const counts = { draft: 0, needs_answer: 0, accepted: 0, rejected: 0, total: answers.length };
  for (const a of answers) counts[a.status]++;
  return { questionnaire: { id: "q1", name: "Q.xlsx", source_format: "xlsx", sheet_name: "S", headers: [], question_column: 1, created_at: "c", rowCount: 3 }, answers, counts, aiAvailable };
};

const base = [
  answer({}),
  answer({ id: "a2", row_index: 1, question: "Do staff get training?", answer: "", draft_answer: "Needs your answer", evidence: [], confidence: "none", status: "needs_answer" }),
  answer({ id: "a3", row_index: 2, question: "Is RDP closed?", status: "accepted", edited: true, ai_worded: true, reused_from: "p1" }),
  answer({ id: "a4", row_index: 3, question: "Are backups tested?", status: "rejected", answer: "Old", evidence: [{ source: "document", label: "Doc", detail: "d", date: null }] }),
];

let fetchMock: ReturnType<typeof vi.fn>;
let current: QuestionnaireDetail;

beforeEach(() => {
  current = detail(base);
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/questionnaires/q1" && !init?.method) return json(200, current);
    if (url === "/api/questionnaires/q1" && init?.method === "PATCH") return json(200, { updated: ["a1"], skipped: [] });
    if (url.startsWith("/api/questionnaires/q1/export")) return json(200, {}, { "Content-Disposition": 'attachment; filename="Q - draft answers.xlsx"' });
    return json(404, { error: "nope" });
  });
  vi.stubGlobal("fetch", fetchMock);
  URL.createObjectURL = vi.fn(() => "blob:x");
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const patches = () => fetchMock.mock.calls.filter((c) => c[1]?.method === "PATCH").map((c) => JSON.parse(String(c[1].body)));
const card = (question: string) => screen.getByText(question).closest("li") as HTMLElement;

describe("QuestionnaireReview", () => {
  it("labels the page as drafts, not certification, and shows each answer's status, confidence and evidence", async () => {
    render(<QuestionnaireReview token="tok" id="q1" />);
    expect(await screen.findByText("Draft answers, not certification")).toBeInTheDocument();
    expect(screen.getByText(/1 accepted · 1 to review · 1 need your answer · 1 rejected/)).toBeInTheDocument();
    const mfa = card("Is MFA enforced?");
    expect(within(mfa).getByText("Draft, not reviewed")).toBeInTheDocument();
    expect(within(mfa).getByText("Confidence: High")).toBeInTheDocument();
    expect(within(mfa).getByText("Microsoft 365 check")).toBeInTheDocument();
    const rdp = card("Is RDP closed?");
    expect(within(rdp).getByText("Accepted (edited)")).toBeInTheDocument();
    expect(within(rdp).getByText("AI-worded")).toBeInTheDocument();
    expect(within(rdp).getByText("Reused")).toBeInTheDocument();
    expect(within(card("Do staff get training?")).getByText("No evidence held for this question.")).toBeInTheDocument();
    expect(screen.getByText(/2 answers are not reviewed yet/)).toBeInTheDocument();
  });

  it("accepts, rejects and undoes single answers", async () => {
    render(<QuestionnaireReview token="tok" id="q1" />);
    await screen.findByText("Is MFA enforced?");
    // Each action disables the buttons until the reload finishes, so wait for them first.
    const clickWhenReady = async (question: string, name: string) => {
      await waitFor(() => expect(within(card(question)).getByRole("button", { name })).toBeEnabled());
      fireEvent.click(within(card(question)).getByRole("button", { name }));
    };
    await clickWhenReady("Is MFA enforced?", "Accept");
    await waitFor(() => expect(patches()).toEqual([{ action: "accept", answerIds: ["a1"] }]));
    await clickWhenReady("Do staff get training?", "Reject");
    await waitFor(() => expect(patches()[1]).toEqual({ action: "reject", answerIds: ["a2"] }));
    await clickWhenReady("Are backups tested?", "Undo");
    await waitFor(() => expect(patches()[2]).toEqual({ action: "reset", answerIds: ["a4"] }));
  });

  it("edits a draft, and writes an answer where there is no evidence", async () => {
    render(<QuestionnaireReview token="tok" id="q1" />);
    await screen.findByText("Is MFA enforced?");
    const mfa = card("Is MFA enforced?");
    fireEvent.click(within(mfa).getByRole("button", { name: "Edit" }));
    fireEvent.click(within(mfa).getByRole("button", { name: "Cancel" }));
    fireEvent.click(within(mfa).getByRole("button", { name: "Edit" }));
    fireEvent.change(within(mfa).getByLabelText("Your answer to row 1"), { target: { value: " Yes, everywhere. " } });
    fireEvent.click(within(mfa).getByRole("button", { name: "Save and accept" }));
    await waitFor(() => expect(patches()[0]).toEqual({ action: "edit", answerIds: ["a1"], answer: "Yes, everywhere." }));

    await waitFor(() => expect(within(card("Do staff get training?")).getByRole("button", { name: "Reject" })).toBeEnabled());
    const training = card("Do staff get training?");
    const box = within(training).getByPlaceholderText(/We hold no evidence/);
    expect(within(training).getByRole("button", { name: "Save and accept" })).toBeDisabled();
    fireEvent.change(box, { target: { value: "Annual training via our HR provider." } });
    fireEvent.click(within(training).getByRole("button", { name: "Save and accept" }));
    await waitFor(() => expect(patches()[1]).toEqual({ action: "edit", answerIds: ["a2"], answer: "Annual training via our HR provider." }));
    fireEvent.click(within(card("Is RDP closed?")).getByRole("button", { name: "Edit" }));
    expect(within(card("Is RDP closed?")).getByLabelText("Your answer to row 3")).toBeInTheDocument();
  });

  it("bulk-accepts high-confidence drafts and reports skipped ones", async () => {
    current = detail([answer({}), answer({ id: "a5", row_index: 4, question: "Is TLS used?" })]);
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => (init?.method === "PATCH" ? json(200, { updated: ["a1"], skipped: ["a5"] }) : json(200, current)));
    render(<QuestionnaireReview token="tok" id="q1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Accept 2 high-confidence drafts" }));
    await waitFor(() => expect(patches()[0]).toEqual({ action: "accept", answerIds: ["a1", "a5"] }));
    expect(await screen.findByText("1 answer still need writing before they can be accepted.")).toBeInTheDocument();
  });

  it("filters by status", async () => {
    render(<QuestionnaireReview token="tok" id="q1" />);
    await screen.findByText("Is MFA enforced?");
    fireEvent.click(screen.getByRole("button", { name: "Needs your answer (1)" }));
    expect(screen.queryByText("Is MFA enforced?")).not.toBeInTheDocument();
    expect(screen.getByText("Do staff get training?")).toBeInTheDocument();
    current = detail([answer({})]);
    fireEvent.click(screen.getByRole("button", { name: "Rejected (1)" }));
    fireEvent.click(screen.getByRole("button", { name: "Accepted (1)" }));
    fireEvent.click(screen.getByRole("button", { name: "To review (1)" }));
    expect(screen.getByText("Is MFA enforced?")).toBeInTheDocument();
  });

  it("shows Nothing here for an empty filter", async () => {
    current = detail([answer({})]);
    render(<QuestionnaireReview token="tok" id="q1" />);
    await screen.findByText("Is MFA enforced?");
    fireEvent.click(screen.getByRole("button", { name: "Rejected (0)" }));
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });

  it("exports in both formats", async () => {
    render(<QuestionnaireReview token="tok" id="q1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Export .xlsx" }));
    fireEvent.click(screen.getByRole("button", { name: "Export .csv" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/questionnaires/q1/export?format=csv", expect.anything()));
    expect(fetchMock).toHaveBeenCalledWith("/api/questionnaires/q1/export?format=xlsx", expect.anything());
  });

  it("offers the other format for a CSV questionnaire and shows export failures", async () => {
    current = { ...detail([answer({})]), questionnaire: { ...detail([]).questionnaire, source_format: "csv" } };
    fetchMock.mockImplementation(async (url: string) => (url.includes("/export") ? json(500, { error: "Couldn't build the export." }) : json(200, current)));
    render(<QuestionnaireReview token="tok" id="q1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Export .xlsx" }));
    expect(await screen.findByText("Couldn't build the export.")).toBeInTheDocument();
  });

  it("rewords with AI until nothing remains", async () => {
    current = detail(base, true);
    let n = 0;
    fetchMock.mockImplementation(async (url: string) => {
      if (url.endsWith("/word")) return json(200, n++ === 0 ? { status: "ok", worded: 10, remaining: 3 } : { status: "ok", worded: 2, remaining: 0 });
      return json(200, current);
    });
    render(<QuestionnaireReview token="tok" id="q1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Improve wording with AI" }));
    expect(await screen.findByText("AI reworded 12 drafts. Check each one before accepting.")).toBeInTheDocument();
  });

  it("says when AI wording isn't available, and shows a failed call", async () => {
    current = detail(base, true);
    fetchMock.mockImplementation(async (url: string) => (url.endsWith("/word") ? json(200, { status: "not_configured", worded: 0, remaining: 4 }) : json(200, current)));
    render(<QuestionnaireReview token="tok" id="q1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Improve wording with AI" }));
    expect(await screen.findByText(/AI wording isn't available right now/)).toBeInTheDocument();
    fetchMock.mockImplementation(async (url: string) => (url.endsWith("/word") ? json(429, {}) : json(200, current)));
    fireEvent.click(screen.getByRole("button", { name: "Improve wording with AI" }));
    expect(await screen.findByText("Too many requests. Try again in a few minutes.")).toBeInTheDocument();
  });

  it("shows a failed review action", async () => {
    fetchMock.mockImplementation(async (_u: string, init?: RequestInit) => (init?.method === "PATCH" ? json(500, { error: "Something went wrong on our side." }) : json(200, current)));
    render(<QuestionnaireReview token="tok" id="q1" />);
    await screen.findByText("Is MFA enforced?");
    fireEvent.click(within(card("Is MFA enforced?")).getByRole("button", { name: "Accept" }));
    expect(await screen.findByText("Something went wrong on our side.")).toBeInTheDocument();
  });

  it("shows a load failure, and nothing without a token", async () => {
    fetchMock.mockResolvedValueOnce(json(404, { error: "Questionnaire not found" }));
    const { unmount } = render(<QuestionnaireReview token="tok" id="q1" />);
    expect(await screen.findByText("Questionnaire not found")).toBeInTheDocument();
    unmount();
    fetchMock.mockClear();
    render(<QuestionnaireReview token={null} id="q1" />);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
