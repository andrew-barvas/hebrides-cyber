import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import CeAssessment from "./CeAssessment";
import { CE_QUESTIONS } from "@/lib/ceSelfAssessment";
import type { Finding } from "@/lib/scanners";

// The latest-completed-scan query result the mocked supabase client returns.
const scanState: { findings: Finding[] | null } = { findings: null };

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: () => ({
      select: () => ({
        eq: () => ({
          order: () => ({
            limit: () => ({
              maybeSingle: () =>
                Promise.resolve({
                  data: scanState.findings ? { id: "s1", created_at: "t", scan_results: [{ results: { findings: scanState.findings } }] } : null,
                  error: null,
                }),
            }),
          }),
        }),
      }),
    }),
  },
}));

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

beforeEach(() => {
  scanState.findings = null;
  fetchMock.mockReset();
  fetchMock.mockResolvedValue(ok({ available: true, answers: [] }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("CeAssessment", () => {
  it("renders the questionnaire for every catalogued question", async () => {
    render(<CeAssessment token="tok" />);
    await waitFor(() => expect(screen.getByText("Combined readiness")).toBeInTheDocument());
    for (const q of CE_QUESTIONS) {
      expect(screen.getByText(q.prompt)).toBeInTheDocument();
    }
  });

  it("shows a not-enabled message before migration 061", async () => {
    fetchMock.mockResolvedValue(ok({ available: false, answers: [] }));
    render(<CeAssessment token="tok" />);
    expect(await screen.findByText("Self-assessment not enabled yet")).toBeInTheDocument();
  });

  it("saves an answer via PUT when a choice is clicked", async () => {
    render(<CeAssessment token="tok" />);
    await waitFor(() => expect(screen.getByText("Combined readiness")).toBeInTheDocument());

    const firstPrompt = CE_QUESTIONS[0].prompt;
    const group = screen.getByRole("group", { name: firstPrompt });
    fireEvent.click(group.querySelector("button")!); // "Yes"

    await waitFor(() => {
      const put = fetchMock.mock.calls.find((c) => c[1]?.method === "PUT");
      expect(put).toBeTruthy();
      const body = JSON.parse(put![1].body);
      expect(body.answers).toContainEqual(expect.objectContaining({ questionKey: CE_QUESTIONS[0].key, answer: "yes" }));
    });
  });

  it("reflects a loaded answer as pressed", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, answers: [{ questionKey: CE_QUESTIONS[0].key, answer: "no" }] }));
    render(<CeAssessment token="tok" />);
    await waitFor(() => expect(screen.getByText("Combined readiness")).toBeInTheDocument());
    const group = screen.getByRole("group", { name: CE_QUESTIONS[0].prompt });
    const noButton = [...group.querySelectorAll("button")].find((b) => b.textContent === "No")!;
    expect(noButton.getAttribute("aria-pressed")).toBe("true");
  });

  it("folds the latest scan's findings into the control evidence", async () => {
    scanState.findings = [
      { severity: "critical", title: "No HTTPS", detail: "", checkId: "tls.no-https" },
    ];
    render(<CeAssessment token="tok" />);
    await waitFor(() => expect(screen.getByText("Combined readiness")).toBeInTheDocument());
    // Secure configuration carries a scan status once findings are present.
    expect(screen.getAllByText(/Scan evidence for this control/).length).toBeGreaterThan(0);
  });
});
