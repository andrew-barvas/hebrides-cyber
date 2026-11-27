import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const { pushMock } = vi.hoisted(() => ({ pushMock: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: pushMock }) }));

import QuestionnaireList from "./QuestionnaireList";

const json = (status: number, body: unknown) => ({ ok: status < 400, status, json: async () => body }) as unknown as Response;
const summary = { id: "q1", name: "Insurer.xlsx", source_format: "xlsx", created_at: "2026-11-20T10:00:00Z", updated_at: "u", counts: { draft: 3, needs_answer: 2, accepted: 5, rejected: 0, total: 10 } };
const preview = {
  format: "csv",
  sheets: [
    { name: "Intro", headers: ["A", "B"], sample: [["x", "y"]], rowCount: 1, suggestedColumn: 0, confident: false, questions: 0 },
    { name: "Questions", headers: ["Ref", "Question"], sample: [["1", "Is MFA enforced?"], ["2", ""]], rowCount: 2, suggestedColumn: 1, confident: true, questions: 2 },
  ],
};

let fetchMock: ReturnType<typeof vi.fn>;
const file = (name = "q.csv", size?: number) => {
  const f = new File(["Ref,Question\n1,Is MFA enforced?"], name, { type: "text/csv" });
  if (size) Object.defineProperty(f, "size", { value: size });
  return f;
};
const choose = (f: File) => fireEvent.change(screen.getByLabelText("Questionnaire file"), { target: { files: [f] } });

beforeEach(() => {
  pushMock.mockReset();
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/questionnaires" && !init?.method) return json(200, { questionnaires: [summary], enabled: true, aiAvailable: false });
    if (url === "/api/questionnaires" && init?.method === "POST") {
      const body = JSON.parse(String(init.body));
      return body.preview ? json(200, preview) : json(201, { id: "new-q", questions: 2 });
    }
    if (url === "/api/questionnaires/q1" && init?.method === "DELETE") return { ok: true, status: 204, json: async () => ({}) } as unknown as Response;
    return json(404, { error: "not found" });
  });
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("QuestionnaireList", () => {
  it("lists earlier questionnaires with their progress", async () => {
    render(<QuestionnaireList token="tok" />);
    expect(await screen.findByText("Insurer.xlsx")).toBeInTheDocument();
    expect(screen.getByText(/5 of 10 accepted · 2 need your answer/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/questionnaires", expect.objectContaining({ headers: { Authorization: "Bearer tok" } }));
  });

  it("previews an upload on the sheet with the most questions, then drafts and opens it", async () => {
    render(<QuestionnaireList token="tok" />);
    await screen.findByText("Insurer.xlsx");
    choose(file());
    expect(await screen.findByText(/q\.csv: 2 rows/)).toBeInTheDocument();
    expect((screen.getByLabelText("Sheet") as HTMLSelectElement).value).toBe("1");
    expect(screen.getByRole("option", { name: "Question (detected)" })).toBeInTheDocument();
    expect(screen.getByText("Is MFA enforced?")).toBeInTheDocument();
    expect(screen.getByText("(empty)")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Draft answers" }));
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/dashboard/questionnaires/new-q"));
    const create = JSON.parse(String(fetchMock.mock.calls.find((c) => c[1]?.method === "POST" && !JSON.parse(String(c[1].body)).preview)![1].body));
    expect(create).toMatchObject({ fileName: "q.csv", sheet: "Questions", questionColumn: 1 });
  });

  it("warns when the column was a guess, and lets the customer change sheet, column or cancel", async () => {
    render(<QuestionnaireList token="tok" />);
    await screen.findByText("Insurer.xlsx");
    choose(file());
    await screen.findByLabelText("Sheet");
    fireEvent.change(screen.getByLabelText("Sheet"), { target: { value: "0" } });
    expect(screen.getByText(/weren't sure which column/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Which column holds the questions?"), { target: { value: "1" } });
    expect(screen.queryByText(/weren't sure which column/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByLabelText("Sheet")).not.toBeInTheDocument();
  });

  it("refuses the wrong file type or size before uploading, and shows server errors", async () => {
    render(<QuestionnaireList token="tok" />);
    await screen.findByText("Insurer.xlsx");
    choose(file("q.xls"));
    expect(await screen.findByText(/Upload an .xlsx or .csv file/)).toBeInTheDocument();
    choose(file("q.csv", 6 * 1024 * 1024));
    expect(await screen.findByText("The file is larger than 5 MB.")).toBeInTheDocument();
    fetchMock.mockResolvedValueOnce(json(400, { error: "No rows were found under the header row." }));
    choose(file());
    expect(await screen.findByText("No rows were found under the header row.")).toBeInTheDocument();
  });

  it("shows a failed draft and stays on the page", async () => {
    render(<QuestionnaireList token="tok" />);
    await screen.findByText("Insurer.xlsx");
    choose(file());
    await screen.findByRole("button", { name: "Draft answers" });
    fetchMock.mockResolvedValueOnce(json(400, { error: "No questions were found in that column." }));
    fireEvent.click(screen.getByRole("button", { name: "Draft answers" }));
    expect(await screen.findByText("No questions were found in that column.")).toBeInTheDocument();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("deletes after confirmation", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<QuestionnaireList token="tok" />);
    await screen.findByText("Insurer.xlsx");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(fetchMock).not.toHaveBeenCalledWith("/api/questionnaires/q1", expect.anything());
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(screen.queryByText("Insurer.xlsx")).not.toBeInTheDocument());
    expect(screen.getByText("No questionnaires yet")).toBeInTheDocument();
    confirm.mockRestore();
  });

  it("shows a failed delete", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fetchMock.mockImplementation(async (_u: string, init?: RequestInit) => (init?.method === "DELETE" ? json(500, { error: "Something went wrong" }) : json(200, { questionnaires: [summary], enabled: true, aiAvailable: false })));
    render(<QuestionnaireList token="tok" />);
    await screen.findByText("Insurer.xlsx");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Something went wrong")).toBeInTheDocument();
  });

  it("says when the feature isn't enabled, and when the list fails", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { questionnaires: [], enabled: false, aiAvailable: false }));
    const { unmount } = render(<QuestionnaireList token="tok" />);
    expect(await screen.findByText("Not available yet")).toBeInTheDocument();
    unmount();
    fetchMock.mockResolvedValueOnce(json(429, {}));
    render(<QuestionnaireList token="tok" />);
    expect(await screen.findByText("Too many requests. Try again in a few minutes.")).toBeInTheDocument();
  });

  it("does nothing without a token", () => {
    render(<QuestionnaireList token={null} />);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
