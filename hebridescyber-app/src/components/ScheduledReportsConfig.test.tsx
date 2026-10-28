import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock } = vi.hoisted(() => ({ getSessionMock: vi.fn() }));
vi.mock("@/lib/supabaseClient", () => ({ supabase: { auth: { getSession: getSessionMock } } }));

import ScheduledReportsConfig from "./ScheduledReportsConfig";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

beforeEach(() => {
  getSessionMock.mockReset().mockResolvedValue({ data: { session: { access_token: "tok" } } });
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

async function openForm() {
  render(<ScheduledReportsConfig />);
  fireEvent.click(await screen.findByRole("button", { name: "+ New schedule" }));
  return screen.getByLabelText("Format") as HTMLSelectElement;
}

describe("ScheduledReportsConfig", () => {
  it("offers PDF, CSV and JSON, with PDF first and selected by default", async () => {
    fetchMock.mockResolvedValueOnce(ok({ reports: [] }));
    const select = await openForm();

    expect([...select.options].map((o) => [o.value, o.textContent])).toEqual([
      ["pdf", "PDF (attached)"],
      ["csv", "CSV"],
      ["json", "JSON"],
    ]);
    expect(select.value).toBe("pdf");
  });

  it("creates a PDF schedule by default", async () => {
    fetchMock.mockResolvedValueOnce(ok({ reports: [] })).mockResolvedValueOnce(ok({ id: "1" })).mockResolvedValueOnce(ok({ reports: [] }));
    await openForm();
    fireEvent.change(screen.getByLabelText(/Recipients/), { target: { value: "sec@example.com, cto@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create schedule" }));

    await screen.findByText("Report schedule created.");
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/account/scheduled-reports");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({
      targetUrl: null,
      frequency: "weekly",
      format: "pdf",
      recipients: ["sec@example.com", "cto@example.com"],
    });
  });

  it("sends the format the customer picks", async () => {
    fetchMock.mockResolvedValueOnce(ok({ reports: [] })).mockResolvedValueOnce(ok({ id: "1" })).mockResolvedValueOnce(ok({ reports: [] }));
    const select = await openForm();
    fireEvent.change(select, { target: { value: "csv" } });
    fireEvent.change(screen.getByLabelText(/Recipients/), { target: { value: "sec@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create schedule" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(JSON.parse(fetchMock.mock.calls[1][1].body).format).toBe("csv");
  });

  it("lists an existing schedule with its format", async () => {
    fetchMock.mockResolvedValueOnce(
      ok({
        reports: [{ id: "r1", target_url: null, frequency: "monthly", format: "pdf", recipients: ["sec@example.com"], enabled: true, last_sent: null, next_due: null }],
      }),
    );
    render(<ScheduledReportsConfig />);

    expect(await screen.findByText("pdf")).toBeInTheDocument();
    expect(screen.getByText("monthly")).toBeInTheDocument();
    expect(screen.getByText("sec@example.com")).toBeInTheDocument();
  });
});
