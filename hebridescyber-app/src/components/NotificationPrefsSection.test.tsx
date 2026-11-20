import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock } = vi.hoisted(() => ({ getSessionMock: vi.fn() }));
vi.mock("@/lib/supabaseClient", () => ({ supabase: { auth: { getSession: getSessionMock } } }));

import NotificationPrefsSection from "./NotificationPrefsSection";

const json = (status: number, body: unknown) => ({ ok: status < 400, status, json: async () => body }) as unknown as Response;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  getSessionMock.mockReset().mockResolvedValue({ data: { session: { access_token: "tok" } } });
  fetchMock = vi.fn(async (_url: string, init?: { method?: string }) =>
    init?.method === "PATCH" ? json(200, { ok: true }) : json(200, { notify_email: true, notify_score_threshold: 70, notify_severity_min: "high", notify_weekly_fix: true })
  );
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const weekly = () => screen.getByRole("checkbox", { name: /Weekly .one thing to fix. email/ });

describe("NotificationPrefsSection", () => {
  it("shows the stored preferences once loaded", async () => {
    render(<NotificationPrefsSection />);
    expect(await screen.findByText("Alert when score < 70")).toBeInTheDocument();
    expect(weekly()).toBeChecked();
    expect(screen.getByRole("combobox")).toHaveValue("high");
    expect(fetchMock).toHaveBeenCalledWith("/api/account/notification-prefs", { headers: { Authorization: "Bearer tok" } });
  });

  it("renders nothing without a session", async () => {
    getSessionMock.mockResolvedValue({ data: { session: null } });
    const { container } = render(<NotificationPrefsSection />);
    await waitFor(() => expect(getSessionMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("falls back to defaults when the read fails", async () => {
    fetchMock.mockImplementationOnce(async () => { throw new Error("offline"); });
    render(<NotificationPrefsSection />);
    expect(await screen.findByText("Alert on every scan")).toBeInTheDocument();
    expect(weekly()).toBeChecked();
  });

  it("saves every setting, including switching the weekly email off", async () => {
    render(<NotificationPrefsSection />);
    await screen.findByText("Alert when score < 70");
    fireEvent.click(weekly());
    fireEvent.change(screen.getByPlaceholderText("Any score"), { target: { value: "" } });
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    const patch = fetchMock.mock.calls.find((c) => (c[1] as { method?: string } | undefined)?.method === "PATCH");
    expect(JSON.parse((patch?.[1] as { body: string }).body)).toEqual({ notify_email: true, notify_weekly_fix: false, notify_score_threshold: null, notify_severity_min: null });
  });

  it("hides the thresholds when scan emails are off, and saves a new threshold", async () => {
    render(<NotificationPrefsSection />);
    await screen.findByText("Alert when score < 70");
    fireEvent.change(screen.getByPlaceholderText("Any score"), { target: { value: "55" } });
    expect(screen.getByText("Alert when score < 55")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "Send email on scan completion" }));
    expect(screen.queryByPlaceholderText("Any score")).not.toBeInTheDocument();
  });

  it.each([
    ["the server's reason", async () => json(400, { error: "No fields to update" }), "No fields to update"],
    ["a generic message for an unreadable error", async () => ({ ok: false, status: 500, json: async () => { throw new Error("x"); } }) as unknown as Response, "Failed to save"],
    ["a generic message when offline", async () => { throw new Error("offline"); }, "Failed to save"],
  ])("shows %s when saving fails", async (_label, impl, message) => {
    render(<NotificationPrefsSection />);
    await screen.findByText("Alert when score < 70");
    fetchMock.mockImplementationOnce(impl as never);
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it("does nothing on save once the session has gone", async () => {
    render(<NotificationPrefsSection />);
    await screen.findByText("Alert when score < 70");
    getSessionMock.mockResolvedValue({ data: { session: null } });
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save preferences" })).toBeEnabled());
    expect(fetchMock.mock.calls.filter((c) => (c[1] as { method?: string } | undefined)?.method === "PATCH")).toHaveLength(0);
  });

  it("labels the filter by which scans get an email, and loads 'only when something new is found'", async () => {
    fetchMock.mockImplementation(async () => json(200, { notify_email: true, notify_score_threshold: 70, notify_severity_min: "info", notify_weekly_fix: false }));
    render(<NotificationPrefsSection />);
    const select = (await screen.findByLabelText("Which scans to email about")) as HTMLSelectElement;
    expect(select.value).toBe("info");
    expect(screen.getByRole("option", { name: "Only when something new is found" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Every scan, even when nothing changed" })).toHaveValue("");
    expect(screen.getByRole("option", { name: "Only new high or critical findings" })).toHaveValue("high");
    expect(screen.getByText(/never trigger an email/)).toBeInTheDocument();
    expect(weekly()).not.toBeChecked();
  });

  it("maps 'every scan' to no filter, and saves scan emails switched off", async () => {
    fetchMock.mockImplementation(async (_url: string, init?: { method?: string }) =>
      init?.method === "PATCH" ? json(200, { ok: true }) : json(200, { notify_email: true, notify_score_threshold: null, notify_severity_min: null, notify_weekly_fix: true })
    );
    render(<NotificationPrefsSection />);
    const select = (await screen.findByLabelText("Which scans to email about")) as HTMLSelectElement;
    expect(select.value).toBe("");
    fireEvent.click(screen.getByRole("checkbox", { name: "Send email on scan completion" }));
    expect(screen.queryByLabelText("Which scans to email about")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
    await screen.findByText("Saved.");
    const patch = fetchMock.mock.calls.find((c) => (c[1] as { method?: string } | undefined)?.method === "PATCH");
    expect(JSON.parse((patch?.[1] as { body: string }).body)).toMatchObject({ notify_email: false, notify_severity_min: null });
  });
});
