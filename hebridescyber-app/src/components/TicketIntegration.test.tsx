import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { getSessionMock } = vi.hoisted(() => ({ getSessionMock: vi.fn() }));
vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));

import TicketIntegration from "./TicketIntegration";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

beforeEach(() => {
  getSessionMock.mockReset().mockResolvedValue({ access_token: "tok" });
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

function bodyOf(callIndex: number) {
  return JSON.parse(fetchMock.mock.calls[callIndex][1].body);
}

describe("TicketIntegration", () => {
  it("reads its status from the server summary, not the table", async () => {
    fetchMock.mockResolvedValueOnce(ok({ integration: null }));
    render(<TicketIntegration />);
    await screen.findByRole("group", { name: "Choose a tracker" });
    expect(fetchMock).toHaveBeenCalledWith("/api/account/ticket-integration", expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer tok" }) }));
  });

  it("offers all four trackers, with labelled fields", async () => {
    fetchMock.mockResolvedValueOnce(ok({ integration: null }));
    render(<TicketIntegration />);
    for (const name of ["Jira", "Linear", "ServiceNow", "GitHub Issues"]) {
      expect(await screen.findByRole("button", { name })).toBeInTheDocument();
    }
    expect(screen.getByLabelText("Jira site URL")).toBeInTheDocument();
    expect(screen.getByLabelText("API token")).toHaveAttribute("type", "password");
  });

  it("splits owner/repo when connecting GitHub Issues", async () => {
    fetchMock.mockResolvedValueOnce(ok({ integration: null })).mockResolvedValueOnce(ok({ ok: true })).mockResolvedValueOnce(ok({ integration: null }));
    render(<TicketIntegration />);
    fireEvent.click(await screen.findByRole("button", { name: "GitHub Issues" }));
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: " acme/webapp " } });
    fireEvent.change(screen.getByLabelText("Access token"), { target: { value: "github_pat_x" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect GitHub Issues" }));

    await screen.findByText(/Connected to GitHub Issues/);
    expect(fetchMock.mock.calls[1][1].method).toBe("POST");
    expect(bodyOf(1)).toEqual({ provider: "github", owner: "acme", repo: "webapp", token: "github_pat_x" });
  });

  it("sends ServiceNow fields under their API names", async () => {
    fetchMock.mockResolvedValueOnce(ok({ integration: null })).mockResolvedValueOnce(ok({ ok: true })).mockResolvedValueOnce(ok({ integration: null }));
    render(<TicketIntegration />);
    fireEvent.click(await screen.findByRole("button", { name: "ServiceNow" }));
    fireEvent.change(screen.getByLabelText("Instance URL"), { target: { value: "https://acme.service-now.com" } });
    fireEvent.change(screen.getByLabelText("Integration username"), { target: { value: "svc" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect ServiceNow" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(bodyOf(1)).toEqual({ provider: "servicenow", instanceUrl: "https://acme.service-now.com", username: "svc", password: "pw" });
  });

  it("shows the server's error when a save is rejected", async () => {
    fetchMock
      .mockResolvedValueOnce(ok({ integration: null }))
      .mockResolvedValueOnce({ ok: false, status: 400, json: async () => ({ error: "ServiceNow rejected the credentials" }) });
    render(<TicketIntegration />);
    fireEvent.click(await screen.findByRole("button", { name: "ServiceNow" }));
    fireEvent.change(screen.getByLabelText("Instance URL"), { target: { value: "https://acme.service-now.com" } });
    fireEvent.change(screen.getByLabelText("Integration username"), { target: { value: "svc" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "bad" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect ServiceNow" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("ServiceNow rejected the credentials");
  });

  it("shows where tickets go once connected, and toggles auto-close", async () => {
    fetchMock
      .mockResolvedValueOnce(ok({ integration: { provider: "github", destination: "acme/webapp", autoCloseEnabled: false } }))
      .mockResolvedValueOnce(ok({ ok: true }))
      .mockResolvedValueOnce(ok({ integration: { provider: "github", destination: "acme/webapp", autoCloseEnabled: true } }));
    render(<TicketIntegration />);
    expect(await screen.findByText("GitHub Issues")).toBeInTheDocument();
    expect(screen.getByText(/acme\/webapp/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox", { name: /Close tickets automatically when fixed/ }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(fetchMock.mock.calls[1][1].method).toBe("PATCH");
    expect(bodyOf(1)).toEqual({ provider: "github", autoCloseEnabled: true });
  });
});
