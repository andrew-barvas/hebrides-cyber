import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

vi.mock("@/lib/auth", () => ({ getSession: async () => ({ access_token: "tok" }) }));

import M365Config from "./M365Config";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe("M365Config", () => {
  const fetchMock = vi.fn();
  const assign = vi.fn();
  const originalLocation = window.location;

  beforeEach(() => {
    fetchMock.mockReset();
    assign.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    Object.defineProperty(window, "location", { configurable: true, value: { ...originalLocation, search: "", assign } });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
  });

  it("starts the consent flow by sending the browser to Microsoft", async () => {
    fetchMock.mockResolvedValueOnce(json({ configured: true, connected: false, tenantId: null, consentedAt: null, lastCheckedAt: null }));
    fetchMock.mockResolvedValueOnce(json({ url: "https://login.microsoftonline.com/organizations/v2.0/adminconsent?x=1" }));
    render(<M365Config />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect Microsoft 365" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://login.microsoftonline.com/organizations/v2.0/adminconsent?x=1"));
    expect(fetchMock.mock.calls[1][1]).toMatchObject({ method: "POST", headers: { Authorization: "Bearer tok" } });
  });

  it("shows the connected tenant and disconnects with the revoke steps", async () => {
    fetchMock.mockResolvedValueOnce(json({ configured: true, connected: true, tenantId: "2222-t", consentedAt: "2026-10-01T10:00:00Z", lastCheckedAt: null }));
    fetchMock.mockResolvedValueOnce(json({ ok: true, revokeSteps: "Delete the app in Entra." }));
    fetchMock.mockResolvedValueOnce(json({ configured: true, connected: false, tenantId: null, consentedAt: null, lastCheckedAt: null }));
    render(<M365Config />);
    expect(await screen.findByText("2222-t")).toBeInTheDocument();
    expect(screen.getByText("Not checked yet.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(await screen.findByText(/Delete the app in Entra\./)).toBeInTheDocument();
    expect(fetchMock.mock.calls[1][1]).toMatchObject({ method: "DELETE" });
  });

  it("shows the callback's outcome and API errors", async () => {
    window.location.search = "?m365=missing_permissions";
    fetchMock.mockResolvedValueOnce(json({ configured: true, connected: false, tenantId: null, consentedAt: null, lastCheckedAt: null }));
    fetchMock.mockResolvedValueOnce(json({ error: "Microsoft 365 posture checks are on the Pro plan and above." }, 403));
    render(<M365Config />);
    expect(await screen.findByText(/without every permission/)).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Connect Microsoft 365" }));
    expect(await screen.findByText(/Pro plan and above/)).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it("says so when the deployment has no app registration", async () => {
    fetchMock.mockResolvedValueOnce(json({ configured: false, connected: false, tenantId: null, consentedAt: null, lastCheckedAt: null }));
    render(<M365Config />);
    expect(await screen.findByText(/aren.t available on this deployment/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect Microsoft 365" })).not.toBeInTheDocument();
  });
});
