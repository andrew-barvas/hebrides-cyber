import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { FixPlanShare } from "./FixPlanShare";
import type { ViewFinding } from "./ScanReportView";

const findings: ViewFinding[] = [
  { checkId: "headers.hsts", severity: "medium", title: "Missing HSTS", detail: "" },
  { checkId: "tls.old", severity: "high", title: "Old TLS", detail: "" },
  { checkId: "gone", severity: "critical", title: "Gone", detail: "", status: "fixed" },
  { checkId: "note", severity: "info", title: "Info only", detail: "" },
];

const listing = { plans: [{ id: "p1", title: "Go-live", host: "shop.example.com", createdAt: "2026-11-01T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z", revokedAt: null, progress: { fixed: 1, markedDone: 1, open: 0, total: 2 } }] };

function mockFetch(listStatus = 200) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.startsWith("/api/fix-plans?")) return { ok: listStatus === 200, status: listStatus, json: async () => listing };
    if (url === "/api/fix-plans" && init?.method === "POST") return { ok: true, status: 201, json: async () => ({ id: "p2", url: "https://www.hebridescyber.co.uk/plan/abc", expiresAt: "2027-01-01T00:00:00Z" }) };
    if (url.startsWith("/api/fix-plans/") && init?.method === "DELETE") return { ok: true, status: 200, json: async () => ({ revoked: true }) };
    return { ok: false, status: 404, json: async () => ({}) };
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("FixPlanShare", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders nothing for accounts below Agency (the list answers 403)", async () => {
    const fetchMock = mockFetch(403);
    const { container } = render(<FixPlanShare scanId="s1" host="shop.example.com" token="t" findings={findings} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("lists existing plans with progress and revokes one", async () => {
    const fetchMock = mockFetch();
    render(<FixPlanShare scanId="s1" host="shop.example.com" token="t" findings={findings} />);
    expect(await screen.findByText(/1 of 2 fixed, 1 marked done/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revoke link for Go-live" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([u, i]) => u === "/api/fix-plans/p1" && i?.method === "DELETE")).toBe(true));
  });

  it("offers only open, untriaged, non-info findings, worst first, and shows the new link once", async () => {
    const fetchMock = mockFetch();
    render(<FixPlanShare scanId="s1" host="shop.example.com" token="t" findings={findings} />);
    fireEvent.click(await screen.findByRole("button", { name: "Share a fix plan" }));
    const labels = screen.getAllByRole("checkbox").map((c) => c.closest("label")?.textContent);
    expect(labels).toEqual(["highOld TLS", "mediumMissing HSTS"]);
    fireEvent.click(screen.getByRole("button", { name: "Create link for 2 items" }));
    expect(await screen.findByText("https://www.hebridescyber.co.uk/plan/abc")).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([u, i]) => u === "/api/fix-plans" && i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ scanId: "s1", checkIds: ["tls.old", "headers.hsts"], expiresInDays: 90 });
  });

  it("lets the owner change the selection, cancel, and see a create error", async () => {
    const fetchMock = mockFetch();
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/fix-plans?")) return { ok: true, status: 200, json: async () => listing };
      if (init?.method === "POST") return { ok: false, status: 400, json: async () => ({ error: "Not on this scan: x" }) };
      return { ok: true, status: 200, json: async () => ({}) };
    });
    render(<FixPlanShare scanId="s1" host="shop.example.com" token="t" findings={findings} />);
    fireEvent.click(await screen.findByRole("button", { name: "Share a fix plan" }));
    fireEvent.click(screen.getByRole("checkbox", { name: /Old TLS/ }));
    expect(screen.getByRole("button", { name: "Create link for 1 item" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: /Old TLS/ }));
    fireEvent.change(screen.getByLabelText(/Title/), { target: { value: "Go-live" } });
    fireEvent.change(screen.getByLabelText(/Link works for/), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Create link for 2 items" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Not on this scan: x");
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({ title: "Go-live", expiresInDays: 30 });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Share a fix plan" })).toBeInTheDocument();
  });

  it("copies the new link, and copes when the clipboard refuses", async () => {
    mockFetch();
    const writeText = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error("denied"));
    Object.assign(navigator, { clipboard: { writeText } });
    render(<FixPlanShare scanId="s1" host="shop.example.com" token="t" findings={findings} />);
    fireEvent.click(await screen.findByRole("button", { name: "Share a fix plan" }));
    fireEvent.click(screen.getByRole("button", { name: "Create link for 2 items" }));
    fireEvent.click(await screen.findByRole("button", { name: "Copy link" }));
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copied" }));
    expect(await screen.findByRole("button", { name: "Copy link" })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith("https://www.hebridescyber.co.uk/plan/abc");
  });

  it("renders nothing when the list request fails outright", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    const { container } = render(<FixPlanShare scanId="s1" host="shop.example.com" token="t" findings={findings} />);
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
