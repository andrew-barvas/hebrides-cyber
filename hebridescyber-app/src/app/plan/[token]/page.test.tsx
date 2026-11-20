import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

vi.mock("next/navigation", () => ({ useParams: () => ({ token: "A".repeat(43) }) }));

import FixPlanPage from "./page";

const plan = {
  title: "Go-live",
  host: "shop.example.com",
  createdAt: "2026-11-01T00:00:00Z",
  expiresAt: "2027-01-30T00:00:00Z",
  progress: { fixed: 1, markedDone: 0, open: 1, total: 2 },
  items: [
    { checkId: "tls.old", position: 1, severity: "high", title: "Old TLS", remediation: "Turn off TLS 1.0.", status: "fixed", fixedAt: "2026-11-10T00:00:00Z", markedDoneAt: null, note: "" },
    { checkId: "headers.hsts", position: 2, severity: "medium", title: "Missing HSTS", remediation: "Add the header.", status: "open", fixedAt: null, markedDoneAt: null, note: "" },
  ],
};

describe("shared fix plan page", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows progress, each item's fix and status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => plan }));
    render(<FixPlanPage />);
    expect(await screen.findByRole("heading", { name: "Go-live" })).toBeInTheDocument();
    expect(screen.getByText(/fixed and confirmed/)).toBeInTheDocument();
    expect(screen.getByText(/Fixed, confirmed by a scan · 10 Nov 2026/)).toBeInTheDocument();
    expect(screen.getByText("Add the header.")).toBeInTheDocument();
  });

  it("marks an item done with a note and reloads", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => plan });
    vi.stubGlobal("fetch", fetchMock);
    render(<FixPlanPage />);
    fireEvent.change(await screen.findByLabelText(/Note for them/), { target: { value: "Added in Cloudflare" } });
    fireEvent.click(screen.getByRole("button", { name: "I've done this" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/done"))).toBe(true));
    const post = fetchMock.mock.calls.find(([u]) => String(u).endsWith("/done"));
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ checkId: "headers.hsts", done: true, note: "Added in Cloudflare" });
  });

  it("shows the link's error when it's no longer valid", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, json: async () => ({ error: "This fix plan link isn't valid any more. Ask whoever sent it for a new one." }) }));
    render(<FixPlanPage />);
    expect(await screen.findByText(/isn't valid any more/)).toBeInTheDocument();
  });
});
