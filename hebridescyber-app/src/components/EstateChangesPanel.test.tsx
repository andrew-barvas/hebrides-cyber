import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import EstateChangesPanel from "./EstateChangesPanel";

const counts = (o: Partial<Record<"critical" | "high" | "medium" | "low", number>> = {}) => {
  const c = { critical: 0, high: 0, medium: 0, low: 0, ...o };
  return { ...c, total: c.critical + c.high + c.medium + c.low };
};
const body = {
  available: true,
  since: "2026-10-15T00:00:00Z",
  until: "2026-11-14T00:00:00Z",
  opened: counts({ critical: 1, medium: 2 }),
  fixed: counts({ high: 4 }),
  openNow: counts({ low: 3 }),
  newHosts: ["new.example.com"],
  hosts: [],
  notableOpened: [{ host: "a.example.com", checkId: "x", severity: "critical", title: "OpenSSH CVE", firstSeenAt: "2026-11-01T00:00:00Z" }],
};

afterEach(() => vi.unstubAllGlobals());

describe("EstateChangesPanel", () => {
  it("shows opened, fixed and open-now counts, notable findings and new hosts", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body))));
    render(<EstateChangesPanel token="t" />);
    await waitFor(() => expect(screen.getByText("OpenSSH CVE")).toBeInTheDocument());
    expect(screen.getByText("1 critical, 2 medium")).toBeInTheDocument();
    expect(screen.getByText("4 high")).toBeInTheDocument();
    expect(screen.getByText("new.example.com")).toBeInTheDocument();
  });

  it("asks for the chosen window", async () => {
    const fetchMock = vi.fn<(url: string) => Promise<Response>>(async () => new Response(JSON.stringify(body)));
    vi.stubGlobal("fetch", fetchMock);
    render(<EstateChangesPanel token="t" />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "90 days" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([u]) => String(u).includes("days=90"))).toBe(true));
  });

  it("says so when loading fails instead of showing zeros, and hides before migration 043", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 500 })));
    const { unmount } = render(<EstateChangesPanel token="t" />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load what changed"));
    unmount();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ available: false }))));
    const { container } = render(<EstateChangesPanel token="t" />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
