import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import PortfolioReportButton, { fetchPortfolioReport } from "./PortfolioReportButton";

describe("PortfolioReportButton", () => {
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => "blob:report");
    URL.revokeObjectURL = vi.fn();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("downloads the PDF with the bearer token", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200, blob: async () => new Blob(["%PDF"]) }));
    vi.stubGlobal("fetch", fetchMock);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<PortfolioReportButton token="tok" />);
    fireEvent.click(screen.getByRole("button", { name: "↓ Portfolio PDF" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(fetchMock).toHaveBeenCalledWith("/api/portfolio-report", { headers: { Authorization: "Bearer tok" } });
    expect(screen.queryByRole("alert")).toBeNull();
    click.mockRestore();
  });

  it("turns the route's error codes into plain words", async () => {
    for (const [status, body, message] of [
      [403, { code: "plan_required" }, "part of the Agency plan"],
      [404, { code: "no_sites" }, "Add sites to monitoring first"],
      [429, {}, "Too many report requests"],
      [500, {}, "could not be generated (500)"],
    ] as const) {
      vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body), { status })));
      await expect(fetchPortfolioReport("tok")).rejects.toThrow(message);
    }
    vi.stubGlobal("fetch", vi.fn(async () => new Response("not json", { status: 502 })));
    await expect(fetchPortfolioReport("tok")).rejects.toThrow("(502)");
  });

  it("shows the error, and is disabled without a session", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ code: "no_sites" }), { status: 404 })));
    const { unmount } = render(<PortfolioReportButton token="tok" />);
    fireEvent.click(screen.getByRole("button", { name: "↓ Portfolio PDF" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/Add sites to monitoring first/);
    unmount();
    render(<PortfolioReportButton token={null} />);
    expect((screen.getByRole("button", { name: "↓ Portfolio PDF" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
