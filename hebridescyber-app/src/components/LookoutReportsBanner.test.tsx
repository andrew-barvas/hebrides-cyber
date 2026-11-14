import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import LookoutReportsBanner from "./LookoutReportsBanner";

afterEach(() => vi.unstubAllGlobals());

describe("LookoutReportsBanner", () => {
  it("renders nothing for a customer with no reports", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ reports: [] }))));
    const { container } = render(<LookoutReportsBanner token="t" />);
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("points to unread reports", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ reports: [{ status: "published" }, { status: "acknowledged" }] }))));
    render(<LookoutReportsBanner token="t" />);
    await waitFor(() => expect(screen.getByText(/1 new Lookout report from your engineer/)).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Read it" })).toHaveAttribute("href", "/dashboard/lookout");
  });
});
