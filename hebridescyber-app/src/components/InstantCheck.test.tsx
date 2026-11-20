import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import InstantCheck from "./InstantCheck";

const result = { target: "https://example.com", score: 90, counts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, total: 1, findings: [{ severity: "medium", title: "No DMARC record", detail: "d" }], hidden: 0, checkedAt: "2026-11-14T00:00:00Z" };

afterEach(() => vi.unstubAllGlobals());

describe("InstantCheck", () => {
  it("runs once straight away for an address passed from the homepage", async () => {
    const fetchMock = vi.fn<(url: string, init?: RequestInit) => Promise<Response>>(async () => new Response(JSON.stringify(result), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<InstantCheck initialUrl="example.com" />);
    await waitFor(() => expect(screen.getByText("No DMARC record")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ url: "example.com" });
    expect(screen.getByLabelText("Website address")).toHaveValue("example.com");
  });

  it("waits for the visitor when no address was passed", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<InstantCheck />);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows how the score compares only when the check returns a benchmark", async () => {
    const withBenchmark = { ...result, benchmark: { betterThanPercent: 62, groupSize: 1240, windowDays: 90, kind: "free_check" } };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(withBenchmark), { status: 200 })));
    const { unmount } = render(<InstantCheck initialUrl="example.com" />);
    expect(await screen.findByText("Better than 62% of the 1,240 sites given this free check in the last 90 days.")).toBeInTheDocument();
    unmount();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(result), { status: 200 })));
    render(<InstantCheck initialUrl="example.com" />);
    await waitFor(() => expect(screen.getByText("No DMARC record")).toBeInTheDocument());
    expect(screen.queryByText(/Better than/)).toBeNull();
  });

  it("runs a typed-in address, and shows the server's error or a network failure", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "That site has been checked a lot recently." }), { status: 429 })));
    const { unmount } = render(<InstantCheck />);
    fireEvent.change(screen.getByLabelText("Website address"), { target: { value: "example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText("That site has been checked a lot recently.")).toBeInTheDocument();
    unmount();
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    render(<InstantCheck initialUrl="example.com" />);
    expect(await screen.findByText("Could not reach the service. Please try again.")).toBeInTheDocument();
  });
});
