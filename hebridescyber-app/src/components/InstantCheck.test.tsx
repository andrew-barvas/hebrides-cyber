import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
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
});
