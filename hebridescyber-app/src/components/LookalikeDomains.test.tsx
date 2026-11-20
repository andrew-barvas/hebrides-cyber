import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { result } = vi.hoisted(() => ({ result: { current: { data: [] as unknown[] | null, error: null as unknown } } }));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: () => ({
      select: () => ({ order: () => ({ limit: () => Promise.resolve(result.current) }) }),
    }),
  },
}));

import LookalikeDomains from "./LookalikeDomains";

const row = { candidate_domain: "examp1e.com", target_domain: "example.com", technique: "substitution", first_seen_at: "2026-10-30T00:00:00Z", notified_at: "2026-11-02T00:00:00Z" };

describe("LookalikeDomains", () => {
  beforeEach(() => {
    result.current = { data: [], error: null };
  });

  it("says when none have been found", async () => {
    render(<LookalikeDomains />);
    expect(await screen.findByText(/None found/)).toBeInTheDocument();
  });

  it("lists each lookalike with how it differs and when it was spotted, and opens the kit", async () => {
    result.current = { data: [row], error: null };
    render(<LookalikeDomains />);
    expect(await screen.findByText("examp1e.com")).toBeInTheDocument();
    expect(screen.getByText(/looks like example.com, a character swapped for a lookalike, spotted 2 Nov 2026/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("What to do"));
    expect(screen.getByText("Block it in your email.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Look up examp1e.com/ })).toHaveAttribute("href", "https://lookup.icann.org/en/lookup?name=examp1e.com");
    expect(screen.getByText(/Subject: Abuse report: examp1e.com may be impersonating example.com/)).toBeInTheDocument();
  });

  it("copies the report, and says so", async () => {
    result.current = { data: [row], error: null };
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<LookalikeDomains />);
    fireEvent.click(await screen.findByText("What to do"));
    fireEvent.click(screen.getByRole("button", { name: "Copy report" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Copied."));
    expect(writeText.mock.calls[0][0]).toMatch(/^Subject: Abuse report/);
  });

  it("says when copying fails, so the owner can select the text instead", async () => {
    result.current = { data: [{ ...row, notified_at: null }], error: null };
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    render(<LookalikeDomains />);
    expect(await screen.findByText(/spotted 30 Oct 2026/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("What to do"));
    fireEvent.click(screen.getByRole("button", { name: "Copy report" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Couldn't copy automatically"));
  });

  it("shows a quiet error rather than an empty list when loading fails", async () => {
    result.current = { data: null, error: { message: "relation does not exist" } };
    render(<LookalikeDomains />);
    expect(await screen.findByText(/couldn't be loaded/)).toBeInTheDocument();
    expect(screen.queryByText(/None found/)).toBeNull();
  });
});
