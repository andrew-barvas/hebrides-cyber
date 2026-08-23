import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, within, waitFor } from "@testing-library/react";
import ScanList, { type Scan } from "./ScanList";

function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "scan-1",
    target_url: "https://example.com",
    status: "completed",
    created_at: "2026-03-01T00:00:00Z",
    score: 82,
    ...overrides,
  };
}

describe("ScanList", () => {
  it("shows an empty state when there are no scans", () => {
    render(<ScanList scans={[]} />);
    expect(screen.getByText(/No scans yet/i)).toBeInTheDocument();
  });

  it("renders a row per scan with its score and status", () => {
    render(<ScanList scans={[scan({ score: 91, status: "completed" })]} />);
    expect(screen.getByText("https://example.com")).toBeInTheDocument();
    expect(screen.getByText("91/100")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
  });

  it("shows a dash instead of a score badge when the scan has no score yet", () => {
    render(<ScanList scans={[scan({ score: null, status: "running" })]} />);
    expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
  });

  it("only shows the 'View report' link for a completed scan", () => {
    const { rerender } = render(<ScanList scans={[scan({ status: "completed" })]} />);
    expect(screen.getByText(/View report/i)).toBeInTheDocument();

    rerender(<ScanList scans={[scan({ status: "running" })]} />);
    expect(screen.queryByText(/View report/i)).not.toBeInTheDocument();
  });

  it("shows who a shared scan belongs to", () => {
    render(<ScanList scans={[scan({ sharedByEmail: "teammate@example.com" })]} />);
    expect(screen.getByText(/shared by teammate@example.com/i)).toBeInTheDocument();
  });

  it("does not show a delete control when onDelete is not provided", () => {
    render(<ScanList scans={[scan()]} />);
    expect(screen.queryByTitle("Delete scan")).not.toBeInTheDocument();
  });

  it("requires a second click to confirm delete, and calls onDelete only after confirming", async () => {
    const onDelete = vi.fn().mockResolvedValue(undefined);
    render(<ScanList scans={[scan({ id: "scan-42" })]} onDelete={onDelete} />);

    fireEvent.click(screen.getByTitle("Delete scan"));
    expect(onDelete).not.toHaveBeenCalled();

    const confirmButton = await screen.findByText("Confirm");
    fireEvent.click(confirmButton);

    expect(onDelete).toHaveBeenCalledWith("scan-42");
  });

  it("cancelling the delete confirmation does not call onDelete", () => {
    const onDelete = vi.fn();
    render(<ScanList scans={[scan()]} onDelete={onDelete} />);

    fireEvent.click(screen.getByTitle("Delete scan"));
    fireEvent.click(screen.getByText("Cancel"));

    expect(onDelete).not.toHaveBeenCalled();
    expect(screen.getByTitle("Delete scan")).toBeInTheDocument();
  });

  // Regression test: a delete failure (e.g. an RLS policy silently
  // matching zero rows, or a real network error) used to be swallowed
  // completely — no catch existed, so the row just sat there forever with
  // no indication anything went wrong. This is exactly the real production
  // bug fixed alongside this test: 015_scans_delete_policy.sql adds the
  // RLS delete policy that was missing entirely for the scans table.
  it("shows an error and keeps the row when onDelete rejects", async () => {
    const onDelete = vi.fn().mockRejectedValue(new Error("permission denied"));
    render(<ScanList scans={[scan({ id: "scan-42" })]} onDelete={onDelete} />);

    fireEvent.click(screen.getByTitle("Delete scan"));
    fireEvent.click(await screen.findByText("Confirm"));

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    expect(screen.getByText("https://example.com")).toBeInTheDocument();
  });

  it("clears a previous delete error once a retry succeeds", async () => {
    const onDelete = vi.fn().mockRejectedValueOnce(new Error("network error")).mockResolvedValueOnce(undefined);
    render(<ScanList scans={[scan({ id: "scan-42" })]} onDelete={onDelete} />);

    fireEvent.click(screen.getByTitle("Delete scan"));
    fireEvent.click(await screen.findByText("Confirm"));
    expect(await screen.findByText("network error")).toBeInTheDocument();

    fireEvent.click(screen.getByTitle("Delete scan"));
    fireEvent.click(await screen.findByText("Confirm"));

    await waitFor(() => expect(screen.queryByText("network error")).not.toBeInTheDocument());
  });

  it("renders each scan in its own row, independent of the others", () => {
    render(
      <ScanList
        scans={[
          scan({ id: "a", target_url: "https://a.example.com", status: "completed" }),
          scan({ id: "b", target_url: "https://b.example.com", status: "failed", score: null }),
        ]}
      />
    );
    const rows = screen.getAllByRole("row").slice(1); // drop the header row
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("https://a.example.com")).toBeInTheDocument();
    expect(within(rows[1]).getByText("https://b.example.com")).toBeInTheDocument();
  });
});
