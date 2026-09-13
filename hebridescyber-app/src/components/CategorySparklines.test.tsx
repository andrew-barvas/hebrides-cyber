import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import CategorySparklines from "./CategorySparklines";
import type { CategoryCountPoint } from "@/lib/clientScanHistory";

describe("CategorySparklines", () => {
  it("shows a message rather than an empty chart with fewer than 2 history points", () => {
    render(<CategorySparklines history={[{ date: "2026-01-01", counts: { tls: 2 } }]} />);
    expect(screen.getByText(/Not enough scan history yet/)).toBeInTheDocument();
  });

  it("shows a message when there are no open findings across the whole history", () => {
    const history: CategoryCountPoint[] = [
      { date: "2026-01-01", counts: {} },
      { date: "2026-02-01", counts: {} },
    ];
    render(<CategorySparklines history={history} />);
    expect(screen.getByText(/nothing to break down by category/)).toBeInTheDocument();
  });

  it("renders one sparkline per category, with a human-readable label", () => {
    const history: CategoryCountPoint[] = [
      { date: "2026-01-01", counts: { tls: 2, headers: 1 } },
      { date: "2026-02-01", counts: { tls: 1, headers: 1 } },
    ];
    render(<CategorySparklines history={history} />);
    expect(screen.getByText("TLS")).toBeInTheDocument();
    expect(screen.getByText("Headers")).toBeInTheDocument();
  });

  it("orders categories by total count across the whole history, highest first", () => {
    const history: CategoryCountPoint[] = [
      { date: "2026-01-01", counts: { headers: 1, tls: 5 } },
      { date: "2026-02-01", counts: { headers: 1, tls: 5 } },
    ];
    render(<CategorySparklines history={history} />);
    const labels = screen.getAllByText(/TLS|Headers/).map((el) => el.textContent);
    expect(labels[0]).toBe("TLS");
  });

  it("shows a down arrow when a category's latest count is lower than its first", () => {
    const history: CategoryCountPoint[] = [
      { date: "2026-01-01", counts: { tls: 5 } },
      { date: "2026-02-01", counts: { tls: 2 } },
    ];
    render(<CategorySparklines history={history} />);
    expect(screen.getByText("▼")).toBeInTheDocument();
  });

  it("shows an up arrow when a category's latest count is higher than its first", () => {
    const history: CategoryCountPoint[] = [
      { date: "2026-01-01", counts: { tls: 1 } },
      { date: "2026-02-01", counts: { tls: 4 } },
    ];
    render(<CategorySparklines history={history} />);
    expect(screen.getByText("▲")).toBeInTheDocument();
  });

  it("caps the number of rendered categories at 8, keeping the highest-total ones", () => {
    const counts: Record<string, number> = {};
    for (let i = 0; i < 12; i++) counts[`category-${i}`] = 12 - i; // category-0 highest, category-11 lowest
    const history: CategoryCountPoint[] = [
      { date: "2026-01-01", counts },
      { date: "2026-02-01", counts },
    ];
    render(<CategorySparklines history={history} />);
    expect(screen.getByText("Category 0")).toBeInTheDocument();
    expect(screen.queryByText("Category 11")).not.toBeInTheDocument();
  });
});
