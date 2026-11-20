import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ScorePlanner } from "./ScorePlanner";
import type { ViewFinding } from "./ScanReportView";

const vf = (checkId: string, severity: ViewFinding["severity"], extra: Partial<ViewFinding> = {}): ViewFinding => ({ checkId, severity, title: `Finding ${checkId}`, detail: "", ...extra });

// 100 - 30 - 15 - 7 = 48
const findings: ViewFinding[] = [
  vf("crit", "critical"),
  vf("high", "high"),
  vf("med", "medium"),
  vf("gone", "critical", { status: "fixed" }),
  vf("fp", "high", { triage: { state: "false_positive", reason: "x", expiresAt: null } as never }),
  vf("note", "info"),
];

describe("ScorePlanner", () => {
  it("lists only open, untriaged findings worth points, largest first", () => {
    render(<ScorePlanner findings={findings} score={48} />);
    const items = screen.getAllByRole("checkbox").map((c) => c.closest("label")?.textContent);
    expect(items).toEqual(["Finding crit+30", "Finding high+15", "Finding med+7"]);
  });

  it("projects the score as findings are ticked", () => {
    render(<ScorePlanner findings={findings} score={48} />);
    fireEvent.click(screen.getByRole("checkbox", { name: /Finding high/ }));
    expect(screen.getByText(/After 1 fix: 63 · Needs attention/)).toBeInTheDocument();
  });

  it("picks the fewest fixes for a target rating and says so", () => {
    render(<ScorePlanner findings={findings} score={48} />);
    fireEvent.click(screen.getByRole("button", { name: "Reach Good (75+)" }));
    expect(screen.getByRole("status")).toHaveTextContent("1 fix should take this site to Good.");
    expect(screen.getByRole("checkbox", { name: /Finding crit/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Finding high/ })).not.toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Reach Strong (90+)" }));
    expect(screen.getByRole("status")).toHaveTextContent("2 fixes should take this site to Strong.");
    expect(screen.getByRole("checkbox", { name: /Finding high/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Finding med/ })).not.toBeChecked();
  });

  it("says when a rating is out of reach because accepted findings still count", () => {
    // 100 - 30 (accepted) - 30 (accepted) - 7 = 33; only the medium is open.
    const accepted = { state: "accepted", reason: "x", expiresAt: null } as never;
    render(<ScorePlanner findings={[vf("a1", "critical", { triage: accepted }), vf("a2", "critical", { triage: accepted }), vf("med", "medium")]} score={33} />);
    fireEvent.click(screen.getByRole("button", { name: "Reach Good (75+)" }));
    expect(screen.getByRole("status")).toHaveTextContent("Fixing every open finding gets to about 40, short of Good: accepted and snoozed findings still count.");
  });

  it("offers only ratings above the current score, and renders nothing with no candidates", () => {
    const { container, rerender } = render(<ScorePlanner findings={findings} score={80} />);
    expect(screen.queryByRole("button", { name: /Reach Good/ })).toBeNull();
    expect(screen.getByRole("button", { name: /Reach Strong/ })).toBeInTheDocument();
    rerender(<ScorePlanner findings={[vf("note", "info")]} score={100} />);
    expect(container).toBeEmptyDOMElement();
  });
});
