import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import FixWizard, { sortForWizard } from "./FixWizard";
import type { ViewFinding } from "./ScanReportView";

function finding(overrides: Partial<ViewFinding> = {}): ViewFinding {
  return { severity: "medium", title: "Test finding", detail: "", ...overrides };
}

describe("sortForWizard", () => {
  it("orders by fixDifficulty, easiest first", () => {
    const findings = [
      finding({ title: "hard", fixDifficulty: "hard" }),
      finding({ title: "trivial", fixDifficulty: "trivial" }),
      finding({ title: "moderate", fixDifficulty: "moderate" }),
      finding({ title: "easy", fixDifficulty: "easy" }),
    ];
    expect(sortForWizard(findings).map((f) => f.title)).toEqual(["trivial", "easy", "moderate", "hard"]);
  });

  it("breaks a tie in difficulty by severity, highest impact first", () => {
    const findings = [
      finding({ title: "low", severity: "low", fixDifficulty: "easy" }),
      finding({ title: "critical", severity: "critical", fixDifficulty: "easy" }),
      finding({ title: "medium", severity: "medium", fixDifficulty: "easy" }),
    ];
    expect(sortForWizard(findings).map((f) => f.title)).toEqual(["critical", "medium", "low"]);
  });

  it("sorts an unrated finding (no fixDifficulty) after every rated one", () => {
    const findings = [finding({ title: "unrated" }), finding({ title: "hard", fixDifficulty: "hard" })];
    expect(sortForWizard(findings).map((f) => f.title)).toEqual(["hard", "unrated"]);
  });

  it("does not mutate the input array", () => {
    const findings = [finding({ fixDifficulty: "hard" }), finding({ fixDifficulty: "trivial" })];
    const copy = [...findings];
    sortForWizard(findings);
    expect(findings).toEqual(copy);
  });
});

describe("FixWizard", () => {
  it("shows a message and an exit link when there are no open findings", () => {
    const onClose = vi.fn();
    render(<FixWizard findings={[finding({ status: "fixed" })]} onClose={onClose} />);
    expect(screen.getByText(/No open findings/)).toBeInTheDocument();
    fireEvent.click(screen.getByText(/Back to full report/));
    expect(onClose).toHaveBeenCalled();
  });

  it("shows step 1 of N and the first (easiest) finding", () => {
    render(
      <FixWizard
        findings={[finding({ title: "Hard one", fixDifficulty: "hard" }), finding({ title: "Easy one", fixDifficulty: "trivial" })]}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText("Step 1 of 2 — ordered easiest to fix first.")).toBeInTheDocument();
    expect(screen.getByText("Easy one")).toBeInTheDocument();
  });

  it("advances to the next finding when Next is clicked, and disables Previous at the start", () => {
    render(
      <FixWizard
        findings={[finding({ title: "Easy one", fixDifficulty: "trivial" }), finding({ title: "Hard one", fixDifficulty: "hard" })]}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText("← Previous")).toBeDisabled();
    fireEvent.click(screen.getByText("Next →"));
    expect(screen.getByText("Hard one")).toBeInTheDocument();
    expect(screen.getByText("Next →")).toBeDisabled();
  });

  it("excludes fixed findings from the wizard's step count", () => {
    render(
      <FixWizard
        findings={[finding({ title: "Open one", fixDifficulty: "easy" }), finding({ title: "Fixed one", status: "fixed" })]}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText("Step 1 of 1 — ordered easiest to fix first.")).toBeInTheDocument();
  });

  it("calls onClose when Exit wizard is clicked", () => {
    const onClose = vi.fn();
    render(<FixWizard findings={[finding({ fixDifficulty: "easy" })]} onClose={onClose} />);
    fireEvent.click(screen.getByText("Exit wizard"));
    expect(onClose).toHaveBeenCalled();
  });
});
