import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingCard, type ViewFinding } from "./ScanReportView";

function finding(overrides: Partial<ViewFinding> = {}): ViewFinding {
  return { severity: "medium", title: "HSTS header missing", detail: "detail", ...overrides };
}

describe("FindingCard corroboration note", () => {
  it("shows 'Also reported by' with each distinct tool once, using theme tokens", () => {
    render(
      <FindingCard
        finding={finding({
          corroboratedBy: [
            { tool: "nuclei", checkId: "nuclei.finding:a", title: "[Nuclei] a" },
            { tool: "ZAP", checkId: "zap.alert:b", title: "[ZAP] b" },
            { tool: "nuclei", checkId: "nuclei.finding:c", title: "[Nuclei] c" },
          ],
        })}
      />
    );
    const note = screen.getByTestId("corroborated-by");
    expect(note).toHaveTextContent("Also reported by nuclei, ZAP");
    expect(note).toHaveClass("text-cybermuted");
    expect(note.className).not.toMatch(/text-white/);
    expect(note).toHaveAttribute("title", "nuclei: [Nuclei] a\nZAP: [ZAP] b\nnuclei: [Nuclei] c");
  });

  it("renders no note without corroboration", () => {
    const { rerender } = render(<FindingCard finding={finding()} />);
    expect(screen.queryByTestId("corroborated-by")).not.toBeInTheDocument();
    rerender(<FindingCard finding={finding({ corroboratedBy: [] })} />);
    expect(screen.queryByTestId("corroborated-by")).not.toBeInTheDocument();
  });
});
