import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingCard, sortFindingsBySeverity, type ViewFinding } from "./ScanReportView";
import { sriRemediation, DKIM_NOT_DETECTED, SPF_MISSING } from "@/lib/scanners/remediationText";

function finding(overrides: Partial<ViewFinding> = {}): ViewFinding {
  return {
    severity: "medium",
    title: "Test finding",
    detail: "Test detail",
    ...overrides,
  };
}

describe("FindingCard", () => {
  it("renders severity label, title, and detail", () => {
    render(<FindingCard finding={finding({ severity: "critical", title: "SQL injection", detail: "param id" })} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText("param id")).toBeInTheDocument();
  });

  it("renders a resolved (fixed) finding as struck-through, without severity chrome", () => {
    render(<FindingCard finding={finding({ title: "Old issue", status: "fixed" })} />);
    expect(screen.getByText("✓")).toBeInTheDocument();
    expect(screen.getByText("Old issue")).toHaveClass("line-through");
    expect(screen.queryByText("How to fix")).not.toBeInTheDocument();
  });

  it("shows a NEW badge for a finding with status 'new'", () => {
    render(<FindingCard finding={finding({ status: "new" })} />);
    expect(screen.getByText("NEW")).toBeInTheDocument();
  });

  it("does not render a 'How to fix' disclosure when there is no remediation text", () => {
    render(<FindingCard finding={finding({ remediation: undefined })} />);
    expect(screen.queryByText(/How to fix/i)).not.toBeInTheDocument();
  });

  it("renders CVE badges linking to NVD when present", () => {
    render(<FindingCard finding={finding({ cveIds: ["CVE-2024-1234"] })} />);
    const link = screen.getByRole("link", { name: /CVE-2024-1234/ });
    expect(link).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2024-1234");
  });

  it("renders the full multi-code-block remediation body for a real sriRemediation() finding", () => {
    const url = "https://fonts.googleapis.com/css2?family=Roboto:wght@300&display=swap";
    render(<FindingCard finding={finding({ remediation: sriRemediation("stylesheet", url) })} />);
    document.querySelector("details")!.setAttribute("open", "");

    expect(screen.getByText(/Add a Subresource Integrity hash/)).toBeInTheDocument();
    // Both fenced code blocks (the openssl command and the <link> snippet)
    // must render as real <pre><code> content, not be swallowed.
    const blocks = document.querySelectorAll("pre code");
    expect(blocks).toHaveLength(2);
    expect(blocks[0].textContent).toContain("openssl dgst -sha384");
    expect(blocks[1].textContent).toContain('integrity="sha384-<hash from above>"');
  });

  // Regression test: DKIM_NOT_DETECTED and SPF_MISSING (src/lib/scanners/
  // remediationText.ts) both embed a GFM pipe table. RemediationBody's
  // parser only understood fenced code / bullet lists / paragraphs, so a
  // table fell through to the paragraph branch and rendered as one garbled
  // run-on line of "|" characters instead of a real table.
  it("renders a markdown table in remediation text as a real <table>, not garbled inline text", () => {
    render(<FindingCard finding={finding({ severity: "info", remediation: DKIM_NOT_DETECTED })} />);
    document.querySelector("details")!.setAttribute("open", "");

    const table = document.querySelector("table");
    expect(table).not.toBeNull();
    expect(screen.getByRole("columnheader", { name: "Provider" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Where" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "Google Workspace" })).toBeInTheDocument();

    // The raw "|---|---|" separator line must never itself appear as
    // rendered text — that would mean the table detection missed it.
    expect(document.body.textContent).not.toMatch(/\|-+\|/);
  });

  it("renders SPF_MISSING's provider table the same way", () => {
    render(<FindingCard finding={finding({ severity: "high", remediation: SPF_MISSING })} />);
    document.querySelector("details")!.setAttribute("open", "");

    expect(document.querySelector("table")).not.toBeNull();
    expect(screen.getByRole("cell", { name: "Google" })).toBeInTheDocument();
  });

  it("renders bullet-list remediation text as a real <ul>, unaffected by the table-detection change", () => {
    render(
      <FindingCard
        finding={finding({
          remediation: "Fix this:\n\n- First step\n- Second step\n- Third step",
        })}
      />
    );
    document.querySelector("details")!.setAttribute("open", "");

    const items = screen.getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual(["First step", "Second step", "Third step"]);
  });
});

describe("sortFindingsBySeverity", () => {
  it("orders critical > high > medium > low > info", () => {
    const input = [
      finding({ title: "info", severity: "info" }),
      finding({ title: "critical", severity: "critical" }),
      finding({ title: "low", severity: "low" }),
      finding({ title: "high", severity: "high" }),
      finding({ title: "medium", severity: "medium" }),
    ];
    const sorted = sortFindingsBySeverity(input);
    expect(sorted.map((f) => f.title)).toEqual(["critical", "high", "medium", "low", "info"]);
  });

  it("does not mutate the input array", () => {
    const input = [finding({ severity: "low" }), finding({ severity: "critical" })];
    const copy = [...input];
    sortFindingsBySeverity(input);
    expect(input).toEqual(copy);
  });
});
