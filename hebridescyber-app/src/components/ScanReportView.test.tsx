import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { FindingCard, groupRefsByFramework, sortFindingsBySeverity, type ViewFinding } from "./ScanReportView";
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

describe("FindingCard — RetestFindingButton (E-30)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    document.querySelector("details")?.setAttribute("open", "");
  });

  const retestable = finding({ checkId: "headers.missing", remediation: "Add the header." });

  it("renders 'Recheck now' when scanId/token are present and the finding is retestable", () => {
    render(<FindingCard finding={retestable} scanId="scan-1" token="tok" />);
    document.querySelector("details")!.setAttribute("open", "");
    expect(screen.getByText("🔁 Recheck now")).toBeInTheDocument();
  });

  it("does not render at all without scanId/token, even for a retestable finding", () => {
    render(<FindingCard finding={retestable} />);
    expect(screen.queryByText("🔁 Recheck now")).not.toBeInTheDocument();
  });

  it("does not render for an extended-tool finding even when scanId/token are present", () => {
    const extendedFinding = finding({ checkId: "sqlmap.sqli:id", remediation: "Parameterise the query." });
    render(<FindingCard finding={extendedFinding} scanId="scan-1" token="tok" />);
    document.querySelector("details")!.setAttribute("open", "");
    expect(screen.queryByText("🔁 Recheck now")).not.toBeInTheDocument();
  });

  it("reports 'Fixed' when the recheck scan completes and the checkId is gone", async () => {
    (fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ scanId: "new-scan-1", status: "queued" }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ status: "completed", findings: [], fixed_findings: [{ check_id: "headers.missing" }] }) });

    render(<FindingCard finding={retestable} scanId="scan-1" token="tok" />);
    document.querySelector("details")!.setAttribute("open", "");
    fireEvent.click(screen.getByText("🔁 Recheck now"));

    await waitFor(() => expect(screen.getByText(/Fixed — confirmed just now/)).toBeInTheDocument());

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/api/scans/scan-1/retest-finding",
      expect.objectContaining({ method: "POST", headers: expect.objectContaining({ Authorization: "Bearer tok" }) })
    );
    expect(fetch).toHaveBeenNthCalledWith(2, "/api/v1/scans/new-scan-1", expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer tok" }) }));
  });

  it("reports 'Still present' when the recheck scan completes and the checkId is still there", async () => {
    (fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ scanId: "new-scan-2", status: "queued" }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ status: "completed", findings: [{ check_id: "headers.missing" }], fixed_findings: [] }) });

    render(<FindingCard finding={retestable} scanId="scan-1" token="tok" />);
    document.querySelector("details")!.setAttribute("open", "");
    fireEvent.click(screen.getByText("🔁 Recheck now"));

    await waitFor(() => expect(screen.getByText(/Still present as of just now/)).toBeInTheDocument());
  });

  it("shows an error and offers a retry when starting the recheck fails", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ok: false, json: async () => ({ error: "Rate limit exceeded" }) });

    render(<FindingCard finding={retestable} scanId="scan-1" token="tok" />);
    document.querySelector("details")!.setAttribute("open", "");
    fireEvent.click(screen.getByText("🔁 Recheck now"));

    await waitFor(() => expect(screen.getByText("Rate limit exceeded")).toBeInTheDocument());
    expect(screen.getByText("Try again")).toBeInTheDocument();
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

  it("puts known-exploited, then likelier, findings first within a severity — never above a higher severity", () => {
    const input = [
      finding({ title: "plain", severity: "high" }),
      finding({ title: "epss-low", severity: "high", threatIntel: { knownExploited: false, epss: 0.02 } }),
      finding({ title: "kev", severity: "high", threatIntel: { knownExploited: true, epss: 0.01 } }),
      finding({ title: "epss-high", severity: "high", threatIntel: { knownExploited: false, epss: 0.6 } }),
      finding({ title: "critical", severity: "critical" }),
      finding({ title: "kev-medium", severity: "medium", threatIntel: { knownExploited: true } }),
    ];
    expect(sortFindingsBySeverity(input).map((f) => f.title)).toEqual(["critical", "kev", "epss-high", "epss-low", "plain", "kev-medium"]);
  });
});

describe("FindingCard threat intel", () => {
  it("flags a CISA KEV finding as actively exploited, naming the CVEs and ransomware use", () => {
    render(
      <FindingCard
        finding={finding({
          severity: "high",
          cveIds: ["CVE-2021-44228"],
          threatIntel: { knownExploited: true, kevCveIds: ["CVE-2021-44228"], ransomware: true, epss: 0.975, epssPercentile: 0.9999 },
        })}
      />
    );
    const kev = screen.getByText("Actively exploited · ransomware");
    expect(kev).toHaveAttribute("title", expect.stringContaining("CVE-2021-44228"));
    expect(screen.getByText("EPSS 98%")).toHaveAttribute("title", expect.stringContaining("higher than 99% of scored CVEs"));
  });

  it("shows EPSS alone for a CVE that isn't in KEV, and small probabilities honestly", () => {
    render(<FindingCard finding={finding({ threatIntel: { knownExploited: false, epss: 0.004 } })} />);
    expect(screen.queryByText(/Actively exploited/)).not.toBeInTheDocument();
    expect(screen.getByText("EPSS <1%")).toBeInTheDocument();
  });

  it("shows nothing when threat intel wasn't looked up", () => {
    render(<FindingCard finding={finding({ cveIds: ["CVE-2020-11022"] })} />);
    expect(screen.queryByText(/EPSS|Actively exploited/)).not.toBeInTheDocument();
  });
});

// Regression: one badge per control showed "CIS Controls v8" twice on a finding.
describe("groupRefsByFramework", () => {
  it("groups controls under one framework, keeping order and dropping repeats", () => {
    expect(
      groupRefsByFramework([
        { framework: "cis-controls-v8", control: "CIS 3" },
        { framework: "iso-27001", control: "A.12" },
        { framework: "cis-controls-v8", control: "CIS 16" },
        { framework: "cis-controls-v8", control: "CIS 3" },
      ])
    ).toEqual([
      ["cis-controls-v8", ["CIS 3", "CIS 16"]],
      ["iso-27001", ["A.12"]],
    ]);
  });
});
