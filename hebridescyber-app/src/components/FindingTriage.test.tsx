import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ExecutiveSummary, FindingCard, TriagedFindings, buildFindingsView, type ViewFinding } from "./ScanReportView";
import { describeTriage, formatTriageDate, triagePayloadFor, type ViewTriage } from "./FindingTriage";

const SCAN = "11111111-2222-4333-8444-555555555555";
const finding = (overrides: Partial<ViewFinding> = {}): ViewFinding => ({
  severity: "high", title: "No CSP", detail: "d", checkId: "headers.csp-absent", ...overrides,
});
const triage = (overrides: Partial<ViewTriage> = {}): ViewTriage => ({
  state: "accepted_risk", reason: "WAF in front", expiresAt: null, triagedAt: "2026-09-21T10:00:00Z", triagedByEmail: "sam@shop.example", ...overrides,
});

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("triagePayloadFor / describeTriage", () => {
  it("turns a snooze preset into an expiry that many days out", () => {
    const now = new Date("2026-10-01T00:00:00Z");
    expect(triagePayloadFor("snooze-30", now)).toEqual({ state: "snoozed", expiresAt: "2026-10-31T00:00:00.000Z" });
    expect(triagePayloadFor("false_positive", now)).toEqual({ state: "false_positive", expiresAt: null });
  });

  it("reads sensibly for an authorised third-party script too", () => {
    // Dates via formatTriageDate: ICU versions disagree on "Sep" vs "Sept".
    const on = formatTriageDate("2026-09-21T10:00:00Z");
    expect(describeTriage(triage())).toBe(`Accepted / authorised by sam@shop.example on ${on} · no expiry`);
    expect(describeTriage(triage({ state: "snoozed", expiresAt: "2026-10-21T00:00:00Z", triagedByEmail: null }))).toBe(
      `Snoozed on ${on} · until ${formatTriageDate("2026-10-21T00:00:00Z")}`
    );
  });
});

describe("FindingCard Mark as…", () => {
  it("only offers it on the owner's dashboard, with triage available", () => {
    const { rerender } = render(<FindingCard finding={finding()} />);
    expect(screen.queryByRole("button", { name: "Mark as…" })).not.toBeInTheDocument();
    rerender(<FindingCard finding={finding()} scanId={SCAN} token="t" />);
    expect(screen.queryByRole("button", { name: "Mark as…" })).not.toBeInTheDocument();
    rerender(<FindingCard finding={finding()} scanId={SCAN} token="t" onTriaged={() => {}} />);
    expect(screen.getByRole("button", { name: "Mark as…" })).toBeInTheDocument();
  });

  it("requires a reason, then saves the chosen decision for this finding", async () => {
    const onTriaged = vi.fn();
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({
        item: { targetHost: "shop.example", checkId: "headers.csp-absent", state: "snoozed", reason: "Next sprint", expiresAt: "2026-10-08T00:00:00Z",
          active: true, triagedAt: "2026-10-01T00:00:00Z", createdAt: "2026-10-01T00:00:00Z", triagedBy: "o1", triagedByEmail: "sam@shop.example" },
      }),
    });
    render(<FindingCard finding={finding()} scanId={SCAN} token="tok" onTriaged={onTriaged} />);
    fireEvent.click(screen.getByRole("button", { name: "Mark as…" }));
    fireEvent.click(screen.getByRole("button", { name: "Snooze 7 days" }));

    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "  Next sprint  " } });
    expect(save).toBeEnabled();
    fireEvent.click(save);

    await waitFor(() => expect(onTriaged).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/findings/triage");
    expect(init.method).toBe("PUT");
    expect(init.headers.Authorization).toBe("Bearer tok");
    const body = JSON.parse(init.body);
    expect(body).toMatchObject({ scanId: SCAN, checkId: "headers.csp-absent", state: "snoozed", reason: "Next sprint" });
    expect(Date.parse(body.expiresAt) - Date.now()).toBeGreaterThan(6.9 * 86_400_000);
    expect(onTriaged).toHaveBeenCalledWith("headers.csp-absent", expect.objectContaining({ state: "snoozed", triagedByEmail: "sam@shop.example" }));
  });

  it("shows the API's error and keeps the form open", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 503, json: async () => ({ error: "migration 046 pending" }) });
    render(<FindingCard finding={finding()} scanId={SCAN} token="tok" onTriaged={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Mark as…" }));
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "Because" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("migration 046 pending");
  });
});

describe("TriagedFindings", () => {
  it("lists triaged findings collapsed, with state, reason, who/when and Undo", async () => {
    const onTriaged = vi.fn();
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ deleted: 1 }) });
    render(
      <TriagedFindings
        findings={[finding({ triage: triage() }), finding({ checkId: "x", title: "Untriaged" })]}
        scanId={SCAN}
        token="tok"
        onTriaged={onTriaged}
      />
    );
    expect(screen.getByText("Triaged (1)")).toBeInTheDocument();
    expect(document.querySelector("details")).not.toHaveAttribute("open");
    expect(screen.getByText("Accepted / authorised")).toBeInTheDocument();
    expect(screen.getByText("WAF in front")).toBeInTheDocument();
    expect(screen.queryByText("Untriaged")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(onTriaged).toHaveBeenCalledWith("headers.csp-absent", null));
    expect(fetchMock.mock.calls[0][1].method).toBe("DELETE");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ scanId: SCAN, checkId: "headers.csp-absent" });
  });

  it("renders nothing when nothing is triaged", () => {
    const { container } = render(<TriagedFindings findings={[finding()]} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ExecutiveSummary and buildFindingsView with triage", () => {
  it("attaches triage by checkId", () => {
    const view = buildFindingsView([finding(), finding({ checkId: "b" })], null, "all", new Map([["b", triage()]]));
    expect(view.map((f) => f.triage?.state ?? null)).toEqual([null, "accepted_risk"]);
  });

  it("excludes triaged findings from the counts and labels them separately", () => {
    render(
      <ExecutiveSummary
        score={70}
        findings={[finding({ severity: "critical", triage: triage({ state: "false_positive" }) }), finding({ checkId: "b" })]}
      />
    );
    expect(screen.getByText("+1 triaged")).toBeInTheDocument();
    expect(screen.getByText(/1 triaged finding \(accepted, false positive or snoozed\) isn’t counted above/)).toBeInTheDocument();
    // One open (the high), and the triaged critical isn't a top priority.
    expect(screen.getByText("Open findings").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Critical + High").previousSibling).toHaveTextContent("1");
  });
});
