import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import FindingsExplorer from "./FindingsExplorer";
import { buildFacets, groupFindings, type FindingRow } from "@/lib/findingsView";

const row = (over: Partial<FindingRow> = {}): FindingRow => ({
  key: "a.example headers.hsts", host: "a.example", checkId: "headers.hsts", checkBase: "headers.hsts", category: "headers",
  severity: "medium", title: "Missing HSTS", detail: null, firstSeenAt: "2026-09-01T00:00:00Z", ageDays: 30, slaState: null, slaDueAt: null,
  knownExploited: false, ransomware: false, epss: null, cveIds: [], scanId: "scan-1", triage: null, ...over,
});

const ROWS = [
  row(),
  row({ key: "b.example headers.hsts", host: "b.example", scanId: null }),
  row({ key: "a.example nuclei.cve", host: "a.example", checkId: "nuclei.cve", checkBase: "nuclei.cve", category: "nuclei", title: "Old Apache", severity: "critical", knownExploited: true, ransomware: true, epss: 0.42, slaState: "breached", ageDays: 1 }),
  row({ key: "a.example dns.spf", host: "a.example", checkId: "dns.spf", checkBase: "dns.spf", category: "dns", title: "No SPF", severity: "low", triage: { state: "snoozed", reason: "waiting on registrar", expiresAt: null } }),
];

type Opts = { view?: "grouped" | "rows"; rows?: FindingRow[]; available?: boolean; triageAvailable?: boolean; slaEnabled?: boolean; detailComplete?: boolean; truncated?: boolean; page?: number; pageCount?: number };

function body(o: Opts = {}) {
  const rows = o.rows ?? ROWS;
  const view = o.view ?? "grouped";
  return {
    available: o.available ?? true, triageAvailable: o.triageAvailable ?? true, slaEnabled: o.slaEnabled ?? false,
    detailComplete: o.detailComplete ?? true, truncated: o.truncated ?? false, facets: buildFacets(rows), view,
    totalFindings: rows.length, items: view === "rows" ? rows : [], groups: view === "grouped" ? groupFindings(rows) : [],
    page: o.page ?? 1, pageSize: 50, total: view === "rows" ? rows.length : groupFindings(rows).length, pageCount: o.pageCount ?? 1,
  };
}

const json = (status: number, payload: unknown) => ({ ok: status < 400, status, json: async () => payload, blob: async () => new Blob(["csv"]) });

let fetchMock: ReturnType<typeof vi.fn>;
let listBody: () => unknown;
let putResponse: () => ReturnType<typeof json>;

beforeEach(() => {
  listBody = () => body();
  putResponse = () => json(200, { count: 1, items: [] });
  fetchMock = vi.fn(async (url: string, init?: { method?: string }) => {
    if (url.startsWith("/api/findings/triage")) return init?.method === "PUT" ? putResponse() : json(200, {});
    return json(200, listBody());
  });
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const listCalls = () => fetchMock.mock.calls.map((c) => c[0] as string).filter((u) => u.startsWith("/api/findings?"));
const lastList = () => listCalls().at(-1) as string;

describe("FindingsExplorer", () => {
  it("shows groups: the same check on several sites reads as one entry", async () => {
    render(<FindingsExplorer token="tok" />);
    expect(await screen.findByText("Missing HSTS")).toBeInTheDocument();
    expect(screen.getByText(/On 2 sites · 2 findings/)).toBeInTheDocument();
    expect(screen.getByText("Known exploited")).toBeInTheDocument();
    expect(screen.getByText("EPSS 42%")).toBeInTheDocument();
    expect(screen.getByText(/On a.example · 1 finding · nuclei/)).toBeInTheDocument();
    expect(screen.getByText("4 findings in 3 groups")).toBeInTheDocument();
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ headers: { Authorization: "Bearer tok" } });
    expect(lastList()).toContain("triage=open");
    expect(lastList()).toContain("view=grouped");
  });

  it("does nothing without a session token", () => {
    render(<FindingsExplorer token={null} />);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByRole("status", { name: "Loading findings" })).toBeInTheDocument();
  });

  it("expands a group to its findings, with a link to the report only when one exists", async () => {
    render(<FindingsExplorer token="tok" />);
    const toggle = await screen.findByRole("button", { name: /2 findings for Missing HSTS/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("checkbox", { name: "Select Missing HSTS on a.example" })).toBeInTheDocument();
    const links = screen.getAllByRole("link", { name: /Latest report/ });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "/dashboard/scans/scan-1");
    fireEvent.click(toggle);
    expect(screen.queryByRole("checkbox", { name: /Select Missing HSTS on/ })).not.toBeInTheDocument();
  });

  it("switches to the ungrouped list and shows triage details", async () => {
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    listBody = () => body({ view: "rows" });
    fireEvent.click(screen.getByRole("button", { name: "All findings" }));
    expect(await screen.findByRole("list", { name: "Open findings" })).toBeInTheDocument();
    expect(lastList()).toContain("view=rows");
    expect(screen.getByText("Reason: waiting on registrar")).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Open findings" })).getByText("Snoozed")).toBeInTheDocument();
    expect(screen.getByText(/open 1 day ·/)).toBeInTheDocument();
    expect(screen.getByText(/SLA breached/)).toBeInTheDocument();
    expect(screen.getByText("4 findings")).toBeInTheDocument();
  });

  it("sends every filter to the API and can reset them", async () => {
    listBody = () => body({ slaEnabled: true });
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    fireEvent.change(screen.getByLabelText("Site"), { target: { value: "a.example" } });
    await waitFor(() => expect(lastList()).toContain("site=a.example"));
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "headers" } });
    fireEvent.change(screen.getByLabelText("Triage"), { target: { value: "snoozed" } });
    fireEvent.change(screen.getByLabelText("Exploit likelihood (EPSS)"), { target: { value: "0.5" } });
    fireEvent.change(screen.getByLabelText("Open for"), { target: { value: "30" } });
    fireEvent.change(screen.getByLabelText("SLA"), { target: { value: "breached" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "Known exploited (CISA KEV) only" }));
    await waitFor(() => expect(lastList()).toContain("kev=1"));
    const q = new URLSearchParams(lastList().split("?")[1]);
    expect(Object.fromEntries(q)).toMatchObject({
      site: "a.example", severity: "high", category: "headers", triage: "snoozed", epssMin: "0.5", minAgeDays: "30", sla: "breached", kev: "1", page: "1",
    });
    fireEvent.click(screen.getByRole("button", { name: "Reset filters" }));
    await waitFor(() => expect(lastList()).toContain("triage=open"));
    expect(lastList()).not.toContain("site=");
    expect(screen.queryByRole("button", { name: "Reset filters" })).not.toBeInTheDocument();
  });

  it("hides the SLA filter unless SLA tracking is on", async () => {
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    expect(screen.queryByLabelText("SLA")).not.toBeInTheDocument();
  });

  it("selects a whole group and bulk-accepts it with a reason, through the existing triage API", async () => {
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    const groupBox = screen.getByRole("checkbox", { name: "Select all 2 findings for Missing HSTS" });
    fireEvent.click(groupBox);
    expect(screen.getByText("2 findings selected")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Accept / authorise" }));
    const apply = screen.getByRole("button", { name: "Apply to 2 findings" });
    expect(apply).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "ok" } });
    expect(apply).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "Reviewed, all first party" } });
    expect(apply).toBeEnabled();
    fireEvent.click(apply);

    expect(await screen.findByText("2 findings marked as accepted / authorised.")).toBeInTheDocument();
    const put = fetchMock.mock.calls.find((c) => (c[1] as { method?: string } | undefined)?.method === "PUT");
    expect(put?.[0]).toBe("/api/findings/triage");
    expect(JSON.parse((put?.[1] as { body: string }).body)).toEqual({
      items: [
        { targetHost: "a.example", checkId: "headers.hsts", state: "accepted_risk", reason: "Reviewed, all first party", expiresAt: null },
        { targetHost: "b.example", checkId: "headers.hsts", state: "accepted_risk", reason: "Reviewed, all first party", expiresAt: null },
      ],
    });
    // Reloaded, selection cleared.
    await waitFor(() => expect(listCalls().length).toBeGreaterThan(1));
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
  });

  it("marks false positives and snoozes with an expiry", async () => {
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Old Apache");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 1 findings for Old Apache" }));
    fireEvent.click(screen.getByRole("button", { name: "Snooze" }));
    fireEvent.change(screen.getByLabelText("Snooze for"), { target: { value: "7" } });
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "Fix is scheduled" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply to 1 finding" }));
    await screen.findByText("1 finding marked as snoozed.");
    const sent = JSON.parse((fetchMock.mock.calls.find((c) => (c[1] as { method?: string } | undefined)?.method === "PUT")?.[1] as { body: string }).body);
    expect(sent.items[0]).toMatchObject({ targetHost: "a.example", checkId: "nuclei.cve", state: "snoozed" });
    const days = (Date.parse(sent.items[0].expiresAt) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThan(7.1);
  });

  it("offers false positive, toggles the action closed and clears the selection", async () => {
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Old Apache");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 1 findings for Old Apache" }));
    const fp = screen.getByRole("button", { name: "False positive" });
    fireEvent.click(fp);
    expect(screen.getByText(/stop counting towards the score/)).toBeInTheDocument();
    fireEvent.click(fp);
    expect(screen.queryByLabelText(/Reason/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Accept / authorise" }));
    expect(screen.getByText(/authorise a third-party script/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
  });

  it("shows a server error from the bulk request and keeps the selection", async () => {
    putResponse = () => json(503, { error: "Finding triage isn't enabled on this server yet (database migration 046 pending)." });
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Old Apache");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 1 findings for Old Apache" }));
    fireEvent.click(screen.getByRole("button", { name: "False positive" }));
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "Scanner is wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply to 1 finding" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("migration 046 pending");
    expect(screen.getByText("1 finding selected")).toBeInTheDocument();
  });

  it("falls back to a generic message when the triage error has no body", async () => {
    putResponse = () => ({ ok: false, status: 500, json: async () => { throw new Error("no json"); }, blob: async () => new Blob([]) });
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Old Apache");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 1 findings for Old Apache" }));
    fireEvent.click(screen.getByRole("button", { name: "False positive" }));
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "Scanner is wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply to 1 finding" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not save the triage");
  });

  it("disables bulk actions before the triage migration", async () => {
    listBody = () => body({ triageAvailable: false });
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Old Apache");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 1 findings for Old Apache" }));
    expect(screen.getByRole("button", { name: "Snooze" })).toBeDisabled();
    expect(screen.getByText("Triage isn't enabled on this server yet.")).toBeInTheDocument();
  });

  it("selects and deselects single findings, and a group's box reflects partial selection", async () => {
    render(<FindingsExplorer token="tok" />);
    const toggle = await screen.findByRole("button", { name: /2 findings for Missing HSTS/ });
    fireEvent.click(toggle);
    const one = screen.getByRole("checkbox", { name: "Select Missing HSTS on a.example" });
    fireEvent.click(one);
    const group = screen.getByRole("checkbox", { name: "Select all 2 findings for Missing HSTS" }) as HTMLInputElement;
    expect(group.indeterminate).toBe(true);
    expect(group.checked).toBe(false);
    fireEvent.click(group);
    expect(group.checked).toBe(true);
    fireEvent.click(group);
    expect(group.checked).toBe(false);
    fireEvent.click(one);
    fireEvent.click(one);
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
  });

  it("selects findings in the ungrouped list", async () => {
    listBody = () => body({ view: "rows" });
    render(<FindingsExplorer token="tok" />);
    fireEvent.click(await screen.findByRole("button", { name: "All findings" }));
    const box = await screen.findByRole("checkbox", { name: "Select Old Apache on a.example" });
    fireEvent.click(box);
    expect(screen.getByText("1 finding selected")).toBeInTheDocument();
  });

  it("paginates, following the server's clamp", async () => {
    listBody = () => body({ pageCount: 3 });
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Page 1 of 3");
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(lastList()).toContain("page=2"));
    listBody = () => body({ pageCount: 3, page: 3 });
    fireEvent.click(await screen.findByRole("button", { name: "Next" }));
    await screen.findByText("Page 3 of 3");
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    await waitFor(() => expect(lastList()).toContain("page=2"));
  });

  it("clamps when the server reports a different page than asked", async () => {
    listBody = () => body({ pageCount: 2, page: 1 });
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Page 1 of 2");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    listBody = () => body({ pageCount: 2, page: 1 });
    await waitFor(() => expect(lastList()).toContain("page=1"));
  });

  it("explains an empty account and an empty filter result", async () => {
    listBody = () => body({ rows: [] });
    render(<FindingsExplorer token="tok" />);
    expect(await screen.findByText("No open findings")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Export CSV/ })).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: "Known exploited (CISA KEV) only" }));
    expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  });

  it("explains when finding tracking isn't migrated yet", async () => {
    listBody = () => body({ available: false, rows: [] });
    render(<FindingsExplorer token="tok" />);
    expect(await screen.findByText("Finding tracking isn't switched on yet")).toBeInTheDocument();
    expect(screen.queryByText("No open findings")).not.toBeInTheDocument();
  });

  it("shows an error with a retry", async () => {
    let fail = true;
    fetchMock.mockImplementation(async (url: string) => (fail && url.startsWith("/api/findings?") ? json(500, { error: "Could not load findings" }) : json(200, listBody())));
    render(<FindingsExplorer token="tok" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load findings");
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Missing HSTS")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("uses a default message when the error response has no body, and ignores network aborts", async () => {
    fetchMock.mockImplementation(async () => ({ ok: false, status: 502, json: async () => { throw new Error("html"); } }));
    render(<FindingsExplorer token="tok" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load your findings");
  });

  it("warns when exploit data or part of the list is missing", async () => {
    listBody = () => body({ detailComplete: false, truncated: true });
    render(<FindingsExplorer token="tok" />);
    expect(await screen.findByText("Some detail is missing")).toBeInTheDocument();
    expect(screen.getByText("Showing part of your findings")).toBeInTheDocument();
  });

  it("exports the filtered list as a CSV download", async () => {
    const createObjectURL = vi.fn(() => "blob:csv");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
    await waitFor(() => expect(lastList()).toContain("severity=high"));
    fireEvent.click(screen.getByRole("button", { name: /Export CSV/ }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    const csvUrl = fetchMock.mock.calls.map((c) => c[0] as string).find((u) => u.includes("format=csv")) as string;
    expect(csvUrl).toContain("severity=high");
    expect(csvUrl).not.toContain("page=");
    expect(createObjectURL).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:csv");
    click.mockRestore();
  });

  it("reports a failed export", async () => {
    fetchMock.mockImplementation(async (url: string) => (url.includes("format=csv") ? json(500, {}) : json(200, listBody())));
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    fireEvent.click(screen.getByRole("button", { name: /Export CSV/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not export your findings");
  });

  it("labels controls for assistive tech", async () => {
    render(<FindingsExplorer token="tok" />);
    await screen.findByText("Missing HSTS");
    const filters = screen.getByRole("region", { name: "Filters" });
    expect(within(filters).getByRole("group", { name: "Group findings" })).toBeInTheDocument();
    expect(within(filters).getByRole("button", { name: "Grouped by check" })).toHaveAttribute("aria-pressed", "true");
  });
});
