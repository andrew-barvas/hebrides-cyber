import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import SlaDashboard from "./SlaDashboard";
import { DEFAULT_SLA_POLICY, buildSlaSummary, type LifecycleRow } from "@/lib/slaMonitoring";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();
const row = (id: string, severity: string, firstSeen: number, host = "shop.example", resolved: number | null = null): LifecycleRow => ({
  id, target_host: host, check_id: `c.${id}`, severity, title: `Finding ${id}`,
  first_seen_at: daysAgo(firstSeen), last_seen_at: daysAgo(0), resolved_at: resolved === null ? null : daysAgo(resolved),
});

function available(rows: LifecycleRow[]) {
  return ok({
    access: true,
    available: true,
    policy: DEFAULT_SLA_POLICY,
    resolvedWindowDays: 90,
    summary: { ...buildSlaSummary(rows, DEFAULT_SLA_POLICY), truncated: false },
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("SlaDashboard", () => {
  it("shows the upsell to accounts without Agency", async () => {
    fetchMock.mockResolvedValue(ok({ access: false, available: true, policy: DEFAULT_SLA_POLICY, summary: null }));
    render(<SlaDashboard token="tok" />);
    expect(await screen.findByText("Agency")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Compare plans" })).toBeInTheDocument();
  });

  it("explains when the database isn't ready yet", async () => {
    fetchMock.mockResolvedValue(ok({ access: true, available: false, policy: DEFAULT_SLA_POLICY, summary: null }));
    render(<SlaDashboard token="tok" />);
    expect(await screen.findByText("SLA tracking isn't switched on yet")).toBeInTheDocument();
  });

  it("lists open findings most urgent first, with plain-language status", async () => {
    fetchMock.mockResolvedValue(
      available([row("late", "critical", 20), row("soon", "high", 28, "blog.example"), row("fine", "low", 2), row("done", "high", 40, "shop.example", 30)])
    );
    render(<SlaDashboard token="tok" />);
    const table = await screen.findByRole("table", { name: "Open findings and their remediation deadlines" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((r) => within(r).getByText(/^Finding/).textContent)).toEqual(["Finding late", "Finding soon", "Finding fine"]);
    expect(within(rows[0]).getByText("5 days overdue")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Due in 2 days")).toBeInTheDocument();
    expect(within(rows[2]).getByText("178 days left")).toBeInTheDocument();
  });

  it("filters to breached findings", async () => {
    fetchMock.mockResolvedValue(available([row("late", "critical", 20), row("fine", "low", 2)]));
    render(<SlaDashboard token="tok" />);
    fireEvent.click(await screen.findByRole("button", { name: "Breached (1)" }));
    expect(screen.getByRole("button", { name: "Breached (1)" })).toHaveAttribute("aria-pressed", "true");
    const table = screen.getByRole("table", { name: /remediation deadlines/ });
    expect(within(table).queryByText("Finding fine")).not.toBeInTheDocument();
  });

  it("says so when nothing is open", async () => {
    fetchMock.mockResolvedValue(available([]));
    render(<SlaDashboard token="tok" />);
    expect(await screen.findByText("Nothing open against an SLA")).toBeInTheDocument();
  });

  it("saves new targets and reloads the deadlines", async () => {
    fetchMock.mockResolvedValueOnce(available([row("late", "critical", 20)]));
    fetchMock.mockResolvedValueOnce(ok({ policy: { ...DEFAULT_SLA_POLICY, days: { ...DEFAULT_SLA_POLICY.days, critical: 30 } } }));
    fetchMock.mockResolvedValueOnce(available([row("late", "critical", 20)]));
    render(<SlaDashboard token="tok" />);

    fireEvent.change(await screen.findByLabelText("Critical (days)"), { target: { value: "30" } });
    fireEvent.click(screen.getByLabelText(/Email me when a finding nears/));
    fireEvent.click(screen.getByRole("button", { name: "Save targets" }));

    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/account/sla");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toEqual({ days: { critical: 30, high: 30, medium: 90, low: 180 }, warnDays: 3, alertsEnabled: false });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
  });

  it("shows the server's error when saving fails", async () => {
    fetchMock.mockResolvedValueOnce(available([]));
    fetchMock.mockResolvedValueOnce({ ok: false, status: 400, json: async () => ({ error: "days.critical: must be at least 1 day" }) });
    render(<SlaDashboard token="tok" />);
    fireEvent.click(await screen.findByRole("button", { name: "Save targets" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("must be at least 1 day");
  });
});
