import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const { session, state } = vi.hoisted(() => ({
  session: { currentClientId: "all" as string, clients: [] as { id: string; name: string }[] },
  state: { targets: [] as { id: string; target_url: string; client_id?: string | null }[], selects: [] as string[] },
}));

vi.mock("@/components/app-shell/AppShell", () => ({ useAppSession: () => session }));
vi.mock("@/components/ScoreTrend", () => ({ default: () => <div /> }));
vi.mock("@/components/CategorySparklines", () => ({ default: () => <div /> }));
vi.mock("@/lib/clientScanHistory", () => ({
  findFullScoreHistoryClient: vi.fn().mockResolvedValue([]),
  findCategoryHistoryClient: vi.fn().mockResolvedValue([]),
}));
vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: () => {
      const b: Record<string, unknown> = {};
      b.select = (cols: string) => (state.selects.push(cols), b);
      b.order = () => Promise.resolve({ data: state.targets });
      return b;
    },
  },
}));

import ScoreHistoryPage from "./page";

beforeEach(() => {
  session.currentClientId = "all";
  session.clients = [];
  state.selects = [];
  state.targets = [
    { id: "t1", target_url: "https://a.test", client_id: "c1" },
    { id: "t2", target_url: "https://b.test", client_id: "c2" },
    { id: "t3", target_url: "https://c.test", client_id: null },
  ];
});

const options = () => screen.getAllByRole("option").map((o) => o.textContent);

describe("Trends page — client scope", () => {
  it("offers every site without clients and does not select client_id", async () => {
    render(<ScoreHistoryPage />);
    await waitFor(() => expect(options()).toHaveLength(3));
    expect(state.selects).toEqual(["id, target_url"]);
  });

  it("offers only the selected client's sites", async () => {
    session.clients = [{ id: "c1", name: "Acme" }, { id: "c2", name: "Beta" }];
    session.currentClientId = "c2";
    render(<ScoreHistoryPage />);
    await waitFor(() => expect(options()).toEqual(["https://b.test"]));
    expect(state.selects).toEqual(["id, target_url, client_id"]);
  });

  it("offers unassigned sites, and re-points the selection when the scope changes", async () => {
    session.clients = [{ id: "c1", name: "Acme" }, { id: "c2", name: "Beta" }];
    session.currentClientId = "unassigned";
    const { rerender } = render(<ScoreHistoryPage />);
    await waitFor(() => expect(options()).toEqual(["https://c.test"]));
    session.currentClientId = "c1";
    rerender(<ScoreHistoryPage />);
    await waitFor(() => expect(options()).toEqual(["https://a.test"]));
    expect((screen.getByLabelText("Site") as HTMLSelectElement).value).toBe("t1");
  });

  it("shows the empty state for a client with no sites", async () => {
    session.clients = [{ id: "c9", name: "New" }];
    session.currentClientId = "c9";
    render(<ScoreHistoryPage />);
    expect(await screen.findByText("No monitored sites yet")).toBeInTheDocument();
  });
});
