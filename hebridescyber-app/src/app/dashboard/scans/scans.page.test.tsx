import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

const { session, state } = vi.hoisted(() => ({
  session: { userId: "u1", currentClientId: "all" as string },
  state: {
    scans: [] as { id: string; target_url: string; status: string; created_at: string; owner: string; scan_results: null }[],
    targets: [] as { target_url: string }[],
    ranges: [] as [number, number][],
  },
}));

vi.mock("@/components/app-shell/AppShell", () => ({ useAppSession: () => session }));
vi.mock("@/components/RunScanForm", () => ({ default: () => <div /> }));
vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: (table: string) => {
      if (table === "monitored_targets") {
        const b: Record<string, unknown> = {};
        b.select = () => b;
        b.is = () => Promise.resolve({ data: state.targets });
        b.eq = () => Promise.resolve({ data: state.targets });
        return b;
      }
      const b: Record<string, unknown> = {};
      b.select = () => b;
      b.order = () => b;
      b.range = (from: number, to: number) => {
        state.ranges.push([from, to]);
        return Promise.resolve({ data: state.scans.slice(from, to + 1), error: null });
      };
      return b;
    },
  },
}));

import ScansPage from "./page";

const scan = (n: number, host: string) => ({
  id: `s${n}`, target_url: `https://${host}/`, status: "completed", created_at: "2026-10-01T00:00:00Z", owner: "u1", scan_results: null as null,
});

beforeEach(() => {
  session.currentClientId = "all";
  state.ranges = [];
  state.targets = [{ target_url: "https://a.test" }];
  state.scans = [scan(1, "a.test"), scan(2, "b.test"), scan(3, "A.test")];
});

describe("Scans page — client scope", () => {
  it("lists every scan for all clients", async () => {
    render(<ScansPage />);
    expect(await screen.findByText("https://b.test/")).toBeInTheDocument();
    expect(screen.getAllByText(/a\.test/i)).toHaveLength(2);
  });

  it("shows only the selected client's sites, matched by hostname", async () => {
    session.currentClientId = "c1";
    render(<ScansPage />);
    await waitFor(() => expect(screen.getAllByText(/a\.test/i)).toHaveLength(2));
    expect(screen.queryByText("https://b.test/")).not.toBeInTheDocument();
  });

  it("filters to unassigned sites", async () => {
    session.currentClientId = "unassigned";
    state.targets = [{ target_url: "https://b.test" }, { target_url: "bad url" }];
    render(<ScansPage />);
    expect(await screen.findByText("https://b.test/")).toBeInTheDocument();
    expect(screen.queryByText("https://a.test/")).not.toBeInTheDocument();
  });

  it("pages on the raw offset, so Load more skips nothing a scope filtered out", async () => {
    session.currentClientId = "c1";
    state.scans = Array.from({ length: 60 }, (_, i) => scan(i, i % 2 === 0 ? "a.test" : "b.test"));
    render(<ScansPage />);
    const more = await screen.findByRole("button", { name: "Load more" });
    fireEvent.click(more);
    await waitFor(() => expect(state.ranges).toContainEqual([50, 99]));
  });

  it("treats a missing target list as no matching sites", async () => {
    session.currentClientId = "c1";
    state.targets = undefined as never;
    render(<ScansPage />);
    await waitFor(() => expect(screen.queryByText("https://a.test/")).not.toBeInTheDocument());
    expect(await screen.findByText(/No scans yet/)).toBeInTheDocument();
  });
});
