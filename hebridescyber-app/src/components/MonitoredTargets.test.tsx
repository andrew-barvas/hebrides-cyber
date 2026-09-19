import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import MonitoredTargets from "./MonitoredTargets";

// Mocked before importing the component so its `import { supabase } from
// "@/lib/supabaseClient"` picks up this mock — same hoisting reason as
// src/lib/auth.test.ts. `state` is mutated per-test to control what each
// call returns; fromMock/rpcMock read it lazily rather than capturing a
// snapshot at mock-definition time.
const { getUserMock, fromMock, rpcMock, insertMock, state } = vi.hoisted(() => ({
  getUserMock: vi.fn(),
  fromMock: vi.fn(),
  rpcMock: vi.fn(),
  insertMock: vi.fn(),
  state: {
    targets: [] as Array<{ id: string; target_url: string; created_at: string }>,
    cap: 1,
  },
}));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    auth: { getUser: getUserMock },
    from: fromMock,
    rpc: rpcMock,
  },
}));

vi.mock("@/lib/auth", () => ({
  getSession: vi.fn().mockResolvedValue(null),
}));

beforeEach(() => {
  state.targets = [];
  state.cap = 1;
  getUserMock.mockResolvedValue({ data: { user: { id: "user-1" } } });
  rpcMock.mockImplementation(() => Promise.resolve({ data: state.cap, error: null }));
  insertMock.mockReset();
  insertMock.mockResolvedValue({ error: null });

  fromMock.mockImplementation((table: string) => {
    if (table === "monitored_targets") {
      return {
        select: () => ({
          order: () => Promise.resolve({ data: state.targets, error: null }),
        }),
        insert: insertMock,
        delete: () => ({ eq: () => Promise.resolve({ error: null }) }),
      };
    }
    if (table === "target_auth_credentials") {
      return {
        select: () => ({
          in: () => Promise.resolve({ data: [], error: null }),
        }),
      };
    }
    throw new Error(`unexpected table in test: ${table}`);
  });
});

describe("MonitoredTargets", () => {
  it("shows how many of the plan's site cap are used", async () => {
    state.targets = [{ id: "t1", target_url: "https://example.com", created_at: "2026-01-01T00:00:00Z" }];
    state.cap = 3;
    render(<MonitoredTargets />);

    expect(await screen.findByText(/1 of 3 sites used/)).toBeInTheDocument();
  });

  it("uses singular 'site' when the cap is 1", async () => {
    state.cap = 1;
    render(<MonitoredTargets />);

    expect(await screen.findByText(/0 of 1 site used/)).toBeInTheDocument();
  });

  it("disables the add-site form once the plan's cap is reached", async () => {
    state.targets = [{ id: "t1", target_url: "https://example.com", created_at: "2026-01-01T00:00:00Z" }];
    state.cap = 1;
    render(<MonitoredTargets />);

    await screen.findByText(/1 of 1 site used/);
    expect(screen.getByPlaceholderText(/Upgrade your plan/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: "Add site" })).toBeDisabled();
  });

  it("leaves the form enabled while under the cap", async () => {
    state.cap = 3;
    render(<MonitoredTargets />);

    await screen.findByText(/0 of 3 sites used/);
    expect(screen.getByPlaceholderText("https://client-site.com")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Add site" })).toBeEnabled();
  });

  // Regression guard: a cap rejection at the database (RLS policy
  // violation, Postgres code 42501 — sql/migrations/018_monitored_targets_
  // plan_cap.sql) used to surface as raw Postgres wording. This asserts the
  // translated, customer-facing message instead.
  it("shows a friendly upgrade message when the server rejects an insert as over-cap", async () => {
    state.cap = 1;
    insertMock.mockResolvedValue({ error: { code: "42501", message: "new row violates row-level security policy" } });
    render(<MonitoredTargets />);

    await screen.findByText(/0 of 1 site used/);
    fireEvent.change(screen.getByPlaceholderText("https://client-site.com"), {
      target: { value: "https://new-site.example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add site" }));

    expect(await screen.findByText(/reached your plan's limit of 1 monitored site/)).toBeInTheDocument();
    expect(screen.queryByText(/row-level security policy/)).not.toBeInTheDocument();
  });

  it("shows the raw error message for a non-cap insert failure", async () => {
    state.cap = 3;
    insertMock.mockResolvedValue({ error: { code: "23505", message: "duplicate key value" } });
    render(<MonitoredTargets />);

    await waitFor(() => expect(screen.getByPlaceholderText("https://client-site.com")).toBeEnabled());
    fireEvent.change(screen.getByPlaceholderText("https://client-site.com"), {
      target: { value: "https://dup.example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add site" }));

    expect(await screen.findByText("duplicate key value")).toBeInTheDocument();
  });

  // Regression guard for the 2026-09-19 incident: monitored_targets_cap()
  // was missing on the live database (migration 018 not yet applied),
  // which 404'd the rpc() call. The form must stay enabled rather than
  // defaulting to a cap of 0 and locking every account out of adding sites.
  it("leaves the add-site form enabled when the cap RPC call fails (e.g. migration not applied)", async () => {
    rpcMock.mockResolvedValue({ data: null, error: { message: "Could not find the function", code: "PGRST202" } });
    render(<MonitoredTargets />);

    await waitFor(() => expect(screen.getByPlaceholderText("https://client-site.com")).toBeEnabled());
    expect(screen.queryByText(/sites? used/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add site" })).toBeEnabled();
  });
});
