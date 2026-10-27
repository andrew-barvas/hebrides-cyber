import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import MonitoredTargets from "./MonitoredTargets";
import { getSession } from "@/lib/auth";

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

describe("AuthenticatedScanConfig — recorded login", () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ access_token: "test-token" } as never);
    vi.stubGlobal("fetch", vi.fn());
  });

  async function openLoginTab() {
    state.targets = [{ id: "t1", target_url: "https://example.com", created_at: "2026-01-01T00:00:00Z" }];
    render(<MonitoredTargets />);
    fireEvent.click(await screen.findByText("+ Add authenticated scan credential"));
    fireEvent.click(screen.getByText("Recorded login"));
  }

  it("posts to record-login (not target-auth) with the acknowledgement, on submit", async () => {
    await openLoginTab();
    vi.mocked(fetch).mockResolvedValue({ ok: true, json: async () => ({ ok: true }) } as Response);

    fireEvent.change(screen.getByPlaceholderText(/Login page URL/), { target: { value: "https://example.com/login" } });
    fireEvent.change(screen.getByPlaceholderText("Username"), { target: { value: "test-account" } });
    fireEvent.change(screen.getByPlaceholderText("Password"), { target: { value: "s3cret" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Log in & save" }));

    await waitFor(() => expect(fetch).toHaveBeenCalled());
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(url).toBe("/api/account/record-login");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      monitoredTargetId: "t1",
      loginUrl: "https://example.com/login",
      username: "test-account",
      password: "s3cret",
      acknowledged: true,
    });
  });

  it("the consent checkbox is required — the browser blocks submission without it", async () => {
    await openLoginTab();
    fireEvent.change(screen.getByPlaceholderText(/Login page URL/), { target: { value: "https://example.com/login" } });
    fireEvent.change(screen.getByPlaceholderText("Username"), { target: { value: "test-account" } });
    fireEvent.change(screen.getByPlaceholderText("Password"), { target: { value: "s3cret" } });

    expect(screen.getByRole("checkbox")).toBeRequired();
  });

  it("shows the server's error message and never submits again automatically on failure", async () => {
    await openLoginTab();
    vi.mocked(fetch).mockResolvedValue({ ok: false, json: async () => ({ error: "Login did not appear to succeed." }) } as Response);

    fireEvent.change(screen.getByPlaceholderText(/Login page URL/), { target: { value: "https://example.com/login" } });
    fireEvent.change(screen.getByPlaceholderText("Username"), { target: { value: "test-account" } });
    fireEvent.change(screen.getByPlaceholderText("Password"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Log in & save" }));

    expect(await screen.findByText("Login did not appear to succeed.")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("MonitoredTargets — client workspaces", () => {
  const clients = [
    { id: "c1", name: "Acme" },
    { id: "c2", name: "Beta" },
  ];
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ access_token: "test-token" } as never);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) } as Response));
    state.cap = 15;
    state.targets = [
      { id: "t1", target_url: "https://a.test", created_at: "2026-01-01T00:00:00Z", client_id: "c1" },
      { id: "t2", target_url: "https://b.test", created_at: "2026-01-01T00:00:00Z", client_id: null },
    ] as never;
  });

  it("shows no client controls without clients", async () => {
    render(<MonitoredTargets />);
    await screen.findByText("https://a.test");
    expect(screen.queryByLabelText(/Client for/)).not.toBeInTheDocument();
  });

  it("filters the list to the selected client scope", async () => {
    render(<MonitoredTargets clients={clients} scope="c1" />);
    await screen.findByText("https://a.test");
    expect(screen.queryByText("https://b.test")).not.toBeInTheDocument();
  });

  it("filters to Unassigned and explains an empty client", async () => {
    const { rerender } = render(<MonitoredTargets clients={clients} scope="unassigned" />);
    await screen.findByText("https://b.test");
    expect(screen.queryByText("https://a.test")).not.toBeInTheDocument();
    rerender(<MonitoredTargets clients={clients} scope="c2" />);
    expect(await screen.findByText("No sites for this client yet.")).toBeInTheDocument();
  });

  it("assigns one site from its row picker and notifies the parent", async () => {
    const onAssigned = vi.fn();
    render(<MonitoredTargets clients={clients} onAssigned={onAssigned} />);
    fireEvent.change(await screen.findByLabelText("Client for https://b.test"), { target: { value: "c2" } });
    await waitFor(() => expect(onAssigned).toHaveBeenCalled());
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(url).toBe("/api/clients/assign");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ client_id: "c2", target_ids: ["t2"] });
  });

  it("bulk-assigns the ticked sites, and unassigns with the blank option", async () => {
    render(<MonitoredTargets clients={clients} />);
    const apply = await screen.findByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Select https://a.test"));
    fireEvent.click(screen.getByLabelText("Select https://b.test"));
    fireEvent.change(screen.getByLabelText(/Assign 2 selected to/), { target: { value: "c1" } });
    fireEvent.click(apply);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    expect(JSON.parse((vi.mocked(fetch).mock.calls[0][1] as RequestInit).body as string)).toEqual({ client_id: "c1", target_ids: ["t1", "t2"] });

    fireEvent.click(await screen.findByLabelText("Select https://b.test"));
    fireEvent.change(screen.getByLabelText(/Assign 1 selected to/), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    expect(JSON.parse((vi.mocked(fetch).mock.calls[1][1] as RequestInit).body as string)).toEqual({ client_id: null, target_ids: ["t2"] });
  });

  it("shows the server's error when assignment fails, and handles a missing session", async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: false, json: async () => ({ error: "Client not found" }) } as Response);
    render(<MonitoredTargets clients={clients} />);
    fireEvent.change(await screen.findByLabelText("Client for https://b.test"), { target: { value: "c1" } });
    expect(await screen.findByText("Client not found")).toBeInTheDocument();

    vi.mocked(fetch).mockResolvedValue({ ok: false, json: async () => { throw new Error("bad json"); } } as unknown as Response);
    fireEvent.change(screen.getByLabelText("Client for https://b.test"), { target: { value: "c2" } });
    expect(await screen.findByText("Could not assign sites")).toBeInTheDocument();

    vi.mocked(getSession).mockResolvedValue(null);
    fireEvent.change(screen.getByLabelText("Client for https://b.test"), { target: { value: "c1" } });
    expect(await screen.findByText("Not signed in.")).toBeInTheDocument();
  });
});
