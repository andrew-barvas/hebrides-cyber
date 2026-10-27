import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const { getSessionMock, getMfaMock, replaceMock, subscriptionRow, clientRows, clientsFail } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  getMfaMock: vi.fn(),
  replaceMock: vi.fn(),
  subscriptionRow: { current: null as Record<string, unknown> | null },
  clientRows: { current: [] as { id: string; name: string }[] },
  clientsFail: { current: false },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard/assets",
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
}));

vi.mock("@/lib/auth", () => ({
  getSession: getSessionMock,
  getMfaAssuranceLevel: getMfaMock,
}));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: (table: string) =>
      table === "clients"
        ? {
            select: () => ({
              order: () => (clientsFail.current ? Promise.reject(new Error("boom")) : Promise.resolve({ data: clientRows.current })),
            }),
          }
        : { select: () => ({ maybeSingle: () => Promise.resolve({ data: subscriptionRow.current }) }) },
  },
}));

import AppShell, { effectivePlan, useAppSession } from "./AppShell";

function SessionProbe() {
  const s = useAppSession();
  return (
    <p data-testid="probe">
      {s.userId}|{s.email}|{s.plan}|{s.billingPlan}|{String(s.planStatus)}|{s.slackWebhookUrl}
    </p>
  );
}

const session = { user: { id: "user-1", email: "owner@example.com" }, access_token: "tok" };

beforeEach(() => {
  getSessionMock.mockReset().mockResolvedValue(session);
  getMfaMock.mockReset().mockResolvedValue({ currentLevel: "aal1", nextLevel: "aal1" });
  replaceMock.mockReset();
  subscriptionRow.current = { plan: "pro", status: "active", slack_webhook_url: "https://hooks.slack.com/x", ms_teams_webhook_url: null };
});

describe("effectivePlan", () => {
  it("only grants the stored plan while the subscription is active", () => {
    expect(effectivePlan("pro", "active")).toBe("pro");
    expect(effectivePlan("pro", "past_due")).toBe("none");
    expect(effectivePlan("agency", null)).toBe("none");
  });
});

describe("AppShell", () => {
  it("provides the session and subscription to every page inside it", async () => {
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    expect(await screen.findByTestId("probe")).toHaveTextContent("user-1|owner@example.com|pro|pro|active|https://hooks.slack.com/x");
  });

  it("keeps billingPlan but drops feature access for a past_due subscription", async () => {
    subscriptionRow.current = { plan: "agency", status: "past_due" };
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    expect(await screen.findByTestId("probe")).toHaveTextContent("|none|agency|past_due|");
  });

  it("treats an account with no subscription row as the free tier", async () => {
    subscriptionRow.current = null;
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    expect(await screen.findByTestId("probe")).toHaveTextContent("|none|none|null|");
  });

  // Regression guard: the AAL2 step-up used to run on /dashboard only, so
  // /account and every /dashboard/* sub-page skipped it.
  it("sends an MFA-enrolled session that hasn't completed its challenge to the MFA page, without rendering the page", async () => {
    getMfaMock.mockResolvedValue({ currentLevel: "aal1", nextLevel: "aal2" });
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/login/mfa-challenge"));
    expect(screen.queryByTestId("probe")).not.toBeInTheDocument();
  });

  it("offers a sign-in link back to the current page when the session has gone", async () => {
    getSessionMock.mockResolvedValue(null);
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    expect(await screen.findByText("Your session has ended")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login?redirect=%2Fdashboard%2Fassets");
    expect(screen.queryByTestId("probe")).not.toBeInTheDocument();
  });

  it("shows the signed-out state when initialisation throws", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    getSessionMock.mockRejectedValue(new Error("network"));
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    expect(await screen.findByText("Your session has ended")).toBeInTheDocument();
    expect(log).toHaveBeenCalledWith("[app-shell] init error:", "network");
    log.mockRestore();
  });

  it("renders the navigation while the session is still loading", () => {
    getSessionMock.mockReturnValue(new Promise(() => {}));
    render(
      <AppShell>
        <SessionProbe />
      </AppShell>
    );
    expect(screen.getAllByRole("navigation", { name: "Dashboard" }).length).toBeGreaterThan(0);
    expect(screen.queryByTestId("probe")).not.toBeInTheDocument();
  });

  describe("client workspaces (Agency)", () => {
    function ScopeProbe() {
      const s = useAppSession();
      return (
        <div>
          <p data-testid="scope">{s.currentClientId}|{s.clients.map((c) => c.name).join(",")}</p>
          <button onClick={() => s.setCurrentClientId("c2")}>pick-c2</button>
          <button onClick={() => s.setCurrentClientId("all")}>pick-all</button>
          <button onClick={() => void s.refreshClients()}>refresh</button>
        </div>
      );
    }
    const renderAgency = () =>
      render(
        <AppShell>
          <ScopeProbe />
        </AppShell>
      );

    beforeEach(() => {
      subscriptionRow.current = { plan: "agency", status: "active" };
      clientRows.current = [{ id: "c1", name: "Acme" }, { id: "c2", name: "Beta" }];
      clientsFail.current = false;
      window.localStorage.clear();
      window.history.replaceState(null, "", "/dashboard");
    });

    it("loads clients, shows the switcher and defaults to all clients", async () => {
      renderAgency();
      await screen.findByTestId("scope");
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("all|Acme,Beta"));
      expect(await screen.findByLabelText(/client/i)).toBeInTheDocument();
    });

    it("persists a selection to localStorage and the ?client= param, and clears the param for all", async () => {
      renderAgency();
      await screen.findByTestId("scope");
      fireEvent.click(screen.getByText("pick-c2"));
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("c2|"));
      expect(window.localStorage.getItem("hc-client-scope")).toBe("c2");
      expect(window.location.search).toBe("?client=c2");
      fireEvent.click(screen.getByText("pick-all"));
      await waitFor(() => expect(window.location.search).toBe(""));
    });

    it("restores the selection from the URL, which wins over localStorage", async () => {
      window.localStorage.setItem("hc-client-scope", "c1");
      window.history.replaceState(null, "", "/dashboard?client=c2");
      renderAgency();
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("c2|Acme,Beta"));
    });

    it("restores from localStorage, and falls back to all for a deleted client", async () => {
      window.localStorage.setItem("hc-client-scope", "gone");
      renderAgency();
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("all|Acme,Beta"));
    });

    it("survives a failing clients load and a manual refresh", async () => {
      clientsFail.current = true;
      renderAgency();
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("all|"));
      expect(screen.queryByLabelText(/client/i)).not.toBeInTheDocument();
      clientsFail.current = false;
      fireEvent.click(screen.getByText("refresh"));
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("all|Acme,Beta"));
    });

    it("falls back to all clients when storage is blocked", async () => {
      const spy = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
        throw new Error("blocked");
      });
      const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
        throw new Error("blocked");
      });
      renderAgency();
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("all|Acme,Beta"));
      fireEvent.click(screen.getByText("pick-c2"));
      await waitFor(() => expect(screen.getByTestId("scope")).toHaveTextContent("c2|"));
      spy.mockRestore();
      set.mockRestore();
    });

    it("does not load clients or show a switcher for non-Agency plans", async () => {
      subscriptionRow.current = { plan: "pro", status: "active" };
      renderAgency();
      expect(await screen.findByTestId("scope")).toHaveTextContent("all|");
      expect(screen.queryByLabelText(/client/i)).not.toBeInTheDocument();
    });
  });

  it("throws a clear error if a page uses the session outside the shell", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<SessionProbe />)).toThrow("useAppSession() must be called inside <AppShell>");
    spy.mockRestore();
  });
});
