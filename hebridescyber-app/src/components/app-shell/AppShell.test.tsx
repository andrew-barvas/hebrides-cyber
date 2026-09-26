import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const { getSessionMock, getMfaMock, replaceMock, subscriptionRow } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  getMfaMock: vi.fn(),
  replaceMock: vi.fn(),
  subscriptionRow: { current: null as Record<string, unknown> | null },
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
    from: () => ({
      select: () => ({ maybeSingle: () => Promise.resolve({ data: subscriptionRow.current }) }),
    }),
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

  it("throws a clear error if a page uses the session outside the shell", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<SessionProbe />)).toThrow("useAppSession() must be called inside <AppShell>");
    spy.mockRestore();
  });
});
