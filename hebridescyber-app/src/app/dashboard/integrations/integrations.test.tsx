import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";

// Every hosted integration fetches its own data on mount — stub them to
// markers so this test is about the page's grouping and plan gating only.
const { session } = vi.hoisted(() => ({ session: { plan: "none" as string, accessToken: "tok" } }));

vi.mock("@/components/app-shell/AppShell", () => ({ useAppSession: () => session }));
vi.mock("@/components/ChannelWebhookIntegration", () => ({
  default: ({ provider }: { provider: string }) => <div data-testid={`channel-${provider}`} />,
}));
for (const name of [
  "ApiKeys",
  "ApiSpecConfig",
  "CloudCredentialsConfig",
  "ConnectRepo",
  "NotificationPrefsSection",
  "OncallIntegrationConfig",
  "ScheduledReportsConfig",
  "TicketIntegration",
  "Webhooks",
]) {
  vi.doMock(`@/components/${name}`, () => ({ default: () => <div data-testid={name} /> }));
}

async function renderPage() {
  const { default: IntegrationsPage } = await import("./page");
  return render(<IntegrationsPage />);
}

beforeEach(() => {
  vi.resetModules();
  session.plan = "none";
});

// vi.resetModules() makes every test re-import the page's whole component
// tree cold; under `test:unit:coverage` on a busy machine that alone passed
// the default 5s, and the timed-out render then leaked into the next test.
describe("Integrations page", { timeout: 20_000 }, () => {
  it("groups every integration under one of four headings", async () => {
    session.plan = "agency";
    await renderPage();
    for (const heading of ["Alerts & notifications", "Ticketing", "Code & API", "Cloud & reporting"]) {
      expect(screen.getByRole("heading", { level: 2, name: heading })).toBeInTheDocument();
    }
    const ticketing = screen.getByRole("region", { name: "Ticketing" });
    expect(within(ticketing).getByTestId("TicketIntegration")).toBeInTheDocument();
  });

  it("shows the real forms on Agency", async () => {
    session.plan = "agency";
    await renderPage();
    for (const id of ["channel-slack", "channel-teams", "NotificationPrefsSection", "ScheduledReportsConfig", "CloudCredentialsConfig"]) {
      expect(screen.getByTestId(id)).toBeInTheDocument();
    }
    expect(screen.queryByRole("link", { name: "Compare plans" })).not.toBeInTheDocument();
  });

  it("keeps gated features discoverable on the free tier instead of hiding them", async () => {
    await renderPage();
    expect(screen.queryByTestId("channel-slack")).not.toBeInTheDocument();
    expect(screen.queryByTestId("CloudCredentialsConfig")).not.toBeInTheDocument();
    for (const locked of ["slack & microsoft teams alerts", "email notifications", "scheduled reports", "cloud posture scanning"]) {
      expect(screen.getByRole("heading", { name: locked })).toBeInTheDocument();
    }
    expect(screen.getAllByRole("link", { name: "Compare plans" })).toHaveLength(4);
  });

  it("unlocks chat alerts on Pro but keeps cloud posture Agency-only", async () => {
    session.plan = "pro";
    await renderPage();
    expect(screen.getByTestId("channel-slack")).toBeInTheDocument();
    expect(screen.getByTestId("ScheduledReportsConfig")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "cloud posture scanning" })).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Compare plans" })).toHaveLength(1);
  });

  it("keeps ungated integrations available on every plan", async () => {
    await renderPage();
    for (const id of ["OncallIntegrationConfig", "Webhooks", "TicketIntegration", "ConnectRepo", "ApiSpecConfig", "ApiKeys"]) {
      expect(screen.getByTestId(id)).toBeInTheDocument();
    }
  });
});
