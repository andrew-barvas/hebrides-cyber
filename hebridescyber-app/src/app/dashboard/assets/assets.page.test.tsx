import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

const { session, props } = vi.hoisted(() => ({
  session: {
    plan: "agency" as string,
    accessToken: "tok",
    clients: [{ id: "c1", name: "Acme" }],
    currentClientId: "c1",
    refreshClients: vi.fn(),
  },
  props: {} as Record<string, Record<string, unknown>>,
}));

vi.mock("@/components/app-shell/AppShell", () => ({ useAppSession: () => session }));
vi.mock("@/components/AssetInventory", () => ({ default: () => <div /> }));
vi.mock("@/components/DmarcReports", () => ({ default: () => <div /> }));
vi.mock("@/components/DomainVerification", () => ({ default: (p: Record<string, unknown>) => ((props.domains = p), <div data-testid="domains" />) }));
vi.mock("@/components/MonitoredTargets", () => ({ default: (p: Record<string, unknown>) => ((props.targets = p), <div data-testid="targets" />) }));
vi.mock("@/components/ClientsManager", () => ({ default: (p: Record<string, unknown>) => ((props.manager = p), <div data-testid="clients-manager" />) }));

import AssetsPage from "./page";

beforeEach(() => {
  session.plan = "agency";
  session.refreshClients.mockReset();
  for (const k of Object.keys(props)) delete props[k];
});

describe("Assets page — client workspaces", () => {
  it("shows the clients manager on Agency and hands clients and scope to the lists", () => {
    render(<AssetsPage />);
    expect(screen.getByTestId("clients-manager")).toBeInTheDocument();
    expect(props.domains.clients).toEqual(session.clients);
    expect(props.targets).toMatchObject({ clients: session.clients, scope: "c1" });
  });

  it("refreshes the shell's clients after a change or assignment", () => {
    render(<AssetsPage />);
    (props.manager.onChanged as () => void)();
    (props.targets.onAssigned as () => void)();
    expect(session.refreshClients).toHaveBeenCalledTimes(2);
  });

  it("hides the clients manager below Agency, and locks monitoring without a plan", () => {
    session.plan = "pro";
    const { unmount } = render(<AssetsPage />);
    expect(screen.queryByTestId("clients-manager")).not.toBeInTheDocument();
    unmount();
    session.plan = "none";
    render(<AssetsPage />);
    expect(screen.queryByTestId("targets")).not.toBeInTheDocument();
  });
});
