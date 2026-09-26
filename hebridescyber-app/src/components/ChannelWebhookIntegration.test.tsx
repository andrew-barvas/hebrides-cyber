import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const { refreshMock, getSessionMock, sessionState } = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  getSessionMock: vi.fn(),
  sessionState: { slackWebhookUrl: "", teamsWebhookUrl: "" },
}));

vi.mock("@/components/app-shell/AppShell", () => ({
  useAppSession: () => ({ ...sessionState, refreshSubscription: refreshMock }),
}));
vi.mock("@/lib/auth", () => ({ getSession: getSessionMock }));

import ChannelWebhookIntegration from "./ChannelWebhookIntegration";

const fetchMock = vi.fn();

beforeEach(() => {
  sessionState.slackWebhookUrl = "";
  sessionState.teamsWebhookUrl = "";
  refreshMock.mockReset().mockResolvedValue(undefined);
  getSessionMock.mockReset().mockResolvedValue({ access_token: "tok" });
  fetchMock.mockReset().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function sentBody() {
  return JSON.parse(fetchMock.mock.calls[0][1].body);
}

describe("ChannelWebhookIntegration", () => {
  // Regression test: the dashboard's inline Slack/Teams forms wrote straight
  // to `subscriptions` from the browser, which migration 024 turned into a
  // silent zero-row no-op while the UI still said "Saved".
  it("saves Slack through the server route, not a browser-side table write", async () => {
    render(<ChannelWebhookIntegration provider="slack" />);
    fireEvent.change(screen.getByLabelText("Slack webhook URL"), { target: { value: "https://hooks.slack.com/services/T/B/x" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await screen.findByText(/Saved — alerts will post/);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/account/notification-webhooks",
      expect.objectContaining({ method: "POST", headers: expect.objectContaining({ Authorization: "Bearer tok" }) })
    );
    expect(sentBody()).toEqual({ slackWebhookUrl: "https://hooks.slack.com/services/T/B/x" });
    expect(refreshMock).toHaveBeenCalled();
  });

  it("sends Teams under its own field", async () => {
    render(<ChannelWebhookIntegration provider="teams" />);
    fireEvent.change(screen.getByLabelText("Microsoft Teams webhook URL"), { target: { value: "https://outlook.office.com/webhook/abc" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(sentBody()).toEqual({ msTeamsWebhookUrl: "https://outlook.office.com/webhook/abc" });
  });

  it("clears with null — the route's URL validation rejects an empty string", async () => {
    sessionState.slackWebhookUrl = "https://hooks.slack.com/services/old";
    render(<ChannelWebhookIntegration provider="slack" />);
    fireEvent.change(screen.getByLabelText("Slack webhook URL"), { target: { value: "   " } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Removed/);
    expect(sentBody()).toEqual({ slackWebhookUrl: null });
  });

  it("prefills the currently saved URL", () => {
    sessionState.teamsWebhookUrl = "https://outlook.office.com/webhook/existing";
    render(<ChannelWebhookIntegration provider="teams" />);
    expect(screen.getByLabelText("Microsoft Teams webhook URL")).toHaveValue("https://outlook.office.com/webhook/existing");
  });

  it("shows the server's error and does not claim success", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 400, json: async () => ({ error: "slackWebhookUrl must be a hooks.slack.com https:// URL" }) });
    render(<ChannelWebhookIntegration provider="slack" />);
    fireEvent.change(screen.getByLabelText("Slack webhook URL"), { target: { value: "https://evil.example.com/hook" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("must be a hooks.slack.com");
    expect(screen.queryByText(/Saved/)).not.toBeInTheDocument();
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("reports an expired session instead of sending an unauthenticated request", async () => {
    getSessionMock.mockResolvedValue(null);
    render(<ChannelWebhookIntegration provider="slack" />);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("session has expired");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
