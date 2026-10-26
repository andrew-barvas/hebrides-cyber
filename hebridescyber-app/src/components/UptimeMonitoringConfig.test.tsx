import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import UptimeMonitoringConfig from "./UptimeMonitoringConfig";

vi.mock("@/lib/auth", () => ({ getSession: vi.fn().mockResolvedValue({ access_token: "tok" }) }));

const fetchMock = vi.fn();

type Body = Record<string, unknown>;
function respond(body: Body, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: async () => body } as Response);
}

const connectedStatus = (over: Body = {}): Body => ({
  allowed: true,
  connected: true,
  lastSyncAt: "2026-10-23T12:00:00Z",
  monitors: [],
  unmonitored: [],
  ...over,
});

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

describe("UptimeMonitoringConfig", () => {
  it("shows the connect form when not connected, and never shows a key", async () => {
    fetchMock.mockReturnValue(respond({ allowed: true, connected: false, monitors: [], unmonitored: [] }));
    render(<UptimeMonitoringConfig />);
    expect(await screen.findByLabelText("UptimeRobot API key")).toHaveAttribute("type", "password");
    expect(screen.getByRole("link", { name: "uptimerobot.com" })).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  it("connects with the pasted key, clears the field and reloads", async () => {
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      if (url === "/api/account/uptime-integration") return respond({ ok: true });
      return respond(init ? {} : connectedStatus());
    });
    fetchMock.mockReturnValueOnce(respond({ allowed: true, connected: false, monitors: [], unmonitored: [] }));
    render(<UptimeMonitoringConfig />);
    const input = await screen.findByLabelText("UptimeRobot API key");
    fireEvent.change(input, { target: { value: "  my-uptimerobot-key  " } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(screen.getByText(/Connected\. Now create monitors/)).toBeInTheDocument());
    const post = fetchMock.mock.calls.find((c) => c[0] === "/api/account/uptime-integration");
    expect(JSON.parse(post![1].body)).toEqual({ apiKey: "my-uptimerobot-key" });
    expect(post![1].headers.Authorization).toBe("Bearer tok");
  });

  it("shows the server's error when the key is refused", async () => {
    fetchMock.mockReturnValueOnce(respond({ allowed: true, connected: false, monitors: [], unmonitored: [] }));
    fetchMock.mockReturnValueOnce(respond({ error: "UptimeRobot rejected this API key." }, 400));
    render(<UptimeMonitoringConfig />);
    fireEvent.change(await screen.findByLabelText("UptimeRobot API key"), { target: { value: "bad-key-123" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("UptimeRobot rejected this API key.");
  });

  it("lists monitors with plain-language statuses and how long they have been in them", async () => {
    fetchMock.mockReturnValue(
      respond(
        connectedStatus({
          monitors: [
            { target_url: "https://shop.example.co.uk", last_status: "up", state_duration_seconds: 7200, last_status_at: null, last_checked_at: null },
            { target_url: "https://blog.example.co.uk", last_status: "down", state_duration_seconds: 600, last_status_at: null, last_checked_at: null },
            { target_url: "https://new.example.co.uk", last_status: "unknown", state_duration_seconds: null, last_status_at: null, last_checked_at: null },
          ],
        }),
      ),
    );
    render(<UptimeMonitoringConfig />);
    expect(await screen.findByText("https://shop.example.co.uk")).toBeInTheDocument();
    expect(screen.getByText("Up")).toBeInTheDocument();
    expect(screen.getByText(/for 2 h/)).toBeInTheDocument();
    expect(screen.getByText("Down")).toBeInTheDocument();
    expect(screen.getByText(/for 10 min/)).toBeInTheDocument();
    expect(screen.getByText("Waiting for first check")).toBeInTheDocument();
  });

  it("shows a monitor UptimeRobot no longer has as not found, not with its stale status", async () => {
    fetchMock.mockReturnValue(
      respond(
        connectedStatus({
          monitors: [{ target_url: "https://gone.example.co.uk", last_status: "up", state_duration_seconds: 7200, last_status_at: null, last_checked_at: null, missing: true }],
        }),
      ),
    );
    render(<UptimeMonitoringConfig />);
    expect(await screen.findByText("Not found in UptimeRobot")).toBeInTheDocument();
    expect(screen.queryByText("Up")).toBeNull();
    expect(screen.queryByText(/for 2 h/)).toBeNull();
    expect(screen.getByText(/disconnect and connect again/)).toBeInTheDocument();
  });

  it("offers to create monitors for sites that have none, and reports each result", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (url === "/api/uptime/monitors") {
        return respond({ results: [{ targetUrl: "https://a.example", result: "created" }, { targetUrl: "https://b.example", result: "not_verified" }] });
      }
      return respond(connectedStatus({ unmonitored: ["https://a.example", "https://b.example"] }));
    });
    render(<UptimeMonitoringConfig />);
    fireEvent.click(await screen.findByRole("button", { name: "Create monitors for 2 sites" }));
    await waitFor(() => expect(screen.getByText(/https:\/\/a\.example: monitor created/)).toBeInTheDocument());
    expect(screen.getByText(/https:\/\/b\.example: verify this domain first/)).toBeInTheDocument();
    const post = fetchMock.mock.calls.find((c) => c[0] === "/api/uptime/monitors");
    expect(JSON.parse(post![1].body)).toEqual({ targetUrls: ["https://a.example", "https://b.example"] });
  });

  it("hides the create button when every site is already monitored", async () => {
    fetchMock.mockReturnValue(respond(connectedStatus()));
    render(<UptimeMonitoringConfig />);
    await screen.findByText("No monitors yet.");
    expect(screen.queryByRole("button", { name: /Create monitors/ })).not.toBeInTheDocument();
  });

  it("says it is showing the last known status when a refresh failed, rather than a fresh one", async () => {
    fetchMock.mockReturnValue(respond(connectedStatus({ refreshError: "UptimeRobot returned 503." })));
    render(<UptimeMonitoringConfig />);
    expect(await screen.findByRole("status")).toHaveTextContent("Showing the last known status. UptimeRobot returned 503.");
  });

  it("disconnects and says the monitors in UptimeRobot are untouched", async () => {
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === "DELETE") return respond({ ok: true });
      return respond(connectedStatus());
    });
    render(<UptimeMonitoringConfig />);
    fireEvent.click(await screen.findByRole("button", { name: "Disconnect" }));
    expect(await screen.findByText(/monitors in UptimeRobot are untouched/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some((c) => c[0] === "/api/account/uptime-integration" && c[1]?.method === "DELETE")).toBe(true);
  });

  it("shows an error when the status cannot be loaded", async () => {
    fetchMock.mockReturnValue(respond({ error: "Could not load your uptime connection." }, 500));
    render(<UptimeMonitoringConfig />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load your uptime connection.");
  });
});
