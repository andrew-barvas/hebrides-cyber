import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import DeviceAgentDevices, { installCommands, STATUS_LABELS } from "./DeviceAgentDevices";

const fetchMock = vi.fn();
const res = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 400, json: async () => body });

const failing = {
  id: "d1",
  name: "Reception PC",
  token_prefix: "hcd_abcdefgh",
  created_at: "2026-11-01T00:00:00Z",
  revoked_at: null,
  last_seen_at: "2026-11-19T09:00:00Z",
  hostname: "RECEPTION-PC",
  os: { family: "windows", name: "Microsoft Windows 11 Pro", version: "10.0.22631.3447" },
  agent_version: "0.1.0",
  status: "fails",
  evaluation: {
    summary: "Misses the 14-day rule: 1 item overdue.",
    overdue: [{ kind: "pending_update", key: "wu:KB1", title: "2026-10 Cumulative Update (KB1)", severity: "critical", since: "2026-10-14", sinceBasis: "vendor_release", dueBy: "2026-10-28", overdue: true, detail: null }],
    dueSoon: [{ kind: "cve", key: "CVE-1:Chrome", title: "CVE-1 in Google Chrome 123", severity: "CVSS 8.8", since: "2026-11-15", sinceBasis: "cve_published", dueBy: "2026-11-29", overdue: false, detail: "Fixed in 124" }],
    gaps: ["CVE and end-of-life matching hasn't run on this report yet."],
  },
  match: { cve_count: 1, os_eol: { cycle: "11-23h2-w", state: "supported", eolDate: null }, coverage: { softwareTotal: 80, softwareChecked: 6 } },
  matched_at: "2026-11-19T10:00:00Z",
};
const revoked = { ...failing, id: "d2", name: "Old laptop", revoked_at: "2026-11-10T00:00:00Z", status: "revoked", evaluation: null, match: null };

function serve(devices: unknown[], extra: (url: string, init?: RequestInit) => unknown = () => undefined) {
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const r = extra(url, init);
    if (r) return r;
    return res({ devices, enabled: true });
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DeviceAgentDevices", () => {
  it("shows an empty state that says the agent never scans the network", async () => {
    serve([]);
    render(<DeviceAgentDevices token="tok" />);
    expect(await screen.findByText("No devices yet")).toBeInTheDocument();
    expect(screen.getByText(/never scans your network/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/agent/devices", { headers: { Authorization: "Bearer tok" } });
  });

  it("lists devices with their 14-day status, and details on demand", async () => {
    serve([failing, revoked]);
    render(<DeviceAgentDevices token="tok" />);
    expect(await screen.findByText("Reception PC")).toBeInTheDocument();
    expect(screen.getByText("1 device, 1 missing the 14-day patch rule.")).toBeInTheDocument();
    expect(screen.getByText(STATUS_LABELS.fails.label)).toBeInTheDocument();
    expect(screen.queryByText("Old laptop")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Details" }));
    expect(screen.getByText("2026-10 Cumulative Update (KB1)")).toBeInTheDocument();
    expect(screen.getByText(/released 2026-10-14, due by 2026-10-28/)).toBeInTheDocument();
    expect(screen.getByText(/CVE published 2026-11-15/)).toBeInTheDocument();
    expect(screen.getByText("Fixed in 124")).toBeInTheDocument();
    expect(screen.getByText(/matching hasn't run/)).toBeInTheDocument();
    expect(screen.getByText(/6 of 80 packages and programs could be checked/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show 1 revoked" }));
    expect(screen.getByText("Old laptop")).toBeInTheDocument();
    expect(screen.getAllByText(STATUS_LABELS.revoked.label)).toHaveLength(1);
  });

  it("adds a device and shows its token once, with install commands", async () => {
    serve([], (url, init) => (init?.method === "POST" ? res({ id: "d9", name: "Laptop", token: "hcd_TOKEN" }) : undefined));
    render(<DeviceAgentDevices token="tok" />);
    await screen.findByText("No devices yet");
    fireEvent.change(screen.getByLabelText("Device name"), { target: { value: "Laptop" } });
    fireEvent.click(screen.getByRole("button", { name: "Add device" }));
    expect(await screen.findByText("Token for Laptop: shown once")).toBeInTheDocument();
    expect(screen.getByText("hcd_TOKEN")).toBeInTheDocument();
    expect(screen.getByText(/enrol --token hcd_TOKEN; .*report/)).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST")!;
    expect(JSON.parse(post[1].body)).toEqual({ name: "Laptop" });
    fireEvent.click(screen.getByRole("button", { name: "I've copied it" }));
    expect(screen.queryByText("hcd_TOKEN")).not.toBeInTheDocument();
  });

  it("revokes a device and reloads", async () => {
    serve([failing], (url, init) => (init?.method === "DELETE" ? res({ ok: true }) : undefined));
    render(<DeviceAgentDevices token="tok" />);
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(true));
    const del = fetchMock.mock.calls.find(([, init]) => init?.method === "DELETE")!;
    expect(JSON.parse(del[1].body)).toEqual({ id: "d1" });
  });

  it("shows server errors from each action", async () => {
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST") return res({ error: "Device patch reporting needs a Pro plan or above." }, false);
      if (init?.method === "DELETE") return res({ error: "Device not found" }, false);
      return res({ devices: [failing], enabled: true });
    });
    render(<DeviceAgentDevices token="tok" />);
    fireEvent.change(await screen.findByLabelText("Device name"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Add device" }));
    expect(await screen.findByText(/needs a Pro plan/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(await screen.findByText("Device not found")).toBeInTheDocument();
  });

  it("says when the server hasn't enabled devices, and when loading fails", async () => {
    fetchMock.mockResolvedValueOnce(res({ devices: [], enabled: false }));
    const { unmount } = render(<DeviceAgentDevices token="tok" />);
    expect(await screen.findByText("Not enabled yet")).toBeInTheDocument();
    unmount();
    fetchMock.mockResolvedValueOnce(res({ error: "Could not load devices" }, false));
    render(<DeviceAgentDevices token="tok" />);
    expect(await screen.findByText("Could not load devices")).toBeInTheDocument();
  });

  it("does nothing without a session token", () => {
    render(<DeviceAgentDevices token={null} />);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Add device" })).toBeDisabled();
  });

  it("builds install commands for both platforms", () => {
    const cmds = installCommands("hcd_x");
    expect(cmds).toHaveLength(2);
    expect(cmds[1].command).toBe("sudo ./hebrides-agent enrol --token hcd_x && sudo ./hebrides-agent report");
  });
});
