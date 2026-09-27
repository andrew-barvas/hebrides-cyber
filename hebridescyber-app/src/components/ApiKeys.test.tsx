import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import ApiKeys from "./ApiKeys";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

const baseKey = {
  id: "k1",
  name: "GitHub Actions",
  key_prefix: "hc_live_abcdefgh",
  last_used_at: null,
  revoked_at: null,
  created_at: "2026-09-01T00:00:00Z",
  allowed_cidrs: [] as string[],
  last_blocked_ip: null as string | null,
  last_blocked_at: null as string | null,
};

/** Routes by URL + method so call order inside effects doesn't matter. */
function serve(keys: (typeof baseKey)[], ip = "203.0.113.7") {
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === "/api/client-ip") return ok({ ip });
    if (url === "/api/keys" && init?.method === "PATCH") {
      const body = JSON.parse(String(init.body));
      return ok({ id: body.id, allowed_cidrs: body.allowed_cidrs });
    }
    return ok({ keys });
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("ApiKeys IP allowlist", () => {
  it("says an unrestricted key works from anywhere", async () => {
    serve([baseKey]);
    render(<ApiKeys token="tok" />);
    expect(await screen.findByText("Usable from any IP address")).toBeInTheDocument();
  });

  it("summarises a restricted key and surfaces its last refused request", async () => {
    serve([
      {
        ...baseKey,
        allowed_cidrs: ["203.0.113.0/24", "198.51.100.1", "2001:db8::/48", "192.0.2.1"],
        last_blocked_ip: "198.51.100.99",
        last_blocked_at: "2026-09-20T10:00:00Z",
      },
    ]);
    render(<ApiKeys token="tok" />);
    expect(await screen.findByText("Only from 203.0.113.0/24, 198.51.100.1, 2001:db8::/48 +1 more")).toBeInTheDocument();
    expect(screen.getByText(/Refused a request from 198\.51\.100\.99/)).toBeInTheDocument();
  });

  it("adds the caller's current IP and saves the list", async () => {
    serve([baseKey]);
    render(<ApiKeys token="tok" />);
    fireEvent.click(await screen.findByRole("button", { name: "IP allowlist" }));

    const field = screen.getByLabelText("Allowed IP addresses and ranges, one per line");
    fireEvent.change(field, { target: { value: "198.51.100.0/24" } });
    fireEvent.click(await screen.findByRole("button", { name: "Add my current IP (203.0.113.7)" }));
    expect(field).toHaveValue("198.51.100.0/24\n203.0.113.7");
    // Already present — the shortcut goes away.
    expect(screen.queryByRole("button", { name: /Add my current IP/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Save allowlist" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
      expect(patch).toBeDefined();
      expect(JSON.parse(String(patch![1].body))).toEqual({ id: "k1", allowed_cidrs: ["198.51.100.0/24", "203.0.113.7"] });
      expect(patch![1].headers).toMatchObject({ Authorization: "Bearer tok" });
    });
    await waitFor(() => expect(screen.queryByLabelText(/Allowed IP addresses/)).not.toBeInTheDocument());
  });

  it("shows the server's validation error and keeps the editor open", async () => {
    serve([baseKey]);
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === "/api/client-ip") return ok({ ip: "203.0.113.7" });
      if (init?.method === "PATCH") return { ok: false, status: 400, json: async () => ({ error: '"office" isn\'t an IP address' }) };
      return ok({ keys: [baseKey] });
    });
    render(<ApiKeys token="tok" />);
    fireEvent.click(await screen.findByRole("button", { name: "IP allowlist" }));
    fireEvent.change(screen.getByLabelText(/Allowed IP addresses/), { target: { value: "office" } });
    fireEvent.click(screen.getByRole("button", { name: "Save allowlist" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("office");
    expect(screen.getByLabelText(/Allowed IP addresses/)).toBeInTheDocument();
  });
});
